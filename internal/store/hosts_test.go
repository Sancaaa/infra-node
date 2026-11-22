package store

import (
	"errors"
	"testing"
	"time"
)

func sampleHost(name, address string) Host {
	return Host{Name: name, Address: address, Port: 22, User: "deploy", Status: "online", HostKeyFP: "SHA256:abc"}
}

func TestHostsCreateListUpdateDelete(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()

	web, err := CreateHost(db, sampleHost("web-1", "10.0.0.1"), now)
	if err != nil || web.ID == 0 || web.CreatedAt != now.Unix() {
		t.Fatalf("create: %+v %v", web, err)
	}
	if _, err := CreateHost(db, sampleHost("db-1", "10.0.0.2"), now); err != nil {
		t.Fatal(err)
	}

	list, err := ListHosts(db)
	if err != nil || len(list) != 2 || list[0].Name != "db-1" { // by name
		t.Fatalf("list: %+v %v", list, err)
	}

	web.Name, web.Port, web.SudoOK, web.SudoersInstalled = "web-one", 2222, true, true
	if err := UpdateHostConnection(db, web); err != nil {
		t.Fatal(err)
	}
	got, err := GetHost(db, web.ID)
	if err != nil || got.Name != "web-one" || got.Port != 2222 || !got.SudoOK || !got.SudoersInstalled {
		t.Fatalf("after update: %+v %v", got, err)
	}

	// Status and facts are written by their own functions and touch nothing else.
	if err := SetHostStatus(db, web.ID, "key_changed", "a different key", "SHA256:new", now); err != nil {
		t.Fatal(err)
	}
	if err := SetHostFacts(db, web.ID, `{"cpus":4}`, false, now); err != nil {
		t.Fatal(err)
	}
	got, _ = GetHost(db, web.ID)
	if got.Status != "key_changed" || got.PresentedFP != "SHA256:new" || got.FactsJSON != `{"cpus":4}` || got.SudoOK || got.Name != "web-one" {
		t.Errorf("after status and facts: %+v", got)
	}

	if err := DeleteHost(db, web.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := GetHost(db, web.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a deleted host: %v", err)
	}
	for _, err := range []error{
		DeleteHost(db, 99),
		SetHostStatus(db, 99, "online", "", "", now),
		SetHostFacts(db, 99, "{}", true, now),
		UpdateHostConnection(db, Host{ID: 99, Name: "x", Address: "x", Port: 22, User: "u"}),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("an unknown host: %v", err)
		}
	}
}

// A host that answers is online again, and a host that stops answering keeps
// its last health and the time it was last seen.
func TestHealthAndLastSeen(t *testing.T) {
	db := newTestDB(t)
	t0 := time.Now().Add(-time.Hour)
	h, err := CreateHost(db, sampleHost("web-1", "10.0.0.1"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetHostStatus(db, h.ID, "key_changed", "a different key", "SHA256:new", t0); err != nil {
		t.Fatal(err)
	}

	if err := SetHostHealth(db, h.ID, `{"load1":0.5}`, t0); err != nil {
		t.Fatal(err)
	}
	got, _ := GetHost(db, h.ID)
	if got.Status != "online" || got.StatusDetail != "" || got.PresentedFP != "" || got.HealthJSON != `{"load1":0.5}` || got.LastSeen != t0.Unix() || got.HealthAt != t0.Unix() {
		t.Errorf("after a good check: %+v", got)
	}

	t1 := t0.Add(10 * time.Minute)
	if err := SetHostStatus(db, h.ID, "offline", "nothing answers", "", t1); err != nil {
		t.Fatal(err)
	}
	got, _ = GetHost(db, h.ID)
	if got.Status != "offline" || got.LastSeen != t0.Unix() || got.HealthJSON != `{"load1":0.5}` || got.StatusAt != t1.Unix() {
		t.Errorf("after the host went away: %+v", got)
	}
	if err := SetHostHealth(db, 99, "{}", t1); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown host: %v", err)
	}
}

func TestHostNamesAndAddressesAreUnique(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	a, err := CreateHost(db, sampleHost("web-1", "10.0.0.1"), now)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := CreateHost(db, sampleHost("web-1", "10.0.0.9"), now); !errors.Is(err, ErrHostNameTaken) {
		t.Errorf("same name: %v", err)
	}
	if _, err := CreateHost(db, sampleHost("other", "10.0.0.1"), now); !errors.Is(err, ErrHostAddressTaken) {
		t.Errorf("same address and port: %v", err)
	}
	// The same address on another port is another host (an SSH jump, a container's forwarded port).
	other := sampleHost("other", "10.0.0.1")
	other.Port = 2222
	b, err := CreateHost(db, other, now)
	if err != nil {
		t.Fatalf("same address, other port: %v", err)
	}

	if err := HostConflict(db, "web-1", "10.0.0.50", 22, 0); !errors.Is(err, ErrHostNameTaken) {
		t.Errorf("HostConflict name: %v", err)
	}
	if err := HostConflict(db, "new", "10.0.0.1", 22, 0); !errors.Is(err, ErrHostAddressTaken) {
		t.Errorf("HostConflict address: %v", err)
	}
	if err := HostConflict(db, "web-1", "10.0.0.1", 22, a.ID); err != nil {
		t.Errorf("a host does not conflict with itself: %v", err)
	}
	// Renaming into somebody else's address is refused by the update too.
	b.Port = 22
	if err := UpdateHostConnection(db, b); !errors.Is(err, ErrHostAddressTaken) {
		t.Errorf("update into a taken address: %v", err)
	}
}
