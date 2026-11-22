package store

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestGroupsMembersAndCascades(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	web1, _ := CreateHost(db, sampleHost("web-1", "10.0.0.1"), now)
	web2, _ := CreateHost(db, sampleHost("web-2", "10.0.0.2"), now)
	db1, _ := CreateHost(db, sampleHost("db-1", "10.0.0.3"), now)

	web, err := CreateGroup(db, "web", now)
	if err != nil || web.ID == 0 {
		t.Fatalf("create: %+v %v", web, err)
	}
	if _, err := CreateGroup(db, "web", now); !errors.Is(err, ErrGroupNameTaken) {
		t.Errorf("same name: %v", err)
	}
	// "web-1" is a host: a group of that name would be ambiguous to Ansible, and the other way round.
	if _, err := CreateGroup(db, "web-1", now); !errors.Is(err, ErrNameIsHost) {
		t.Errorf("a group named like a host: %v", err)
	}
	if err := HostConflict(db, "web", "10.9.9.9", 22, 0); !errors.Is(err, ErrNameIsGroup) {
		t.Errorf("a host named like a group: %v", err)
	}
	if err := RenameGroup(db, web.ID, "web-2"); !errors.Is(err, ErrNameIsHost) {
		t.Errorf("rename to a host's name: %v", err)
	}

	// Several at once, in one go; adding twice is harmless.
	if err := ChangeGroupHosts(db, web.ID, []int64{web1.ID, web2.ID, web1.ID}, nil); err != nil {
		t.Fatal(err)
	}
	g, err := GetGroup(db, web.ID)
	if err != nil || !reflect.DeepEqual(g.HostIDs, []int64{web1.ID, web2.ID}) {
		t.Fatalf("members: %+v %v", g, err)
	}
	if err := ChangeGroupHosts(db, web.ID, []int64{db1.ID}, []int64{web1.ID}); err != nil {
		t.Fatal(err)
	}
	g, _ = GetGroup(db, web.ID)
	if !reflect.DeepEqual(g.HostIDs, []int64{web2.ID, db1.ID}) {
		t.Errorf("members after add and remove: %+v", g.HostIDs)
	}
	// All or none: a host that does not exist undoes the whole change.
	if err := ChangeGroupHosts(db, web.ID, []int64{web1.ID, 999}, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown host: %v", err)
	}
	if g, _ = GetGroup(db, web.ID); len(g.HostIDs) != 2 {
		t.Errorf("a failed change was half applied: %+v", g.HostIDs)
	}
	if err := ChangeGroupHosts(db, 999, []int64{web1.ID}, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown group: %v", err)
	}

	names, err := HostGroupNames(db)
	if err != nil || !reflect.DeepEqual(names[web2.ID], []string{"web"}) || len(names[web1.ID]) != 0 {
		t.Errorf("group names: %+v %v", names, err)
	}

	// A host that is deleted leaves its groups; a group that is deleted leaves its hosts.
	if err := DeleteHost(db, db1.ID); err != nil {
		t.Fatal(err)
	}
	if g, _ = GetGroup(db, web.ID); !reflect.DeepEqual(g.HostIDs, []int64{web2.ID}) {
		t.Errorf("members after a host was deleted: %+v", g.HostIDs)
	}
	if err := SetGroupVars(db, web.ID, []Var{{"a", "1"}}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteGroup(db, web.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := GetHost(db, web2.ID); err != nil {
		t.Errorf("deleting a group deleted a host: %v", err)
	}
	if all, _ := AllGroupVars(db); len(all) != 0 {
		t.Errorf("the group's variables are still there: %+v", all)
	}
	if err := DeleteGroup(db, web.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice: %v", err)
	}
}

func TestVariablesAreReplacedWholeAndSorted(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	h, _ := CreateHost(db, sampleHost("web-1", "10.0.0.1"), now)
	g, _ := CreateGroup(db, "web", now)

	if err := SetGroupVars(db, g.ID, []Var{{"port", "80"}, {"domain", "app.example.com"}}); err != nil {
		t.Fatal(err)
	}
	got, err := GroupVars(db, g.ID)
	if err != nil || !reflect.DeepEqual(got, []Var{{"domain", "app.example.com"}, {"port", "80"}}) {
		t.Fatalf("vars: %+v %v", got, err)
	}
	// Setting again replaces: a variable left out is gone.
	if err := SetGroupVars(db, g.ID, []Var{{"port", "8080"}}); err != nil {
		t.Fatal(err)
	}
	if got, _ = GroupVars(db, g.ID); !reflect.DeepEqual(got, []Var{{"port", "8080"}}) {
		t.Errorf("after replacing: %+v", got)
	}
	if err := SetGroupVars(db, g.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ = GroupVars(db, g.ID); len(got) != 0 || got == nil {
		t.Errorf("after clearing: %#v (want an empty list, not nil)", got)
	}

	if err := SetHostVars(db, h.ID, []Var{{"role", "primary"}}); err != nil {
		t.Fatal(err)
	}
	all, err := AllHostVars(db)
	if err != nil || !reflect.DeepEqual(all[h.ID], []Var{{"role", "primary"}}) {
		t.Errorf("all host vars: %+v %v", all, err)
	}
	if err := SetHostVars(db, 999, []Var{{"a", "b"}}); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown host: %v", err)
	}
	if err := SetGroupVars(db, 999, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown group: %v", err)
	}
	// The host's variables go with the host.
	if err := DeleteHost(db, h.ID); err != nil {
		t.Fatal(err)
	}
	if all, _ = AllHostVars(db); len(all) != 0 {
		t.Errorf("a deleted host's variables are still there: %+v", all)
	}
}
