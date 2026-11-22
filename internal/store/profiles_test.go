package store

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"infra-manager/internal/ansible"
)

func TestProfilesBelongToAGroupOrAHostAndAreReplacedWhole(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	h, _ := CreateHost(db, sampleHost("web-1", "10.0.0.1"), now)
	g, _ := CreateGroup(db, "web", now)

	nginx := ansible.ProfileRole{Role: "nginx", Params: map[string]any{"nginx_domain": "app.example.com"}}
	base := ansible.ProfileRole{Role: "base", Params: map[string]any{}}
	if err := SetProfile(db, ScopeGroup, g.ID, []ansible.ProfileRole{nginx, base}); err != nil {
		t.Fatal(err)
	}
	if err := SetProfile(db, ScopeHost, h.ID, []ansible.ProfileRole{{Role: "docker", Params: map[string]any{}}}); err != nil {
		t.Fatal(err)
	}

	got, err := GetProfile(db, ScopeGroup, g.ID)
	if err != nil || !reflect.DeepEqual(got, []ansible.ProfileRole{nginx, base}) {
		t.Fatalf("group profile: %+v %v", got, err)
	}
	groups, hosts, err := AllProfiles(db)
	if err != nil || len(groups[g.ID]) != 2 || len(hosts[h.ID]) != 1 || hosts[h.ID][0].Role != "docker" {
		t.Fatalf("all: %+v %+v %v", groups, hosts, err)
	}

	// Setting again replaces: a role left out is gone, and parameters keep their types.
	if err := SetProfile(db, ScopeGroup, g.ID, []ansible.ProfileRole{{Role: "firewall", Params: map[string]any{"firewall_allow_ports": []any{"8080/tcp"}}}}); err != nil {
		t.Fatal(err)
	}
	got, _ = GetProfile(db, ScopeGroup, g.ID)
	if len(got) != 1 || got[0].Role != "firewall" || !reflect.DeepEqual(got[0].Params["firewall_allow_ports"], []any{"8080/tcp"}) {
		t.Errorf("after replacing: %+v", got)
	}
	if err := SetProfile(db, ScopeGroup, g.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ = GetProfile(db, ScopeGroup, g.ID); len(got) != 0 || got == nil {
		t.Errorf("an empty profile: %#v (want an empty list, not nil)", got)
	}

	// The same role twice in one profile is refused by the database itself.
	if err := SetProfile(db, ScopeHost, h.ID, []ansible.ProfileRole{{Role: "base"}, {Role: "base"}}); err == nil {
		t.Error("a role twice in a profile was stored")
	}
	if got, _ := GetProfile(db, ScopeHost, h.ID); len(got) != 1 {
		t.Errorf("the failed change was half applied: %+v", got)
	}

	if err := SetProfile(db, ScopeGroup, 999, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown group: %v", err)
	}
	if err := SetProfile(db, "planet", 1, nil); err == nil {
		t.Error("an unknown scope")
	}

	// A profile goes with its group or host.
	if err := DeleteGroup(db, g.ID); err != nil {
		t.Fatal(err)
	}
	if err := DeleteHost(db, h.ID); err != nil {
		t.Fatal(err)
	}
	groups, hosts, _ = AllProfiles(db)
	if len(groups) != 0 || len(hosts) != 0 {
		t.Errorf("profiles outlived their owners: %+v %+v", groups, hosts)
	}
}

func TestRunsAndWhatWasApplied(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	h, _ := CreateHost(db, sampleHost("web-1", "10.0.0.1"), now)

	if cfg, _ := AllHostConfig(db); len(cfg) != 0 {
		t.Fatalf("a host that was never configured has a record: %+v", cfg)
	}
	hashes := map[string]string{"base": "aaa", "nginx": "bbb"}

	// A run that worked marks its roles as applied.
	if err := RecordRun(db, h.ID, true, "5 changes", hashes, now); err != nil {
		t.Fatal(err)
	}
	applied, _ := AppliedRoles(db)
	if !reflect.DeepEqual(applied[h.ID], hashes) {
		t.Errorf("applied: %+v", applied)
	}
	cfg, _ := AllHostConfig(db)
	if c := cfg[h.ID]; c.Result != "ok" || c.Detail != "5 changes" || c.RunAt != now.Unix() || c.Idempotent != -1 {
		t.Errorf("config: %+v", c)
	}

	// Check again says whether a second run changed anything.
	if err := SetIdempotent(db, h.ID, true); err != nil {
		t.Fatal(err)
	}
	if cfg, _ = AllHostConfig(db); cfg[h.ID].Idempotent != 1 {
		t.Errorf("idempotent: %+v", cfg[h.ID])
	}

	// A run that failed marks nothing as applied, and keeps what was applied before
	// (it may well still be there); it forgets the verdict.
	if err := RecordRun(db, h.ID, false, "nginx: boom", map[string]string{"base": "zzz"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if applied, _ = AppliedRoles(db); !reflect.DeepEqual(applied[h.ID], hashes) {
		t.Errorf("a failed run changed what was applied: %+v", applied)
	}
	if cfg, _ = AllHostConfig(db); cfg[h.ID].Result != "failed" || cfg[h.ID].Idempotent != -1 {
		t.Errorf("after a failed run: %+v", cfg[h.ID])
	}

	// A later success updates one role and leaves the other.
	if err := RecordRun(db, h.ID, true, "1 change", map[string]string{"nginx": "ccc"}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if applied, _ = AppliedRoles(db); applied[h.ID]["nginx"] != "ccc" || applied[h.ID]["base"] != "aaa" {
		t.Errorf("after a run of one role: %+v", applied[h.ID])
	}

	if err := SetIdempotent(db, 999, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown host: %v", err)
	}
	if err := DeleteHost(db, h.ID); err != nil {
		t.Fatal(err)
	}
	if applied, _ = AppliedRoles(db); len(applied) != 0 {
		t.Errorf("a deleted host's history of runs is still there: %+v", applied)
	}
}
