package web

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"infra-manager/internal/remote"
	"infra-manager/internal/remote/remotetest"
	"infra-manager/internal/store"
	"infra-manager/internal/tf"
)

func TestNextDailyRunAndCheckHHMM(t *testing.T) {
	for _, ok := range []string{"00:00", "03:00", "23:59"} {
		if _, _, err := checkHHMM(ok); err != nil {
			t.Errorf("checkHHMM(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "3:00", "24:00", "12:60", "ab:cd", "03:00:00"} {
		if _, _, err := checkHHMM(bad); err == nil {
			t.Errorf("checkHHMM(%q) accepted", bad)
		}
	}

	loc := time.FixedZone("UTC+8", 8*3600)
	before := time.Date(2026, 11, 22, 2, 15, 0, 0, loc)
	if got := nextDailyRun(before, "03:00"); !got.Equal(time.Date(2026, 11, 22, 3, 0, 0, 0, loc)) {
		t.Errorf("before: got %v", got)
	}
	exact := time.Date(2026, 11, 22, 3, 0, 0, 0, loc)
	if got := nextDailyRun(exact, "03:00"); !got.Equal(time.Date(2026, 11, 23, 3, 0, 0, 0, loc)) {
		t.Errorf("exact: got %v", got)
	}
	after := time.Date(2026, 11, 22, 14, 30, 0, 0, loc)
	if got := nextDailyRun(after, "03:00"); !got.Equal(time.Date(2026, 11, 23, 3, 0, 0, 0, loc)) {
		t.Errorf("after: got %v", got)
	}
}

func TestPickNextStepPriority(t *testing.T) {
	// Empty lab.
	if s := pickNextStep(overviewAnswer{}, nil, nil); s.Page != "hosts" || !strings.Contains(s.Title, "first host") {
		t.Errorf("empty: %+v", s)
	}

	// Security alert (key changed) beats offline.
	hosts := []store.Host{
		{ID: 1, Name: "h1", Status: remote.StatusOffline},
		{ID: 2, Name: "h2", Status: remote.StatusKeyChanged},
	}
	if s := pickNextStep(overviewAnswer{Hosts: 2}, hosts, nil); !strings.Contains(s.Title, "SSH key") {
		t.Errorf("key changed: %+v", s)
	}

	// Profile drift beats Proxmox drift and offers direct Fix when 1 host drifted.
	online := []store.Host{{ID: 7, Name: "web-1", Status: remote.StatusOnline}}
	o := overviewAnswer{
		Hosts: 1, Online: 1, ConfigDrifted: 1, MachinesDrifted: 1,
		ProfileDrift: []hostDrift{{HostID: 7, HostName: "web-1", Changes: []change{{Role: "nginx", Title: "site"}}}},
		MachineDrift: []tf.DriftDetail{{Machine: "web-1", Sentence: "web-1 changed"}},
	}
	if s := pickNextStep(o, online, nil); s.FixHost != 7 || !strings.Contains(s.Title, "drifted from its profile") {
		t.Errorf("profile drift: %+v", s)
	}

	// Once profile drift is fixed, Proxmox drift comes next.
	o.ConfigDrifted = 0
	o.ProfileDrift = nil
	if s := pickNextStep(o, online, nil); s.Page != "machines" || !strings.Contains(s.Title, "Proxmox") {
		t.Errorf("proxmox drift: %+v", s)
	}

	// All clear.
	o.MachinesDrifted = 0
	o.MachineDrift = nil
	if s := pickNextStep(o, online, nil); !s.Good {
		t.Errorf("all good: %+v", s)
	}
}

func TestScheduleSettingsAPI(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, viewer := a.user("vera", store.RoleViewer)

	rec := a.do("GET", "/api/schedule", viewer, nil)
	want(t, rec, http.StatusOK)
	var sched scheduleView
	if err := json.Unmarshal(rec.Body.Bytes(), &sched); err != nil || len(sched.Jobs) != 3 || sched.ComplianceTime != "03:00" || !sched.ComplianceEnabled {
		t.Fatalf("default schedule: %v %s", err, rec.Body.String())
	}

	// Invalid HH:MM is refused.
	want(t, a.do("POST", "/api/schedule", admin, map[string]any{"compliance_time": "25:00"}), http.StatusBadRequest)

	// Valid update persists and writes History.
	rec = a.do("POST", "/api/schedule", admin, map[string]any{"compliance_time": "04:30", "compliance_enabled": true})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"compliance_time":"04:30"`) || !strings.Contains(rec.Body.String(), `"Nightly at 04:30"`) {
		t.Fatalf("updated schedule: %s", rec.Body.String())
	}
	if !a.has("schedule.update", store.ResultOK) {
		t.Error("schedule.update not in History")
	}

	// Disabling clears next_run for compliance.
	rec = a.do("POST", "/api/schedule", admin, map[string]any{"compliance_time": "04:30", "compliance_enabled": false})
	want(t, rec, http.StatusOK)
	var disabled scheduleView
	_ = json.Unmarshal(rec.Body.Bytes(), &disabled)
	if disabled.ComplianceEnabled || disabled.Jobs[2].Enabled || disabled.Jobs[2].NextRun != 0 {
		t.Errorf("disabled schedule: %+v", disabled)
	}
}

// End-to-end IM9 vertical slice: configure web-1 with nginx -> simulate editing
// a file by hand -> compliance check marks web-1 drifted with diff -> Overview
// shows both profile drift and Proxmox drift + schedule + last runs + Next step
// -> Fix (Apply) makes web-1 compliant again.
func TestComplianceCheckDriftFixAndFullOverview(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)

	srv := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	idStr := a.addHost(admin, srv, "web-1")
	hostID := mustID(t, idStr)

	// Assign nginx profile and apply it.
	want(t, a.do("POST", "/api/hosts/"+idStr+"/profile", admin, map[string]any{
		"roles": []map[string]any{role("nginx", nil)},
	}), http.StatusNoContent)
	want(t, a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "host_id": hostID}), http.StatusOK)

	// Immediately after apply, compliance check reports zero drift.
	cRec := a.do("POST", "/api/compliance/check", operator, nil)
	want(t, cRec, http.StatusOK)
	if !strings.Contains(cRec.Body.String(), `"checked":1`) || !strings.Contains(cRec.Body.String(), `"drifted":[]`) {
		t.Fatalf("clean compliance: %s", cRec.Body.String())
	}

	// Simulate editing /etc/nginx/sites-enabled/app by hand (remove stub marker).
	_ = os.Remove(filepath.Join(a.s.ansible.Dir, ".applied-web-1-nginx"))

	cRec = a.do("POST", "/api/compliance/check", operator, nil)
	want(t, cRec, http.StatusOK)
	if !strings.Contains(cRec.Body.String(), `"host_name":"web-1"`) || !strings.Contains(cRec.Body.String(), "written by the stub for nginx on web-1") {
		t.Fatalf("drifted compliance: %s", cRec.Body.String())
	}

	// Hosts page marks web-1 as drifted with the diff attached.
	hRec := a.do("GET", "/api/hosts", operator, nil)
	want(t, hRec, http.StatusOK)
	if !strings.Contains(hRec.Body.String(), `"state":"drifted"`) || !strings.Contains(hRec.Body.String(), "written by the stub for nginx on web-1") {
		t.Fatalf("hosts drifted: %s", hRec.Body.String())
	}

	// Also record Proxmox drift so Overview shows both kinds of drift at once.
	a.s.setLastDrift(&driftReport{
		CheckedAt: time.Now().Unix(),
		Items:     []tf.DriftDetail{{Machine: "web-1", Action: "update", Sentence: "web-1 was changed outside the dashboard (memory 1024 → 2048)"}},
	})

	ovRec := a.do("GET", "/api/overview", operator, nil)
	want(t, ovRec, http.StatusOK)
	var ov overviewAnswer
	if err := json.Unmarshal(ovRec.Body.Bytes(), &ov); err != nil {
		t.Fatalf("overview json: %v", err)
	}
	if ov.ConfigDrifted != 1 || ov.MachinesDrifted != 1 || len(ov.ProfileDrift) != 1 || len(ov.MachineDrift) != 1 {
		t.Fatalf("overview both drifts: %+v", ov)
	}
	if ov.NextStep.FixHost != hostID || len(ov.Schedule.Jobs) != 3 || len(ov.LastRuns) == 0 {
		t.Fatalf("overview next_step/schedule/last_runs: %+v", ov)
	}

	// Fix (Apply) clears profile drift immediately and subsequent compliance check stays clean.
	want(t, a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "host_id": hostID}), http.StatusOK)

	ovRec = a.do("GET", "/api/overview", operator, nil)
	want(t, ovRec, http.StatusOK)
	_ = json.Unmarshal(ovRec.Body.Bytes(), &ov)
	if ov.ConfigDrifted != 0 || len(ov.ProfileDrift) != 0 {
		t.Fatalf("overview after fix: %+v", ov)
	}
	cRec = a.do("POST", "/api/compliance/check", operator, nil)
	want(t, cRec, http.StatusOK)
	if !strings.Contains(cRec.Body.String(), `"drifted":[]`) {
		t.Fatalf("compliance after fix: %s", cRec.Body.String())
	}
}

func TestRunMonitorStopsCleanlyOnCancel(t *testing.T) {
	a := newTestApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.s.RunMonitor(ctx)
		close(done)
	}()

	// Schedule wake should be handled without blocking, and cancel must exit immediately.
	select {
	case a.s.schedWake <- struct{}{}:
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunMonitor did not exit promptly after context cancel")
	}
}
