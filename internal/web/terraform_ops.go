package web

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"infra-manager/internal/run"
	"infra-manager/internal/store"
	"infra-manager/internal/tf"
)

// Drift check, Adopt and State backups / Restore (IM8). Every Terraform command
// here uses s.tfMu so only one Terraform job runs at a time (OD-04).

// ---------------------------------------------------------------------- drift

type driftReport struct {
	CheckedAt int64            `json:"checked_at"`
	Items     []tf.DriftDetail `json:"items"`
}

func (s *Server) getLastDrift() *driftReport {
	s.driftMu.Lock()
	defer s.driftMu.Unlock()
	if s.lastDrift == nil {
		return nil
	}
	cp := *s.lastDrift
	cp.Items = append([]tf.DriftDetail{}, s.lastDrift.Items...)
	return &cp
}

func (s *Server) setLastDrift(r *driftReport) {
	s.driftMu.Lock()
	defer s.driftMu.Unlock()
	s.lastDrift = r
}

// runDriftCheck runs `terraform plan -refresh-only` and reads resource_drift.
// Caller must hold s.tfMu.
func (s *Server) runDriftCheck() (driftReport, []run.Shown, int, string, string) {
	if _, err := s.generateTerraform(); err != nil {
		s.recordJobOutcome("drift", "failed", "could not write Terraform files")
		return driftReport{}, nil, http.StatusInternalServerError, "Could not write Terraform files.", ""
	}
	s.markJobStart("drift")
	plan, planPath, cmds, status, msg, detail := s.runPlan("drift-", "-refresh-only")
	if status != 0 {
		s.recordJobOutcome("drift", "failed", firstLine(msg))
		return driftReport{}, cmds, status, msg, detail
	}
	_ = os.Remove(planPath)

	items := make([]tf.DriftDetail, 0, len(plan.Drift))
	for _, c := range plan.Drift {
		items = append(items, tf.ExplainDrift(c))
	}
	rep := driftReport{CheckedAt: time.Now().Unix(), Items: items}
	s.setLastDrift(&rep)
	driftDetail := "no drift"
	if len(items) > 0 {
		driftDetail = plural(len(items), "container") + " drifted"
	}
	s.recordJobOutcome("drift", "ok", driftDetail)
	return rep, cmds, 0, "", ""
}

// driftRound is the scheduled check called from RunMonitor. It skips quietly
// when Proxmox or Terraform is not set up, no machines exist, or Terraform is busy.
func (s *Server) driftRound() {
	if s.terraformVersion() == "" {
		return
	}
	st, err := s.loadProxmoxSettings()
	if err != nil || !st.Configured {
		return
	}
	machines, err := store.ListMachines(s.db)
	if err != nil {
		return
	}
	hasApplied := false
	for _, m := range machines {
		if m.AppliedAt > 0 {
			hasApplied = true
			break
		}
	}
	if !hasApplied || !s.tfMu.TryLock() {
		return
	}
	defer s.tfMu.Unlock()

	if _, _, status, msg, _ := s.runDriftCheck(); status != 0 {
		slog.Warn("scheduled drift check failed", "msg", msg)
	}
}

func (s *Server) checkDrift(w http.ResponseWriter, r *http.Request, me store.User) {
	if s.terraformVersion() == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": tf.InstallHint, "missing": true})
		return
	}
	st, err := s.loadProxmoxSettings()
	if err != nil {
		serverError(w, "read Proxmox settings", err)
		return
	}
	if !st.Configured {
		writeError(w, http.StatusBadRequest, "Configure Proxmox in Settings first.")
		return
	}
	if !s.tfMu.TryLock() {
		writeError(w, http.StatusConflict, "Another Terraform job is running. Wait for it to finish.")
		return
	}
	defer s.tfMu.Unlock()

	rep, cmds, status, msg, detail := s.runDriftCheck()
	if status != 0 {
		writePlanError(w, status, msg, detail, cmds)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"drift": rep, "commands": cmds})
}

// acceptDrift writes the drifted size values from Proxmox into SQLite and
// refreshes Terraform state so dashboard, state and Proxmox match again.
func (s *Server) acceptDrift(w http.ResponseWriter, r *http.Request, me store.User) {
	m, ok := s.loadMachine(w, r)
	if !ok {
		return
	}
	target := "machine " + m.Name
	last := s.getLastDrift()
	var found *tf.DriftDetail
	if last != nil {
		for i := range last.Items {
			if last.Items[i].Machine == m.Name {
				found = &last.Items[i]
				break
			}
		}
	}
	if found == nil {
		s.failHost(w, r, me, "machine.accept_drift", target, http.StatusConflict, "No drift is recorded for this machine. Run a drift check first.")
		return
	}
	if found.Action == "destroy" {
		s.failHost(w, r, me, "machine.accept_drift", target, http.StatusConflict, "This container was deleted outside the dashboard. Use Put it back to recreate it, or Remove to forget it.")
		return
	}
	if s.terraformVersion() == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": tf.InstallHint, "missing": true})
		return
	}
	if !s.tfMu.TryLock() {
		writeError(w, http.StatusConflict, "Another Terraform job is running. Wait for it to finish.")
		return
	}
	defer s.tfMu.Unlock()

	cores, mem, disk := m.Cores, m.MemoryMB, m.DiskGB
	if found.Cores > 0 {
		cores = found.Cores
	}
	if found.MemoryMB > 0 {
		mem = found.MemoryMB
	}
	if found.DiskGB > 0 {
		disk = found.DiskGB
	}
	if err := tf.CheckMachineSize(cores, mem, disk); err != nil {
		s.failHost(w, r, me, "machine.accept_drift", target, http.StatusBadRequest, err.Error())
		return
	}

	// Backup and refresh Terraform state for ONLY this machine (refresh-only apply never touches Proxmox).
	if _, berr := tf.BackupState(s.tf.Dir, time.Now()); berr != nil {
		slog.Error("backup state before accept drift", "err", berr)
	}
	targetFlag := fmt.Sprintf(`-target=proxmox_virtual_environment_container.machine[%q]`, m.Name)
	_, planPath, _, status, msg, _ := s.runPlan("accept-", "-refresh-only", targetFlag)
	if status != 0 {
		s.failHost(w, r, me, "machine.accept_drift", target, status, msg)
		return
	}
	defer os.Remove(planPath)

	secret, _ := tf.LoadTokenSecret(s.tf.SecretFile)
	if res, err := run.Output(s.tf.ApplyCmd(planPath), 5*time.Minute); err != nil || res.Exit != 0 {
		errMsg := "Could not update Terraform state."
		if err != nil {
			errMsg = scrubSecret(err.Error(), secret)
		}
		s.failHost(w, r, me, "machine.accept_drift", target, http.StatusBadGateway, errMsg)
		return
	}

	if err := store.UpdateMachineSize(s.db, m.ID, cores, mem, disk); err != nil {
		serverError(w, "update machine size", err)
		return
	}
	m.Cores, m.MemoryMB, m.DiskGB = cores, mem, disk
	if err := store.MarkMachineApplied(s.db, m.ID, m.VMID, m.IPResolved, m.SizeSpec(), time.Now()); err != nil {
		serverError(w, "mark machine applied", err)
		return
	}
	_, _ = s.generateTerraform()
	s.clearPendingPlan()

	// Remove this machine from the cached drift report.
	if last != nil {
		var rest []tf.DriftDetail
		for _, item := range last.Items {
			if item.Machine != m.Name {
				rest = append(rest, item)
			}
		}
		if rest == nil {
			rest = []tf.DriftDetail{}
		}
		s.setLastDrift(&driftReport{CheckedAt: last.CheckedAt, Items: rest})
	}
	s.record(r, me, "machine.accept_drift", target, store.ResultOK, found.Sentence)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------- adopt

// adoptPreview writes a temporary import block + candidate machine into
// terraform/ and runs `terraform plan`. Adopt is allowed ONLY when the plan
// shows zero changes; otherwise the mismatches are returned and nothing is kept.
func (s *Server) adoptPreview(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Node     string  `json:"node"`
		VMID     int     `json:"vmid"`
		Name     string  `json:"name"`
		Cores    int     `json:"cores"`
		MemoryMB int     `json:"memory_mb"`
		DiskGB   int     `json:"disk_gb"`
		Storage  string  `json:"storage"`
		Bridge   string  `json:"bridge"`
		Template string  `json:"template"`
		IPMode   string  `json:"ip_mode"`
		IPCIDR   string  `json:"ip_cidr"`
		Gateway  string  `json:"gateway"`
		GroupIDs []int64 `json:"group_ids"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	node, storage, bridge := strings.TrimSpace(req.Node), strings.TrimSpace(req.Storage), strings.TrimSpace(req.Bridge)
	tmpl := strings.TrimSpace(req.Template)
	if tmpl == "" {
		tmpl = "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst"
	}
	ipMode := strings.ToLower(strings.TrimSpace(req.IPMode))

	if req.VMID < 100 {
		writeError(w, http.StatusBadRequest, "VM ID must be 100 or higher.")
		return
	}
	for _, err := range []error{
		tf.CheckMachineName(name),
		tf.CheckIdent(node, "Proxmox node"),
		tf.CheckMachineSize(req.Cores, req.MemoryMB, req.DiskGB),
		tf.CheckIdent(storage, "Proxmox storage"),
		tf.CheckIdent(bridge, "network bridge"),
		tf.CheckTemplateID(tmpl),
	} {
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	cleanCIDR, staticIP, cleanGW, err := tf.CheckIPConfig(ipMode, req.IPCIDR, req.Gateway)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := store.MachineConflict(s.db, name, staticIP); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if s.terraformVersion() == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": tf.InstallHint, "missing": true})
		return
	}
	st, err := s.loadProxmoxSettings()
	if err != nil {
		serverError(w, "read Proxmox settings", err)
		return
	}
	if !st.Configured {
		writeError(w, http.StatusBadRequest, "Configure Proxmox in Settings first.")
		return
	}
	if !s.tfMu.TryLock() {
		writeError(w, http.StatusConflict, "Another Terraform job is running. Wait for it to finish.")
		return
	}
	defer s.tfMu.Unlock()

	candidate := store.Machine{
		Name: name, Node: node, VMID: req.VMID, Cores: req.Cores, MemoryMB: req.MemoryMB, DiskGB: req.DiskGB,
		Storage: storage, Bridge: bridge, Template: tmpl, IPMode: ipMode, IPCIDR: cleanCIDR, Gateway: cleanGW,
		GroupIDs: req.GroupIDs,
	}
	if candidate.GroupIDs == nil {
		candidate.GroupIDs = []int64{}
	}

	cleanup := func() {
		tf.ClearImport(s.tf.Dir)
		_, _ = s.generateTerraform()
	}

	snap, err := s.generateTerraformWith(&candidate)
	if err != nil {
		serverError(w, "write Terraform files", err)
		return
	}
	if err := tf.WriteImport(s.tf.Dir, name, node, req.VMID); err != nil {
		cleanup()
		serverError(w, "write import block", err)
		return
	}

	plan, planPath, cmds, status, msg, detail := s.runPlan("adopt-")
	if status != 0 {
		cleanup()
		writePlanError(w, status, msg, detail, cmds)
		return
	}

	// Roadmap rule: review must show NO changes before Adopt is allowed.
	if len(plan.Changes) > 0 {
		_ = os.Remove(planPath)
		cleanup()
		writeJSON(w, http.StatusOK, map[string]any{
			"ready":         false,
			"plain_summary": "Cannot adopt yet: the settings do not match Proxmox. Fix the differences below and check again.",
			"changes":       toChangeViews(plan.Changes),
			"commands":      cmds,
		})
		return
	}

	s.setPendingPlan(&savedPlan{
		ID: plan.ID, File: planPath, Created: plan.Created, Snapshot: snap,
		Summary: fmt.Sprintf("Adopt %s (VM %d on %s)", name, req.VMID, node),
		Actions: map[string]string{name: "adopt"},
		Adopt:   &candidate,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ready":         true,
		"plan_id":       plan.ID,
		"plain_summary": fmt.Sprintf("No changes: %s (VM %d) matches Proxmox and is ready to adopt.", name, req.VMID),
		"changes":       []planChangeView{},
		"commands":      cmds,
	})
}

func (s *Server) finishAdopt(r *http.Request, me store.User, candidate store.Machine, stateMap map[string]tf.StateMachine, out *sseWriter) applyOutcome {
	res := applyOutcome{
		Created: []string{}, Updated: []string{}, Replaced: []string{}, Destroyed: []string{},
		HostsAdded: []string{}, Configured: []string{}, Warnings: []string{},
	}
	now := time.Now()
	m, err := store.CreateMachine(s.db, candidate, now)
	if err != nil {
		res.Error = "Adopted in Terraform, but could not save machine: " + err.Error()
		s.record(r, me, "machine.adopt", "machine "+candidate.Name, store.ResultFailed, err.Error())
		return res
	}
	sm := stateMap[m.Name]
	vmid := m.VMID
	if sm.VMID > 0 {
		vmid = sm.VMID
	}
	client, _, _ := s.proxmoxClient()
	ip := s.resolveMachineIP(m, sm, client, out)
	_ = store.MarkMachineApplied(s.db, m.ID, vmid, ip, m.SizeSpec(), now)
	m.VMID, m.IPResolved = vmid, ip
	res.Created = append(res.Created, m.Name)

	if ip != "" {
		host, warn := s.enrollMachineHost(m, ip, out)
		if warn != "" {
			res.Warnings = append(res.Warnings, warn)
		}
		if host.ID > 0 {
			res.HostsAdded = append(res.HostsAdded, host.Name)
		}
	} else {
		res.Warnings = append(res.Warnings, m.Name+" was adopted, but no IP address could be read from Proxmox yet.")
	}
	s.record(r, me, "machine.adopt", "machine "+m.Name, store.ResultOK, fmt.Sprintf("VM %d on %s", vmid, m.Node))
	return res
}

// --------------------------------------------------- state backups & restore

func (s *Server) listBackups(w http.ResponseWriter, r *http.Request, me store.User) {
	list, err := tf.ListBackups(s.tf.Dir)
	if err != nil {
		serverError(w, "list state backups", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backups": list})
}

// previewRestore runs `terraform plan -state=<backup>` to show what restoring
// this backup would lead to without touching the live terraform.tfstate.
func (s *Server) previewRestore(w http.ResponseWriter, r *http.Request, me store.User) {
	id := r.PathValue("id")
	backupPath, err := tf.BackupPath(s.tf.Dir, id)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := os.Stat(backupPath); errors.Is(err, fs.ErrNotExist) {
		writeError(w, http.StatusNotFound, "There is no such state backup.")
		return
	}
	if s.terraformVersion() == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": tf.InstallHint, "missing": true})
		return
	}
	if !s.tfMu.TryLock() {
		writeError(w, http.StatusConflict, "Another Terraform job is running. Wait for it to finish.")
		return
	}
	defer s.tfMu.Unlock()

	if _, err := s.generateTerraform(); err != nil {
		serverError(w, "write Terraform files", err)
		return
	}
	plan, planPath, cmds, status, msg, detail := s.runPlan("restore-", "-state="+backupPath)
	if status != 0 {
		writePlanError(w, status, msg, detail, cmds)
		return
	}
	_ = os.Remove(planPath)

	writeJSON(w, http.StatusOK, map[string]any{
		"backup_id":     id,
		"plain_summary": tf.PlainSummary(plan),
		"summary":       plan.Summary,
		"changes":       toChangeViews(plan.Changes),
		"commands":      cmds,
	})
}

func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request, me store.User) {
	id := r.PathValue("id")
	if err := tf.CheckBackupID(id); err != nil {
		s.failHost(w, r, me, "terraform.restore", "state "+id, http.StatusBadRequest, err.Error())
		return
	}
	if !s.tfMu.TryLock() {
		writeError(w, http.StatusConflict, "Another Terraform job is running. Wait for it to finish.")
		return
	}
	defer s.tfMu.Unlock()

	err := tf.RestoreBackup(s.tf.Dir, id, time.Now())
	if errors.Is(err, fs.ErrNotExist) {
		s.failHost(w, r, me, "terraform.restore", "state "+id, http.StatusNotFound, "There is no such state backup.")
		return
	}
	if err != nil {
		serverError(w, "restore state backup", err)
		return
	}
	s.clearPendingPlan()
	s.setLastDrift(nil)
	s.record(r, me, "terraform.restore", "state "+id, store.ResultOK, "current state backed up before restore")
	w.WriteHeader(http.StatusNoContent)
}
