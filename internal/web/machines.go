package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"infra-manager/internal/ansible"
	"infra-manager/internal/remote"
	"infra-manager/internal/run"
	"infra-manager/internal/store"
	"infra-manager/internal/tf"
)

// Proxmox machines and Terraform plan/apply (IM7). Desired state lives in
// SQLite; Review changes generates terraform/ and runs `terraform plan -out`;
// Apply applies that exact saved plan once within 15 minutes (OD-04), then
// enrolls new containers as hosts and runs their groups' profile if ticked.

type savedPlan struct {
	ID       string
	File     string
	Created  time.Time
	Snapshot string
	Summary  string
	Actions  map[string]string // machine name -> create/update/replace/destroy
	Adopt    *store.Machine    // non-nil when this plan imports an unmanaged container (IM8)
}

func (s *Server) clearPendingPlan() {
	s.planMu.Lock()
	defer s.planMu.Unlock()
	if s.pendingPlan != nil {
		_ = os.Remove(s.pendingPlan.File)
		if s.pendingPlan.Adopt != nil {
			tf.ClearImport(s.tf.Dir)
		}
		s.pendingPlan = nil
	}
}

func (s *Server) setPendingPlan(p *savedPlan) {
	s.planMu.Lock()
	defer s.planMu.Unlock()
	if s.pendingPlan != nil && s.pendingPlan.File != p.File {
		_ = os.Remove(s.pendingPlan.File)
		if s.pendingPlan.Adopt != nil && p.Adopt == nil {
			tf.ClearImport(s.tf.Dir)
		}
	}
	s.pendingPlan = p
}

func (s *Server) pendingAdoptFor(id string) *store.Machine {
	s.planMu.Lock()
	defer s.planMu.Unlock()
	if s.pendingPlan != nil && s.pendingPlan.ID == id && s.pendingPlan.Adopt != nil {
		cp := *s.pendingPlan.Adopt
		return &cp
	}
	return nil
}

// takePendingPlan consumes the saved plan so it can only be applied once, within
// 15 minutes, and only if the desired machines have not changed since.
func (s *Server) takePendingPlan(id, currentSnapshot string) (*savedPlan, string) {
	s.planMu.Lock()
	defer s.planMu.Unlock()
	if s.pendingPlan == nil || id == "" || s.pendingPlan.ID != id {
		return nil, "That plan is no longer available (it was already applied, replaced, or cleared). Review the changes again."
	}
	p := s.pendingPlan
	s.pendingPlan = nil
	if time.Since(p.Created) > s.provision.planTTL {
		_ = os.Remove(p.File)
		if p.Adopt != nil {
			tf.ClearImport(s.tf.Dir)
		}
		return nil, "This plan is more than 15 minutes old. Review the changes again."
	}
	if p.Snapshot != currentSnapshot {
		_ = os.Remove(p.File)
		if p.Adopt != nil {
			tf.ClearImport(s.tf.Dir)
		}
		return nil, "The machines changed since this plan was made. Review the changes again."
	}
	return p, ""
}

// generateTerraform writes the four managed Terraform files from SQLite and
// returns a SHA-256 snapshot of the desired state.
func (s *Server) generateTerraform() (string, error) { return s.generateTerraformWith(nil) }

// generateTerraformWith also includes one candidate machine during Adopt preview/apply.
func (s *Server) generateTerraformWith(extra *store.Machine) (string, error) {
	s.tfGenMu.Lock()
	defer s.tfGenMu.Unlock()

	st, err := s.loadProxmoxSettings()
	if err != nil {
		return "", err
	}
	machines, err := store.ListMachines(s.db)
	if err != nil {
		return "", err
	}
	if extra != nil {
		machines = append(machines, *extra)
	}

	specs := map[string]tf.MachineSpec{}
	var deletes []string
	for _, m := range machines {
		if m.PendingDelete {
			deletes = append(deletes, m.Name)
			continue
		}
		specs[m.Name] = tf.MachineSpec{
			Node: m.Node, Cores: m.Cores, Memory: m.MemoryMB, DiskGB: m.DiskGB,
			Storage: m.Storage, Bridge: m.Bridge, Template: m.Template,
			OSType: tf.InferOSType(m.Template), IPMode: m.IPMode, IPCIDR: m.IPCIDR, Gateway: m.Gateway,
		}
	}
	files, err := tf.Render(tf.Input{
		Endpoint: st.Endpoint, TokenID: st.TokenID, Insecure: st.Insecure,
		SSHPublicKey: s.remote.PublicKey(), Machines: specs,
	})
	if err != nil {
		return "", err
	}
	if err := tf.Write(s.tf.Dir, files); err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(files["machines.auto.tfvars.json"] + "\ndelete:" + strings.Join(deletes, ",")))
	return hex.EncodeToString(h[:]), nil
}

// ------------------------------------------------------------------ machines

type machineView struct {
	store.Machine
	Groups     []string `json:"groups"`
	Status     string   `json:"status"`      // will_be_created, running, stopped, will_change, will_be_removed, unknown
	RealStatus string   `json:"real_status"` // not_created, running, stopped, unknown
	HostName   string   `json:"host_name,omitempty"`
	HostStatus string   `json:"host_status,omitempty"`
}

func (s *Server) listMachines(w http.ResponseWriter, r *http.Request, me store.User) {
	st, err := s.loadProxmoxSettings()
	if err != nil {
		serverError(w, "read Proxmox settings", err)
		return
	}
	machines, err := store.ListMachines(s.db)
	if err != nil {
		serverError(w, "list machines", err)
		return
	}
	groups, err := store.ListGroups(s.db)
	if err != nil {
		serverError(w, "list groups", err)
		return
	}
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		serverError(w, "list hosts", err)
		return
	}
	groupNames := map[int64]string{}
	for _, g := range groups {
		groupNames[g.ID] = g.Name
	}
	hostByID := map[int64]store.Host{}
	for _, h := range hosts {
		hostByID[h.ID] = h
	}

	// Read live container status from Proxmox for nodes that have applied machines.
	liveByVMID := map[string]string{}
	proxmoxErr := ""
	if client, _, cerr := s.proxmoxClient(); cerr == nil && client != nil {
		seen := map[string]bool{}
		for _, m := range machines {
			if m.AppliedAt == 0 || seen[m.Node] {
				continue
			}
			seen[m.Node] = true
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			cts, lerr := client.ListContainers(ctx, m.Node)
			cancel()
			if lerr != nil {
				if proxmoxErr == "" {
					proxmoxErr = lerr.Error()
				}
				continue
			}
			for _, ct := range cts {
				liveByVMID[fmt.Sprintf("%s/%d", m.Node, ct.VMID)] = ct.Status
			}
		}
	}

	views := make([]machineView, len(machines))
	hasPending := false
	for i, m := range machines {
		if m.HasPendingChange() {
			hasPending = true
		}
		v := machineView{Machine: m, Groups: []string{}, RealStatus: "not_created"}
		for _, gid := range m.GroupIDs {
			if name, ok := groupNames[gid]; ok {
				v.Groups = append(v.Groups, name)
			}
		}
		if h, ok := hostByID[m.HostID]; ok {
			v.HostName, v.HostStatus = h.Name, h.Status
		}
		if m.AppliedAt > 0 {
			v.RealStatus = firstNonEmpty(liveByVMID[fmt.Sprintf("%s/%d", m.Node, m.VMID)], "unknown")
		}
		switch {
		case m.AppliedAt == 0:
			v.Status = "will_be_created"
		case m.PendingDelete:
			v.Status = "will_be_removed"
		case m.SizeSpec() != m.AppliedSpec:
			v.Status = "will_change"
		case v.RealStatus == "running", v.RealStatus == "stopped":
			v.Status = v.RealStatus
		default:
			v.Status = "unknown"
		}
		views[i] = v
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"machines": views, "configured": st.Configured, "has_pending": hasPending,
		"proxmox_error": proxmoxErr, "terraform": s.terraformStatusMap(), "drift": s.getLastDrift(),
	})
}

func (s *Server) loadMachine(w http.ResponseWriter, r *http.Request) (store.Machine, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "There is no such machine.")
		return store.Machine{}, false
	}
	m, err := store.GetMachine(s.db, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "There is no such machine.")
		return store.Machine{}, false
	}
	if err != nil {
		serverError(w, "read the machine", err)
		return store.Machine{}, false
	}
	return m, true
}

func (s *Server) createMachine(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Name          string  `json:"name"`
		Node          string  `json:"node"`
		Cores         int     `json:"cores"`
		MemoryMB      int     `json:"memory_mb"`
		DiskGB        int     `json:"disk_gb"`
		Storage       string  `json:"storage"`
		Bridge        string  `json:"bridge"`
		Template      string  `json:"template"`
		IPMode        string  `json:"ip_mode"`
		IPCIDR        string  `json:"ip_cidr"`
		Gateway       string  `json:"gateway"`
		AutoConfigure bool    `json:"auto_configure"`
		GroupIDs      []int64 `json:"group_ids"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	node, storage, bridge, tmpl := strings.TrimSpace(req.Node), strings.TrimSpace(req.Storage), strings.TrimSpace(req.Bridge), strings.TrimSpace(req.Template)
	ipMode := strings.ToLower(strings.TrimSpace(req.IPMode))
	target := "machine " + name

	for _, err := range []error{
		tf.CheckMachineName(name),
		tf.CheckIdent(node, "Proxmox node"),
		tf.CheckMachineSize(req.Cores, req.MemoryMB, req.DiskGB),
		tf.CheckIdent(storage, "Proxmox storage"),
		tf.CheckIdent(bridge, "network bridge"),
		tf.CheckTemplateID(tmpl),
	} {
		if err != nil {
			s.failHost(w, r, me, "machine.create", target, http.StatusBadRequest, err.Error())
			return
		}
	}
	cleanCIDR, staticIP, cleanGW, err := tf.CheckIPConfig(ipMode, req.IPCIDR, req.Gateway)
	if err != nil {
		s.failHost(w, r, me, "machine.create", target, http.StatusBadRequest, err.Error())
		return
	}

	groups, err := store.ListGroups(s.db)
	if err != nil {
		serverError(w, "list groups", err)
		return
	}
	known := map[int64]bool{}
	for _, g := range groups {
		known[g.ID] = true
	}
	cleanGroups := []int64{}
	seen := map[int64]bool{}
	for _, gid := range req.GroupIDs {
		if !known[gid] {
			s.failHost(w, r, me, "machine.create", target, http.StatusBadRequest, "One of the selected groups does not exist.")
			return
		}
		if !seen[gid] {
			seen[gid] = true
			cleanGroups = append(cleanGroups, gid)
		}
	}
	if err := store.MachineConflict(s.db, name, staticIP); err != nil {
		s.failHost(w, r, me, "machine.create", target, http.StatusConflict, err.Error())
		return
	}

	m, err := store.CreateMachine(s.db, store.Machine{
		Name: name, Node: node, Cores: req.Cores, MemoryMB: req.MemoryMB, DiskGB: req.DiskGB,
		Storage: storage, Bridge: bridge, Template: tmpl,
		IPMode: ipMode, IPCIDR: cleanCIDR, Gateway: cleanGW,
		AutoConfigure: req.AutoConfigure, GroupIDs: cleanGroups,
	}, time.Now())
	if errors.Is(err, store.ErrMachineNameTaken) {
		s.failHost(w, r, me, "machine.create", target, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		serverError(w, "create machine", err)
		return
	}
	s.clearPendingPlan()
	s.record(r, me, "machine.create", target, store.ResultOK,
		fmt.Sprintf("%s: %d CPU, %d MB, %d GB (%s)", node, m.Cores, m.MemoryMB, m.DiskGB, firstNonEmpty(cleanCIDR, "DHCP")))
	writeJSON(w, http.StatusCreated, map[string]any{"machine": m})
}

func (s *Server) resizeMachine(w http.ResponseWriter, r *http.Request, me store.User) {
	m, ok := s.loadMachine(w, r)
	if !ok {
		return
	}
	target := "machine " + m.Name
	if m.PendingDelete {
		s.failHost(w, r, me, "machine.resize", target, http.StatusConflict, "This machine is marked for removal. Cancel the removal first.")
		return
	}
	var req struct {
		Cores    int `json:"cores"`
		MemoryMB int `json:"memory_mb"`
		DiskGB   int `json:"disk_gb"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := tf.CheckMachineSize(req.Cores, req.MemoryMB, req.DiskGB); err != nil {
		s.failHost(w, r, me, "machine.resize", target, http.StatusBadRequest, err.Error())
		return
	}
	if err := store.UpdateMachineSize(s.db, m.ID, req.Cores, req.MemoryMB, req.DiskGB); err != nil {
		serverError(w, "resize machine", err)
		return
	}
	s.clearPendingPlan()
	s.record(r, me, "machine.resize", target, store.ResultOK,
		fmt.Sprintf("%d CPU, %d MB, %d GB → %d CPU, %d MB, %d GB", m.Cores, m.MemoryMB, m.DiskGB, req.Cores, req.MemoryMB, req.DiskGB))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeMachine(w http.ResponseWriter, r *http.Request, me store.User) {
	m, ok := s.loadMachine(w, r)
	if !ok {
		return
	}
	target := "machine " + m.Name
	if m.AppliedAt == 0 {
		if err := store.DeleteMachine(s.db, m.ID); err != nil {
			serverError(w, "delete machine", err)
			return
		}
		s.clearPendingPlan()
		s.record(r, me, "machine.remove", target, store.ResultOK, "discarded before creation")
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
		return
	}
	if err := store.SetMachinePendingDelete(s.db, m.ID, true); err != nil {
		serverError(w, "mark machine for removal", err)
		return
	}
	s.clearPendingPlan()
	s.record(r, me, "machine.remove", target, store.ResultOK, "marked for removal")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": false})
}

func (s *Server) cancelMachine(w http.ResponseWriter, r *http.Request, me store.User) {
	m, ok := s.loadMachine(w, r)
	if !ok {
		return
	}
	if m.AppliedAt == 0 {
		s.failHost(w, r, me, "machine.cancel", "machine "+m.Name, http.StatusConflict, "This machine has not been created yet.")
		return
	}
	if err := store.RevertMachine(s.db, m.ID); err != nil {
		serverError(w, "revert machine", err)
		return
	}
	s.clearPendingPlan()
	s.record(r, me, "machine.cancel", "machine "+m.Name, store.ResultOK, "reverted unapplied changes")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) startMachine(w http.ResponseWriter, r *http.Request, me store.User) {
	s.powerMachine(w, r, me, true)
}

func (s *Server) stopMachine(w http.ResponseWriter, r *http.Request, me store.User) {
	s.powerMachine(w, r, me, false)
}

func (s *Server) powerMachine(w http.ResponseWriter, r *http.Request, me store.User, start bool) {
	m, ok := s.loadMachine(w, r)
	if !ok {
		return
	}
	action, state := "machine.stop", "stopped"
	if start {
		action, state = "machine.start", "running"
	}
	target := "machine " + m.Name
	if m.AppliedAt == 0 || m.VMID == 0 {
		s.failHost(w, r, me, action, target, http.StatusConflict, "This machine has not been created on Proxmox yet.")
		return
	}
	client, _, err := s.proxmoxClient()
	if err != nil {
		serverError(w, "read Proxmox settings", err)
		return
	}
	if client == nil {
		s.failHost(w, r, me, action, target, http.StatusBadRequest, "Configure Proxmox in Settings first.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if start {
		err = client.StartContainer(ctx, m.Node, m.VMID)
	} else {
		err = client.StopContainer(ctx, m.Node, m.VMID)
	}
	if err != nil {
		s.failHost(w, r, me, action, target, http.StatusBadGateway, err.Error())
		return
	}
	s.record(r, me, action, target, store.ResultOK, fmt.Sprintf("VM %d on %s is now %s", m.VMID, m.Node, state))
	writeJSON(w, http.StatusOK, map[string]any{"status": state})
}

// ------------------------------------------------------ Terraform plan & apply

type planChangeView struct {
	Machine     string          `json:"machine"`
	Action      string          `json:"action"`
	PlainAction string          `json:"plain_action"`
	Reason      string          `json:"reason,omitempty"`
	Attributes  []tf.AttrChange `json:"attributes"`
}

func toChangeViews(changes []tf.Change) []planChangeView {
	out := make([]planChangeView, len(changes))
	for i, c := range changes {
		out[i] = planChangeView{
			Machine: tf.MachineName(c.Address), Action: c.Action,
			PlainAction: tf.PlainAction(c.Action), Reason: c.Reason, Attributes: c.Attributes,
		}
	}
	return out
}

func writePlanError(w http.ResponseWriter, status int, msg, detail string, cmds []run.Shown) {
	body := map[string]any{"error": msg}
	if detail != "" {
		body["detail"] = detail
	}
	if len(cmds) > 0 {
		body["commands"] = cmds
	}
	writeJSON(w, status, body)
}

// runPlan ensures Terraform is initialized, runs `terraform plan -out` with the
// given extra flags, parses `terraform show -json`, and returns the plan along
// with its saved plan file path. Caller must hold s.tfMu and remove planPath
// when it is no longer needed.
func (s *Server) runPlan(prefix string, flags ...string) (*tf.Plan, string, []run.Shown, int, string, string) {
	secrets := s.streamSecrets()
	failRes := func(res run.Result, cmds []run.Shown) (*tf.Plan, string, []run.Shown, int, string, string) {
		raw := scrubSecrets(strings.TrimSpace(res.Stderr+"\n"+res.Stdout), secrets)
		msg := firstNonEmpty(tf.Explain(raw), firstLine(strings.TrimSpace(scrubSecrets(res.Message(), secrets))), fmt.Sprintf("Terraform failed (exit %d).", res.Exit))
		return nil, "", cmds, http.StatusBadGateway, msg, raw
	}

	var cmds []run.Shown
	if !s.tf.IsInitialized() {
		initCmd := s.tf.InitCmd()
		cmds = append(cmds, initCmd.Shown())
		res, err := run.Output(initCmd, 5*time.Minute)
		if err != nil {
			return nil, "", cmds, http.StatusBadGateway, scrubSecrets(err.Error(), secrets), ""
		}
		if res.Exit != 0 {
			return failRes(res, cmds)
		}
	}

	plansDir := filepath.Join(s.tf.Dir, "plans")
	if err := os.MkdirAll(plansDir, 0o700); err != nil {
		return nil, "", cmds, http.StatusInternalServerError, "Could not create plans directory.", ""
	}
	rawID := make([]byte, 16)
	_, _ = rand.Read(rawID)
	planID := hex.EncodeToString(rawID)
	planPath := filepath.Join(plansDir, prefix+planID+".tfplan")

	planCmd := s.tf.PlanCmd(planPath, flags...)
	cmds = append(cmds, planCmd.Shown())
	res, err := run.Output(planCmd, 5*time.Minute)
	if err != nil {
		_ = os.Remove(planPath)
		return nil, "", cmds, http.StatusBadGateway, scrubSecrets(err.Error(), secrets), ""
	}
	if res.Exit != 0 {
		_ = os.Remove(planPath)
		return failRes(res, cmds)
	}
	_ = os.Chmod(planPath, 0o600)

	showRes, err := run.Output(s.tf.ShowPlanCmd(planPath), 2*time.Minute)
	if err != nil {
		_ = os.Remove(planPath)
		return nil, "", cmds, http.StatusBadGateway, scrubSecrets(err.Error(), secrets), ""
	}
	if showRes.Exit != 0 {
		_ = os.Remove(planPath)
		return failRes(showRes, cmds)
	}
	plan, err := tf.ParsePlan([]byte(showRes.Stdout))
	if err != nil {
		_ = os.Remove(planPath)
		slog.Error("parse terraform plan", "err", err)
		return nil, "", cmds, http.StatusInternalServerError, "Could not parse the Terraform plan.", ""
	}
	plan.ID, plan.Mode, plan.Created = planID, "plan", time.Now()
	return plan, planPath, cmds, 0, "", ""
}

func (s *Server) terraformPlan(w http.ResponseWriter, r *http.Request, me store.User) {
	// Optional body: {"replace": "<machine_name>"} for Rebuild (IM8).
	var req struct {
		Replace string `json:"replace"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if !readJSON(w, r, &req) {
			return
		}
	}
	var flags []string
	if name := strings.TrimSpace(req.Replace); name != "" {
		if err := tf.CheckMachineName(name); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		flags = append(flags, fmt.Sprintf(`-replace=proxmox_virtual_environment_container.machine[%q]`, name))
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

	tf.ClearImport(s.tf.Dir)
	snapshot, err := s.generateTerraform()
	if err != nil {
		serverError(w, "write Terraform files", err)
		return
	}

	plan, planPath, cmds, status, msg, detail := s.runPlan("", flags...)
	if status != 0 {
		writePlanError(w, status, msg, detail, cmds)
		return
	}

	changes := toChangeViews(plan.Changes)
	actions := map[string]string{}
	for _, c := range plan.Changes {
		actions[tf.MachineName(c.Address)] = c.Action
	}
	summary := tf.PlainSummary(plan)

	if len(plan.Changes) == 0 {
		_ = os.Remove(planPath)
		s.clearPendingPlan()
	} else {
		s.setPendingPlan(&savedPlan{ID: plan.ID, File: planPath, Created: plan.Created, Snapshot: snapshot, Summary: summary, Actions: actions})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"plan": plan, "plain_summary": summary, "changes": changes,
		"applicable": len(plan.Changes) > 0, "commands": cmds,
	})
}

type applyOutcome struct {
	Created    []string `json:"created"`
	Updated    []string `json:"updated"`
	Replaced   []string `json:"replaced"`
	Destroyed  []string `json:"destroyed"`
	HostsAdded []string `json:"hosts_added"`
	Configured []string `json:"configured"`
	Warnings   []string `json:"warnings"`
	Error      string   `json:"error,omitempty"`
}

func (s *Server) terraformApply(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		PlanID string `json:"plan_id"`
	}
	if !readJSON(w, r, &req) {
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

	planID := strings.TrimSpace(req.PlanID)
	adoptCandidate := s.pendingAdoptFor(planID)
	snap, err := s.generateTerraformWith(adoptCandidate)
	if err != nil {
		serverError(w, "write Terraform files", err)
		return
	}
	plan, refusal := s.takePendingPlan(planID, snap)
	if refusal != "" {
		s.failHost(w, r, me, "terraform.apply", "terraform", http.StatusConflict, refusal)
		return
	}
	defer os.Remove(plan.File)
	if plan.Adopt != nil {
		defer tf.ClearImport(s.tf.Dir)
	}

	// State backup before every apply, kept 30 deep (IM8).
	if _, berr := tf.BackupState(s.tf.Dir, time.Now()); berr != nil {
		slog.Error("backup terraform state", "err", berr)
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "Streaming is not supported here.")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	out := &sseWriter{w: w, flusher: flusher}

	secrets := s.streamSecrets()
	var logBuf bytes.Buffer
	sw := newScrubWriter(io.MultiWriter(out, &logBuf), secrets...)
	exit, err := run.Stream(s.tf.ApplyCmd(plan.File), sw, run.DefaultStreamTimeout)
	_ = sw.Flush()
	if err != nil || exit != 0 {
		msg := ""
		if err != nil {
			msg = scrubSecrets(err.Error(), secrets)
		} else {
			msg = firstNonEmpty(tf.Explain(scrubSecrets(logBuf.String(), secrets)), fmt.Sprintf("Terraform apply failed (exit %d).", exit))
		}
		if plan.Adopt != nil {
			tf.ClearImport(s.tf.Dir)
			_, _ = s.generateTerraform()
		}
		s.record(r, me, "terraform.apply", "terraform", store.ResultFailed, firstLine(msg))
		out.result(applyOutcome{Error: msg})
		out.finish(errors.New(msg))
		return
	}

	stateMap := map[string]tf.StateMachine{}
	if showRes, serr := run.Output(s.tf.ShowStateCmd(), 2*time.Minute); serr == nil && showRes.Exit == 0 {
		if parsed, perr := tf.ParseState([]byte(showRes.Stdout)); perr == nil {
			stateMap = parsed
		}
	}

	if plan.Adopt != nil {
		tf.ClearImport(s.tf.Dir)
		outcome := s.finishAdopt(r, me, *plan.Adopt, stateMap, out)
		_, _ = s.generateTerraform()
		out.result(outcome)
		out.finish(nil)
		return
	}

	outcome := s.reconcileAfterApply(r, me, plan, stateMap, out)
	s.setLastDrift(nil) // apply reconciled Terraform state with desired config
	s.record(r, me, "terraform.apply", "terraform", store.ResultOK, plan.Summary)
	out.result(outcome)
	out.finish(nil)
}

func (s *Server) reconcileAfterApply(r *http.Request, me store.User, plan *savedPlan, stateMap map[string]tf.StateMachine, out *sseWriter) applyOutcome {
	res := applyOutcome{
		Created: []string{}, Updated: []string{}, Replaced: []string{}, Destroyed: []string{},
		HostsAdded: []string{}, Configured: []string{}, Warnings: []string{},
	}
	machines, err := store.ListMachines(s.db)
	if err != nil {
		res.Warnings = append(res.Warnings, "Could not read machines after apply.")
		return res
	}
	client, _, _ := s.proxmoxClient()
	now := time.Now()

	for _, m := range machines {
		sm, inState := stateMap[m.Name]
		if m.PendingDelete && !inState {
			if m.HostID > 0 {
				if h, err := store.GetHost(s.db, m.HostID); err == nil {
					_ = s.remote.Forget(targetOf(h))
					if err := store.DeleteHost(s.db, h.ID); err != nil {
						res.Warnings = append(res.Warnings, "Could not remove host "+h.Name+": "+err.Error())
					} else {
						_, _ = fmt.Fprintf(out, "\nRemoved host %s from the dashboard.\n", h.Name)
					}
				}
			}
			_ = store.DeleteMachine(s.db, m.ID)
			res.Destroyed = append(res.Destroyed, m.Name)
			continue
		}
		if !inState {
			continue
		}

		switch plan.Actions[m.Name] {
		case "create":
			res.Created = append(res.Created, m.Name)
		case "update":
			res.Updated = append(res.Updated, m.Name)
		case "replace":
			res.Replaced = append(res.Replaced, m.Name)
		}

		ip := s.resolveMachineIP(m, sm, client, out)
		if err := store.MarkMachineApplied(s.db, m.ID, sm.VMID, ip, m.SizeSpec(), now); err != nil {
			slog.Error("mark machine applied", "machine", m.Name, "err", err)
			continue
		}
		m.VMID, m.IPResolved = sm.VMID, ip

		if m.HostID == 0 {
			if ip == "" {
				res.Warnings = append(res.Warnings, m.Name+" was created, but no IP could be read from Proxmox yet.")
				continue
			}
			host, warn := s.enrollMachineHost(m, ip, out)
			if warn != "" {
				res.Warnings = append(res.Warnings, warn)
			}
			if host.ID > 0 {
				res.HostsAdded = append(res.HostsAdded, host.Name)
				if m.AutoConfigure && host.Status == remote.StatusOnline {
					if ok, cw := s.autoConfigureHost(r, me, host, out); ok {
						res.Configured = append(res.Configured, host.Name)
					} else if cw != "" {
						res.Warnings = append(res.Warnings, cw)
					}
				}
			}
		} else if plan.Actions[m.Name] == "replace" {
			// Rebuild (IM8): the dashboard made this container itself, so trust
			// the new SSH host key automatically (audited) and re-apply its profile.
			if h, err := store.GetHost(s.db, m.HostID); err == nil {
				oldFP := h.HostKeyFP
				t := s.targetForMachine(m, firstNonEmpty(ip, h.Address))
				_, _ = fmt.Fprintf(out, "\nWaiting for SSH on rebuilt %s (%s:%d)…\n", h.Name, t.Address, t.Port)
				if er, eerr := s.waitEnrollSSH(t); eerr == nil {
					h.Address, h.HostKeyFP = t.Address, er.HostKeyFP
					_ = store.UpdateHostConnection(s.db, h)
					if fj, err := json.Marshal(er.Facts); err == nil {
						_ = store.SetHostFacts(s.db, h.ID, string(fj), er.SudoOK || t.User == "root", time.Now())
					}
					if hj, err := mergeHealth(er.Health, "", time.Now()); err == nil {
						_ = store.SetHostHealth(s.db, h.ID, hj, time.Now())
					}
					h.Status = remote.StatusOnline
					s.record(r, me, "host.trust_key", "host "+h.Name, store.ResultOK,
						fmt.Sprintf("trusted automatically after rebuilding machine %s (%s → %s)", m.Name, oldFP, er.HostKeyFP))
					_, _ = fmt.Fprintf(out, "Trusted new SSH host key for %s.\n", h.Name)
					if ok, cw := s.autoConfigureHost(r, me, h, out); ok {
						res.Configured = append(res.Configured, h.Name)
					} else if cw != "" {
						res.Warnings = append(res.Warnings, cw)
					}
				} else {
					res.Warnings = append(res.Warnings, m.Name+" was rebuilt, but SSH did not answer yet: "+remote.Classify(eerr).Message)
				}
			}
		}
	}
	return res
}

func (s *Server) resolveMachineIP(m store.Machine, sm tf.StateMachine, client *tf.ProxmoxClient, out *sseWriter) string {
	if ip := firstNonEmpty(m.StaticIP(), sm.IPv4); ip != "" {
		return ip
	}
	if client == nil || sm.VMID == 0 {
		return m.IPResolved
	}
	_, _ = fmt.Fprintf(out, "\nWaiting for %s to get a DHCP address…\n", m.Name)
	deadline := time.Now().Add(s.provision.dhcpWait)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := client.ContainerInterfaces(ctx, m.Node, sm.VMID)
		cancel()
		if err == nil && len(ips) > 0 {
			return ips[0]
		}
		if time.Now().After(deadline) {
			return m.IPResolved
		}
		time.Sleep(s.provision.dhcpPoll)
	}
}

func (s *Server) targetForMachine(m store.Machine, ip string) remote.Target {
	if s.hostTarget != nil {
		return s.hostTarget(m, ip)
	}
	return remote.Target{Address: ip, Port: 22, User: "root"}
}

func (s *Server) waitEnrollSSH(t remote.Target) (remote.EnrollResult, error) {
	deadline := time.Now().Add(s.provision.sshWait)
	for {
		_ = s.remote.Forget(t)
		res, err := s.remote.Enroll(remote.EnrollRequest{Target: t}, true)
		if err == nil || time.Now().After(deadline) {
			return res, err
		}
		time.Sleep(s.provision.sshPoll)
	}
}

func (s *Server) enrollMachineHost(m store.Machine, ip string, out *sseWriter) (store.Host, string) {
	t := s.targetForMachine(m, ip)
	_, _ = fmt.Fprintf(out, "\nWaiting for SSH on %s (%s:%d)…\n", m.Name, t.Address, t.Port)
	now := time.Now()

	res, err := s.waitEnrollSSH(t)
	var host store.Host
	var warn string
	if err != nil {
		p := remote.Classify(err)
		warn = fmt.Sprintf("%s was created, but SSH did not answer yet (%s). It was added as a host anyway.", m.Name, p.Message)
		host, err = store.CreateHost(s.db, store.Host{
			Name: m.Name, Address: t.Address, Port: t.Port, User: t.User,
			SudoOK: true, Status: p.Status, StatusDetail: p.Message, StatusAt: now.Unix(),
		}, now)
	} else {
		factsJSON, _ := json.Marshal(res.Facts)
		healthJSON, _ := mergeHealth(res.Health, "", now)
		host, err = store.CreateHost(s.db, store.Host{
			Name: m.Name, Address: t.Address, Port: t.Port, User: t.User,
			SudoOK: res.SudoOK || t.User == "root", Status: remote.StatusOnline, StatusAt: now.Unix(),
			HostKeyFP: res.HostKeyFP, FactsJSON: string(factsJSON), FactsAt: now.Unix(),
			HealthJSON: healthJSON, HealthAt: now.Unix(), LastSeen: now.Unix(),
		}, now)
	}
	if err != nil {
		return store.Host{}, fmt.Sprintf("Could not add %s as a host: %s", m.Name, err.Error())
	}
	_ = store.SetMachineHost(s.db, m.ID, host.ID, t.Address)
	for _, gid := range m.GroupIDs {
		_ = store.ChangeGroupHosts(s.db, gid, []int64{host.ID}, nil)
	}
	_, _ = fmt.Fprintf(out, "Added %s (%s) as a host.\n", host.Name, host.Address)
	return host, warn
}

func (s *Server) autoConfigureHost(r *http.Request, me store.User, host store.Host, out *sseWriter) (bool, string) {
	ts, rerr := s.targets(0, host.ID, "", true)
	if rerr != nil {
		return false, fmt.Sprintf("Could not configure %s: %s", host.Name, rerr.msg)
	}
	if len(ts.Hosts) == 0 {
		return false, ""
	}
	if s.ansibleVersion() == "" {
		return false, host.Name + " was added as a host, but Ansible is not installed."
	}
	if _, err := exec.LookPath(s.ansible.PlaybookBin); err != nil {
		return false, host.Name + " was added as a host, but ansible-playbook is not installed."
	}

	s.ansibleMu.Lock()
	defer s.ansibleMu.Unlock()
	ts.Playbook, ts.ActionPrefix = "site.yml", "config"
	if err := s.generateWith(genOptions{Overrides: ts.Overrides}); err != nil {
		return false, fmt.Sprintf("Could not write Ansible files for %s: %v", host.Name, err)
	}
	cmd, err := s.ansible.PlaybookRun("site.yml", []string{host.Name}, "", false)
	if err != nil {
		return false, err.Error()
	}

	_, _ = fmt.Fprintf(out, "\nConfiguring %s (%s)…\n", host.Name, strings.Join(ts.Roles[host.Name], ", "))
	secrets := s.streamSecrets()
	var ansibleLog bytes.Buffer
	sw := newScrubWriter(io.MultiWriter(out, &ansibleLog), secrets...)
	exit, err := run.Stream(cmd, sw, run.DefaultStreamTimeout)
	_ = sw.Flush()
	if err != nil {
		msg := scrubSecrets(err.Error(), secrets)
		s.record(r, me, "config.apply", "host "+host.Name, store.ResultFailed, msg)
		return false, fmt.Sprintf("Configuring %s failed: %s", host.Name, msg)
	}
	s.recordRun(r, me, ts, ansible.ParsePlaybook(ansibleLog.String()), "apply", "config.apply")
	if exit != 0 {
		return false, "Configuring " + host.Name + " finished with errors."
	}
	return true, ""
}
