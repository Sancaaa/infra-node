package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"infra-manager/internal/ansible"
	"infra-manager/internal/run"
	"infra-manager/internal/store"
)

// Compliance checks and the background scheduler (IM9).
//
// Compliance runs `ansible-playbook site.yml --check --diff` against every host
// whose profile has been applied. Any host where a file or setting would change
// is marked "drifted" with the exact diff until Fix (normal Apply) makes it
// match again. Results stay in memory like Proxmox drift (OD-04, OD-15).

const defaultComplianceTime = "03:00"

type hostDrift struct {
	HostID   int64    `json:"host_id"`
	HostName string   `json:"host_name"`
	Changes  []change `json:"changes"`
}

type complianceReport struct {
	CheckedAt int64       `json:"checked_at"`
	Checked   int         `json:"checked"`
	Drifted   []hostDrift `json:"drifted"`
	Errors    []string    `json:"errors,omitempty"`
}

type scheduleJob struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Cadence string `json:"cadence"`
	Enabled bool   `json:"enabled"`
	LastRun int64  `json:"last_run,omitempty"`
	NextRun int64  `json:"next_run,omitempty"`
	Running bool   `json:"running"`
	Status  string `json:"status,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type scheduleView struct {
	Jobs              []scheduleJob `json:"jobs"`
	ComplianceTime    string        `json:"compliance_time"`
	ComplianceEnabled bool          `json:"compliance_enabled"`
	Timezone          string        `json:"timezone"`
}

func defaultSchedJobs() map[string]*scheduleJob {
	return map[string]*scheduleJob{
		"health":     {ID: "health", Label: "Host health check", Cadence: "Every minute", Enabled: true},
		"drift":      {ID: "drift", Label: "Proxmox drift check", Cadence: "Every 15 minutes", Enabled: true},
		"compliance": {ID: "compliance", Label: "Profile compliance check", Cadence: "Nightly at " + defaultComplianceTime, Enabled: true},
	}
}

func checkHHMM(raw string) (int, int, error) {
	s := strings.TrimSpace(raw)
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, fmt.Errorf("Use 24-hour HH:MM format (for example 03:00).")
	}
	h, err1 := strconv.Atoi(s[:2])
	m, err2 := strconv.Atoi(s[3:])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("Use 24-hour HH:MM format between 00:00 and 23:59.")
	}
	return h, m, nil
}

// nextDailyRun returns the next local occurrence of hhmm strictly after now.
func nextDailyRun(now time.Time, hhmm string) time.Time {
	h, m, err := checkHHMM(hhmm)
	if err != nil {
		h, m = 3, 0
	}
	t := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if !t.After(now) {
		t = time.Date(now.Year(), now.Month(), now.Day()+1, h, m, 0, 0, now.Location())
	}
	return t
}

func (s *Server) loadScheduleSettings() (hhmm string, enabled bool, err error) {
	vals, err := store.GetSettings(s.db, "schedule.")
	if err != nil {
		return defaultComplianceTime, true, err
	}
	hhmm = vals["schedule.compliance_time"]
	if _, _, cerr := checkHHMM(hhmm); cerr != nil {
		hhmm = defaultComplianceTime
	}
	enabled = vals["schedule.compliance_enabled"] != "false"
	return hhmm, enabled, nil
}

func (s *Server) markJobStart(id string) {
	s.schedMu.Lock()
	defer s.schedMu.Unlock()
	if j := s.schedJobs[id]; j != nil {
		j.Running = true
	}
}

func (s *Server) markJobDone(id, status, detail string, next time.Time) {
	s.schedMu.Lock()
	defer s.schedMu.Unlock()
	if j := s.schedJobs[id]; j != nil {
		j.Running = false
		if status != "" {
			j.LastRun = time.Now().Unix()
			j.Status = status
			j.Detail = detail
		}
		if !next.IsZero() {
			j.NextRun = next.Unix()
		}
	}
}

// recordJobOutcome records the result of a run without changing NextRun (used
// when an operator triggers Drift or Compliance manually).
func (s *Server) recordJobOutcome(id, status, detail string) {
	s.schedMu.Lock()
	defer s.schedMu.Unlock()
	if j := s.schedJobs[id]; j != nil {
		j.Running = false
		j.LastRun = time.Now().Unix()
		j.Status = status
		j.Detail = detail
	}
}

func (s *Server) setJobNext(id string, next time.Time, cadence string, enabled bool) {
	s.schedMu.Lock()
	defer s.schedMu.Unlock()
	if j := s.schedJobs[id]; j != nil {
		j.Enabled = enabled
		if cadence != "" {
			j.Cadence = cadence
		}
		if enabled && !next.IsZero() {
			j.NextRun = next.Unix()
		} else if !enabled {
			j.NextRun = 0
		}
	}
}

func (s *Server) scheduleSnapshot() scheduleView {
	hhmm, enabled, _ := s.loadScheduleSettings()
	now := time.Now()
	tz, _ := now.Zone()

	s.schedMu.Lock()
	defer s.schedMu.Unlock()
	if c := s.schedJobs["compliance"]; c != nil {
		c.Enabled = enabled
		c.Cadence = "Nightly at " + hhmm
		if enabled && c.NextRun == 0 {
			c.NextRun = nextDailyRun(now, hhmm).Unix()
		}
		if !enabled {
			c.NextRun = 0
		}
	}
	order := []string{"health", "drift", "compliance"}
	jobs := make([]scheduleJob, 0, len(order))
	for _, id := range order {
		if j := s.schedJobs[id]; j != nil {
			jobs = append(jobs, *j)
		}
	}
	return scheduleView{
		Jobs:              jobs,
		ComplianceTime:    hhmm,
		ComplianceEnabled: enabled,
		Timezone:          tz,
	}
}

// ------------------------------------------------------- compliance results

func (s *Server) setLastCompliance(rep *complianceReport) {
	s.compMu.Lock()
	defer s.compMu.Unlock()
	s.lastCompliance = rep
}

func (s *Server) hostComplianceDrift(hostID int64) []change {
	s.compMu.Lock()
	defer s.compMu.Unlock()
	if s.lastCompliance == nil {
		return nil
	}
	for _, d := range s.lastCompliance.Drifted {
		if d.HostID == hostID {
			return append([]change{}, d.Changes...)
		}
	}
	return nil
}

func (s *Server) clearHostCompliance(hostID int64) {
	s.compMu.Lock()
	defer s.compMu.Unlock()
	if s.lastCompliance == nil {
		return
	}
	rest := make([]hostDrift, 0, len(s.lastCompliance.Drifted))
	for _, d := range s.lastCompliance.Drifted {
		if d.HostID != hostID {
			rest = append(rest, d)
		}
	}
	s.lastCompliance.Drifted = rest
}

// ---------------------------------------------------------- running the check

// runComplianceCheck runs `ansible-playbook site.yml --check --diff` against
// every host whose profile has been applied.
func (s *Server) runComplianceCheck() (complianceReport, []run.Shown, int, string, string) {
	if s.ansibleVersion() == "" {
		return complianceReport{}, nil, http.StatusServiceUnavailable, ansible.InstallHint, ""
	}
	if _, err := exec.LookPath(s.ansible.PlaybookBin); err != nil {
		return complianceReport{}, nil, http.StatusServiceUnavailable, ansible.InstallHint, ""
	}
	if !s.ansibleMu.TryLock() {
		return complianceReport{}, nil, http.StatusConflict, "Another Ansible run is going. Wait for it to finish.", ""
	}
	defer s.ansibleMu.Unlock()

	hosts, err := store.ListHosts(s.db)
	if err != nil {
		return complianceReport{}, nil, http.StatusInternalServerError, "Could not list hosts.", ""
	}
	views, ps, err := s.configViews()
	if err != nil {
		return complianceReport{}, nil, http.StatusInternalServerError, "Could not work out host profiles.", ""
	}

	s.mu.Lock()
	rebooting := map[int64]bool{}
	for id, v := range s.rebooting {
		rebooting[id] = v
	}
	s.mu.Unlock()

	var targets []store.Host
	overrides := map[string]ansible.HostPlan{}
	for _, h := range hosts {
		cv := views[h.ID]
		if (cv.State != configApplied && cv.State != configDrifted) || !canRoot(h) || rebooting[h.ID] {
			continue
		}
		plan := ps.plans[h.ID]
		effective := plan
		if plan.Has("ssh_hardening") && s.sshHardeningBlocked(h, plan, false) != "" {
			effective = plan.Without("ssh_hardening")
		}
		if len(effective.Roles) == 0 {
			continue
		}
		targets = append(targets, h)
		overrides[h.Name] = effective
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })

	now := time.Now().Unix()
	if len(targets) == 0 {
		rep := complianceReport{CheckedAt: now, Checked: 0, Drifted: []hostDrift{}}
		s.setLastCompliance(&rep)
		s.recordJobOutcome("compliance", "ok", "no applied hosts to check")
		return rep, nil, 0, "", ""
	}

	if err := s.generateWith(genOptions{Overrides: overrides}); err != nil {
		s.recordJobOutcome("compliance", "failed", "could not write Ansible files")
		return complianceReport{}, nil, http.StatusInternalServerError, "Could not write the Ansible files.", ""
	}
	names := make([]string, len(targets))
	for i, h := range targets {
		names[i] = h.Name
	}
	cmd, err := s.ansible.PlaybookRun("site.yml", names, "", true)
	if err != nil {
		return complianceReport{}, nil, http.StatusBadRequest, err.Error(), ""
	}
	cmds := []run.Shown{cmd.Shown()}

	s.markJobStart("compliance")
	res, err := run.Output(cmd, 15*time.Minute)
	if err != nil {
		s.recordJobOutcome("compliance", "failed", err.Error())
		return complianceReport{}, cmds, http.StatusBadGateway, err.Error(), ""
	}
	parsed := ansible.ParsePlaybook(res.Stdout)
	if len(parsed.Recap) == 0 && res.Exit != 0 {
		raw := strings.TrimSpace(res.Stderr + "\n" + res.Stdout)
		msg := firstNonEmpty(ansible.Explain(raw), firstLine(raw), fmt.Sprintf("Ansible failed (exit %d).", res.Exit))
		s.recordJobOutcome("compliance", "failed", firstLine(msg))
		return complianceReport{}, cmds, http.StatusBadGateway, msg, raw
	}

	rep := complianceReport{CheckedAt: now, Checked: len(targets), Drifted: []hostDrift{}}
	for _, h := range targets {
		changes, errs, down := tasksOf(parsed, h.Name)
		switch {
		case down != "":
			rep.Errors = append(rep.Errors, h.Name+": "+ansibleSentence(down))
		case len(errs) > 0:
			rep.Errors = append(rep.Errors, h.Name+": "+errs[0].Task+": "+ansibleSentence(errs[0].Message))
		case len(changes) > 0:
			rep.Drifted = append(rep.Drifted, hostDrift{HostID: h.ID, HostName: h.Name, Changes: changes})
		}
	}
	s.setLastCompliance(&rep)

	detail := complianceSummary(rep)
	status := "ok"
	if len(rep.Errors) > 0 && len(rep.Drifted) == 0 {
		status = "failed"
	}
	s.recordJobOutcome("compliance", status, detail)
	return rep, cmds, 0, "", ""
}

func complianceSummary(rep complianceReport) string {
	if rep.Checked == 0 {
		return "no applied hosts"
	}
	if len(rep.Drifted) == 0 && len(rep.Errors) == 0 {
		return fmt.Sprintf("%s compliant", plural(rep.Checked, "host"))
	}
	var parts []string
	if len(rep.Drifted) > 0 {
		names := make([]string, len(rep.Drifted))
		for i, d := range rep.Drifted {
			names[i] = d.HostName
		}
		parts = append(parts, fmt.Sprintf("%d drifted (%s)", len(rep.Drifted), strings.Join(names, ", ")))
	}
	if len(rep.Errors) > 0 {
		parts = append(parts, fmt.Sprintf("%d failed to check", len(rep.Errors)))
	}
	return strings.Join(parts, "; ")
}

// complianceRound is the scheduled nightly check called from RunMonitor.
func (s *Server) complianceRound() {
	rep, _, status, msg, _ := s.runComplianceCheck()
	if status == http.StatusServiceUnavailable || status == http.StatusConflict {
		return
	}
	if status != 0 {
		slog.Warn("scheduled compliance check failed", "msg", msg)
		_ = store.AddEvent(s.db, store.Event{
			Username: "scheduler", Action: "compliance.check", Target: "all hosts",
			Result: store.ResultFailed, Detail: firstLine(msg),
		})
		return
	}
	if rep.Checked > 0 {
		_ = store.AddEvent(s.db, store.Event{
			Username: "scheduler", Action: "compliance.check", Target: "all hosts",
			Result: store.ResultOK, Detail: complianceSummary(rep),
		})
	}
}

// ------------------------------------------------------------------ HTTP API

func (s *Server) checkCompliance(w http.ResponseWriter, r *http.Request, me store.User) {
	rep, cmds, status, msg, detail := s.runComplianceCheck()
	if status != 0 {
		if status == http.StatusServiceUnavailable {
			writeJSON(w, status, map[string]any{"error": msg, "missing": true})
			return
		}
		if status != http.StatusConflict {
			s.record(r, me, "compliance.check", "all hosts", store.ResultFailed, firstLine(msg))
		}
		writePlanError(w, status, msg, detail, cmds)
		return
	}
	s.record(r, me, "compliance.check", "all hosts", store.ResultOK, complianceSummary(rep))
	writeJSON(w, http.StatusOK, map[string]any{"compliance": rep, "commands": cmds})
}

func (s *Server) getSchedule(w http.ResponseWriter, r *http.Request, me store.User) {
	writeJSON(w, http.StatusOK, s.scheduleSnapshot())
}

func (s *Server) saveSchedule(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		ComplianceTime    string `json:"compliance_time"`
		ComplianceEnabled *bool  `json:"compliance_enabled"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	hhmm := strings.TrimSpace(req.ComplianceTime)
	if _, _, err := checkHHMM(hhmm); err != nil {
		s.failHost(w, r, me, "schedule.update", "compliance", http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if req.ComplianceEnabled != nil {
		enabled = *req.ComplianceEnabled
	}
	if err := store.SetSetting(s.db, "schedule.compliance_time", hhmm); err != nil {
		serverError(w, "save compliance time", err)
		return
	}
	enVal := "true"
	if !enabled {
		enVal = "false"
	}
	if err := store.SetSetting(s.db, "schedule.compliance_enabled", enVal); err != nil {
		serverError(w, "save compliance enabled", err)
		return
	}

	next := time.Time{}
	detail := "nightly compliance check off"
	if enabled {
		next = nextDailyRun(time.Now(), hhmm)
		detail = "nightly compliance check at " + hhmm
	}
	s.setJobNext("compliance", next, "Nightly at "+hhmm, enabled)
	select {
	case s.schedWake <- struct{}{}:
	default:
	}

	s.record(r, me, "schedule.update", "compliance", store.ResultOK, detail)
	writeJSON(w, http.StatusOK, s.scheduleSnapshot())
}
