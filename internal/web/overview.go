package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"infra-manager/internal/remote"
	"infra-manager/internal/store"
	"infra-manager/internal/tf"
)

// overviewAnswer is the full Overview (IM9): health, configuration state,
// profile drift, Proxmox drift, pending updates/reboots, the scheduler, recent
// runs and one "Next step" card. It makes no network calls of its own.
type overviewAnswer struct {
	Hosts             int              `json:"hosts"`
	Online            int              `json:"online"`
	WithFailed        int              `json:"with_failed_services"`
	WithUpdates       int              `json:"with_updates"`
	NeedReboot        int              `json:"need_reboot"`
	ConfigFailed      int              `json:"config_failed"`
	ConfigWaiting     int              `json:"config_waiting"`
	ConfigDrifted     int              `json:"config_drifted"`
	Machines          int              `json:"machines"`
	MachinesPending   int              `json:"machines_pending"`
	MachinesDrifted   int              `json:"machines_drifted"`
	ProxmoxConfigured bool             `json:"proxmox_configured"`
	Attention         []attention      `json:"attention"`
	ProfileDrift      []hostDrift      `json:"profile_drift"`
	MachineDrift      []tf.DriftDetail `json:"machine_drift"`
	LastRuns          []store.Event    `json:"last_runs"`
	Schedule          scheduleView     `json:"schedule"`
	NextStep          nextStep         `json:"next_step"`
}

// attention is a host with something to look at, and what it is.
type attention struct {
	ID     int64    `json:"id"`
	Name   string   `json:"name"`
	Status string   `json:"status"`
	Issues []string `json:"issues"`
}

// nextStep is the single most important thing to do right now (OD-04, IM9).
type nextStep struct {
	Title   string   `json:"title"`
	Body    string   `json:"body"`
	Details []string `json:"details,omitempty"`
	Action  string   `json:"action,omitempty"`
	Page    string   `json:"page,omitempty"`
	FixHost int64    `json:"fix_host,omitempty"`
	Good    bool     `json:"good,omitempty"`
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request, me store.User) {
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		serverError(w, "list hosts", err)
		return
	}
	configs, _, err := s.configViews()
	if err != nil {
		serverError(w, "work out the configuration states", err)
		return
	}
	machines, err := store.ListMachines(s.db)
	if err != nil {
		serverError(w, "list machines", err)
		return
	}
	px, _ := s.loadProxmoxSettings()

	o := summarize(hosts, configs)
	o.Machines = len(machines)
	o.ProxmoxConfigured = px.Configured
	for _, m := range machines {
		if m.AppliedAt == 0 || m.PendingDelete || m.SizeSpec() != m.AppliedSpec {
			o.MachinesPending++
		}
	}

	// Profile drift (only for hosts currently in configDrifted state).
	o.ProfileDrift = []hostDrift{}
	for _, h := range hosts {
		if cv := configs[h.ID]; cv.State == configDrifted && len(cv.Drift) > 0 {
			o.ProfileDrift = append(o.ProfileDrift, hostDrift{
				HostID: h.ID, HostName: h.Name, Changes: cv.Drift,
			})
		}
	}

	// Proxmox drift from the last refresh-only check.
	o.MachineDrift = []tf.DriftDetail{}
	if d := s.getLastDrift(); d != nil && len(d.Items) > 0 {
		o.MachineDrift = d.Items
		o.MachinesDrifted = len(d.Items)
	}

	o.LastRuns = s.recentRuns(8)
	o.Schedule = s.scheduleSnapshot()
	o.NextStep = pickNextStep(o, hosts, configs)

	writeJSON(w, http.StatusOK, o)
}

// summarize counts what is wrong. A host that is not online is counted only as
// not online: what it had wrong when it was last seen is old news, and listing
// it twice would make the numbers add up to more than the hosts. The state of a
// host's configuration is not about the host being up, so it is counted for
// every host.
func summarize(hosts []store.Host, configs map[int64]configView) overviewAnswer {
	out := overviewAnswer{
		Hosts:        len(hosts),
		Attention:    []attention{},
		ProfileDrift: []hostDrift{},
		MachineDrift: []tf.DriftDetail{},
		LastRuns:     []store.Event{},
	}
	for _, h := range hosts {
		a := attention{ID: h.ID, Name: h.Name, Status: h.Status, Issues: []string{}}

		switch cv := configs[h.ID]; cv.State {
		case configFailed:
			out.ConfigFailed++
			a.Issues = append(a.Issues, "configuration failed: "+cv.Detail)
		case configInvalid:
			out.ConfigFailed++
			a.Issues = append(a.Issues, "its profile is not valid: "+cv.Detail)
		case configDrifted:
			out.ConfigDrifted++
			a.Issues = append(a.Issues, "drifted from its profile")
		case configWaiting:
			out.ConfigWaiting++
			a.Issues = append(a.Issues, "profile changes waiting to be applied")
		}

		if h.Status != remote.StatusOnline {
			a.Issues = append(a.Issues, statusIssue(h))
		} else {
			out.Online++
			var health remote.Health
			if h.HealthJSON != "" && json.Unmarshal([]byte(h.HealthJSON), &health) == nil {
				if n := len(health.Failed); n > 0 {
					out.WithFailed++
					a.Issues = append(a.Issues, plural(n, "failed service")+": "+failedNames(health.Failed))
				}
				if health.Updates > 0 {
					out.WithUpdates++
					a.Issues = append(a.Issues, plural(health.Updates, "update")+" waiting")
				}
				if health.Reboot {
					out.NeedReboot++
					a.Issues = append(a.Issues, "needs a reboot")
				}
			}
			if !h.SudoOK && h.User != "root" {
				a.Issues = append(a.Issues, "no sudo: it cannot be configured")
			}
		}
		if len(a.Issues) > 0 {
			out.Attention = append(out.Attention, a)
		}
	}

	// Hosts that are down first: they are the ones that cannot wait.
	sort.SliceStable(out.Attention, func(i, j int) bool {
		return (out.Attention[i].Status != remote.StatusOnline) && (out.Attention[j].Status == remote.StatusOnline)
	})
	return out
}

// pickNextStep chooses the single most important next action in strict priority
// order, as in OD-04's redesign: security alerts first, then unreachable hosts,
// broken config, both kinds of drift, pending changes, services, reboots,
// updates, and finally "all good".
func pickNextStep(o overviewAnswer, hosts []store.Host, configs map[int64]configView) nextStep {
	if o.Hosts == 0 && o.Machines == 0 {
		return nextStep{
			Title:  "Add your first host or machine",
			Body:   "Add an existing Linux host with its SSH login, or configure Proxmox in Settings to create containers.",
			Action: "Go to Hosts",
			Page:   "hosts",
		}
	}

	var keyChanged, down, neverApplied []string
	for _, h := range hosts {
		switch h.Status {
		case remote.StatusKeyChanged:
			keyChanged = append(keyChanged, h.Name)
		case remote.StatusOffline, remote.StatusAuthFailed:
			down = append(down, h.Name)
		}
		if configs[h.ID].State == configNever {
			neverApplied = append(neverApplied, h.Name)
		}
	}

	if len(keyChanged) > 0 {
		return nextStep{
			Title:   plural(len(keyChanged), "host") + " showed a different SSH key",
			Body:    "Connections are refused until an admin checks the fingerprint and trusts the new key.",
			Details: keyChanged,
			Action:  "Review on Hosts",
			Page:    "hosts",
		}
	}
	if len(down) > 0 {
		return nextStep{
			Title:   plural(len(down), "host") + " cannot be reached",
			Body:    "Check whether the host is powered on, reachable on the network, or still accepts the dashboard's SSH key.",
			Details: down,
			Action:  "Go to Hosts",
			Page:    "hosts",
		}
	}
	if o.ConfigFailed > 0 {
		return nextStep{
			Title:  plural(o.ConfigFailed, "host") + " failed configuration",
			Body:   "Inspect the error on Hosts, fix the profile or host issue, and apply again.",
			Action: "Go to Hosts",
			Page:   "hosts",
		}
	}
	if o.ConfigDrifted > 0 {
		step := nextStep{
			Title: plural(o.ConfigDrifted, "host") + " drifted from its profile",
			Body:  "Files or settings were changed outside the dashboard. Review the diff below and apply the profile to restore it.",
		}
		for _, d := range o.ProfileDrift {
			step.Details = append(step.Details, d.HostName+": "+plural(len(d.Changes), "change"))
		}
		if len(o.ProfileDrift) == 1 {
			step.Action = "Fix " + o.ProfileDrift[0].HostName
			step.FixHost = o.ProfileDrift[0].HostID
		} else {
			step.Action = "Go to Hosts"
			step.Page = "hosts"
		}
		return step
	}
	if o.MachinesDrifted > 0 {
		var details []string
		for _, d := range o.MachineDrift {
			details = append(details, d.Sentence)
		}
		return nextStep{
			Title:   plural(o.MachinesDrifted, "Proxmox container") + " drifted outside the dashboard",
			Body:    "Review the changes on Machines and choose Put it back or Accept.",
			Details: details,
			Action:  "Go to Machines",
			Page:    "machines",
		}
	}
	if o.MachinesPending > 0 {
		return nextStep{
			Title:  plural(o.MachinesPending, "machine change") + " waiting for review",
			Body:   "Run Review changes on Machines to preview the Terraform plan before applying.",
			Action: "Review on Machines",
			Page:   "machines",
		}
	}
	if o.ConfigWaiting > 0 || len(neverApplied) > 0 {
		n := o.ConfigWaiting + len(neverApplied)
		return nextStep{
			Title:  plural(n, "host") + " waiting to be configured",
			Body:   "Preview and apply their profiles from Hosts or Groups.",
			Action: "Go to Hosts",
			Page:   "hosts",
		}
	}
	if o.WithFailed > 0 {
		return nextStep{
			Title:  plural(o.WithFailed, "host") + " have failed services",
			Body:   "Open Details or Service logs on Hosts to inspect and restart the failed units.",
			Action: "Go to Hosts",
			Page:   "hosts",
		}
	}
	if o.NeedReboot > 0 {
		return nextStep{
			Title:  plural(o.NeedReboot, "host") + " need a reboot",
			Body:   "Reboot them from Hosts or Reboot one by one from a group.",
			Action: "Go to Hosts",
			Page:   "hosts",
		}
	}
	if o.WithUpdates > 0 {
		return nextStep{
			Title:  plural(o.WithUpdates, "host") + " have package updates waiting",
			Body:   "Run Update packages on a group or host to apply updates rolling.",
			Action: "Go to Hosts",
			Page:   "hosts",
		}
	}
	return nextStep{
		Title: "Everything looks good",
		Body:  "All hosts are online, match their profiles, and are in sync with Proxmox.",
		Good:  true,
	}
}

func isRunAction(action string) bool {
	for _, prefix := range []string{
		"config.", "patch.", "access.", "playbook.",
		"terraform.", "machine.", "compliance.", "host.reboot",
	} {
		if strings.HasPrefix(action, prefix) {
			return true
		}
	}
	return false
}

func (s *Server) recentRuns(limit int) []store.Event {
	events, err := store.ListEvents(s.db, 0, 60)
	if err != nil {
		return []store.Event{}
	}
	out := make([]store.Event, 0, limit)
	for _, ev := range events {
		if isRunAction(ev.Action) {
			out = append(out, ev)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

func statusIssue(h store.Host) string {
	switch h.Status {
	case remote.StatusOffline:
		return "offline"
	case remote.StatusAuthFailed:
		return "refuses the dashboard's key"
	case remote.StatusKeyChanged:
		return "its SSH host key changed"
	case statusRebooting:
		return "rebooting"
	}
	return "not checked yet"
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// failedNames lists at most three units, so a host with twenty does not make a
// line of History-sized text.
func failedNames(units []string) string {
	text := ""
	for i, u := range units {
		if i == 3 {
			return text + ", …"
		}
		if i > 0 {
			text += ", "
		}
		text += u
	}
	return text
}
