package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"infra-manager/internal/ansible"
	"infra-manager/internal/remote"
	"infra-manager/internal/store"
)

// Patching: "Update packages" on a group or a host, one host at a time, and then
// "Reboot one by one" for the hosts that need a reboot. Both stop at the first
// problem and leave the rest alone, because a bad update that reached every host
// at once is how a service goes down everywhere.

type patchReq struct {
	Mode    string `json:"mode"` // plan, preview, apply
	HostID  int64  `json:"host_id"`
	GroupID int64  `json:"group_id"`
	Serial  int    `json:"serial"` // hosts at a time; 0 means the default, 1
}

func (s *Server) patch(w http.ResponseWriter, r *http.Request, me store.User) {
	var req patchReq
	if !readJSON(w, r, &req) {
		return
	}
	switch req.Mode {
	case "plan", "preview", "apply":
	default:
		writeError(w, http.StatusBadRequest, "The mode is plan, preview or apply.")
		return
	}
	// Updating is always rolling. There is no "all at once" here: 0 is the default,
	// one at a time, and a bigger number is a choice for a big group.
	if req.Serial == 0 {
		req.Serial = 1
	}
	if req.Serial < 1 || req.Serial > maxSerial {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Updating goes 1 to %d hosts at a time.", maxSerial))
		return
	}
	label, hosts, rerr := s.candidates(req.GroupID, req.HostID)
	if rerr != nil {
		writeError(w, rerr.status, rerr.msg)
		return
	}

	ts := targetSet{
		Label: label, Roles: map[string][]string{}, Hashes: map[int64]map[string]string{}, Overrides: map[string]ansible.HostPlan{},
		Playbook: "patch.yml", Serial: req.Serial, ActionPrefix: "patch",
	}
	for _, h := range hosts {
		if !canRoot(h) {
			ts.Skipped = append(ts.Skipped, skip{h.Name, "the dashboard has no sudo on it, so Ansible cannot become root. Edit the host and allow sudo without a password"})
			continue
		}
		ts.Hosts = append(ts.Hosts, h)
		ts.Roles[h.Name] = []string{"update packages"}
	}
	sort.Slice(ts.Hosts, func(i, j int) bool { return ts.Hosts[i].Name < ts.Hosts[j].Name })

	// After a real run, look at the hosts that were updated: which of them now
	// wait for a reboot. The page offers "Reboot one by one" for those.
	ts.Done = func(done []hostRun) map[string]any {
		need := []string{}
		byName := map[string]store.Host{}
		for _, h := range ts.Hosts {
			byName[h.Name] = h
		}
		for _, hr := range done {
			if !hr.OK {
				continue
			}
			h := byName[hr.Name]
			health, err := s.remote.Probe(targetOf(h), true)
			if err != nil {
				continue // the next check of the host says what is wrong
			}
			now := time.Now()
			if healthJSON, err := mergeHealth(health, h.HealthJSON, now); err == nil {
				if err := store.SetHostHealth(s.db, h.ID, healthJSON, now); err != nil {
					slog.Error("patch: record the health", "host", h.Name, "err", err)
				}
			}
			if health.Reboot {
				need = append(need, h.Name)
			}
		}
		return map[string]any{"reboot_needed": need}
	}
	s.execute(w, r, me, ts, req.Mode)
}

// ------------------------------------------------------------ reboot one by one

// rebootSequence is "Reboot one by one": each host is rebooted, and the next one
// only when the last has answered again. If a host does not come back the
// sequence stops there, so that a bad update never takes every host down.
func (s *Server) rebootSequence(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		HostIDs []int64 `json:"host_ids"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.HostIDs) == 0 || len(req.HostIDs) > 100 {
		writeError(w, http.StatusBadRequest, "Pick 1 to 100 hosts.")
		return
	}

	// The order is the order given: the page sends the least important first.
	var hosts []store.Host
	seen := map[int64]bool{}
	for _, id := range req.HostIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		h, err := store.GetHost(s.db, id)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "One of the hosts does not exist.")
			return
		}
		if err != nil {
			serverError(w, "read a host", err)
			return
		}
		if !canRoot(h) {
			writeError(w, http.StatusConflict, h.Name+": "+noSudoMessage)
			return
		}
		hosts = append(hosts, h)
	}

	if !s.rebootSeq.TryLock() {
		writeError(w, http.StatusConflict, "Hosts are being rebooted one by one already. Wait for that to finish.")
		return
	}
	defer s.rebootSeq.Unlock()

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

	type step struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	steps := []step{}
	ip := clientIP(r)
	stopped := ""

	for _, h := range hosts {
		target := "host " + h.Name
		fmt.Fprintf(out, "Rebooting %s …\n", h.Name)
		if !s.beginReboot(h.ID) {
			steps = append(steps, step{h.Name, false, "it is already rebooting"})
			s.recordFrom(ip, me, "host.reboot", target, store.ResultRefused, "it is already rebooting")
			stopped = h.Name + " is already rebooting"
			break
		}
		asked := time.Now()
		if err := s.remote.Reboot(targetOf(h)); err != nil {
			s.endReboot(h.ID)
			msg := remote.Classify(err).Message
			steps = append(steps, step{h.Name, false, msg})
			s.recordFrom(ip, me, "host.reboot", target, store.ResultFailed, msg)
			stopped = h.Name + " could not be told to reboot: " + msg
			break
		}
		if err := store.SetHostStatus(s.db, h.ID, statusRebooting, "Rebooting: waiting for the host to answer again.", "", asked); err != nil {
			slog.Error("record the reboot", "err", err)
		}
		s.recordFrom(ip, me, "host.reboot", target, store.ResultOK, "the reboot was sent (one by one)")

		back, detail := s.waitForReboot(h, asked)
		s.endReboot(h.ID)
		result := store.ResultOK
		if !back {
			result = store.ResultFailed
		}
		s.recordFrom(ip, me, "host.reboot.done", target, result, detail)
		steps = append(steps, step{h.Name, back, detail})
		if !back {
			stopped = h.Name + " did not come back (" + detail + ")"
			break
		}
		fmt.Fprintf(out, "%s is back: %s\n", h.Name, detail)
	}

	left := []string{}
	for _, h := range hosts[len(steps):] {
		left = append(left, h.Name)
	}
	out.result(map[string]any{"steps": steps, "not_rebooted": left})
	if stopped != "" {
		out.finish(fmt.Errorf("Stopped: %s. The hosts after it were left alone.", stopped))
		return
	}
	out.finish(nil)
}
