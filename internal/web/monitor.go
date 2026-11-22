package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"infra-manager/internal/remote"
	"infra-manager/internal/store"
)

const (
	monitorEvery   = time.Minute
	monitorWorkers = 4 // hosts checked at the same time
	updatesEvery   = 10 * time.Minute
	driftEvery     = 15 * time.Minute // Proxmox Terraform drift check (IM8)
	// A host that refused the dashboard's key, or showed a different host key, is
	// looked at again only this often. Every look is a failed login on that host,
	// and a few of them in a row can get this machine's address banned.
	recheckBroken = 10 * time.Minute
)

// mergeHealth turns a fresh health reading into the JSON that is stored. The
// number of pending updates is slow to take, so most readings do not have it
// (Updates is -1): then the last known count is kept, with the time it was
// taken.
func mergeHealth(h remote.Health, previousJSON string, now time.Time) (string, error) {
	if h.Updates >= 0 {
		h.UpdatesAt = now.Unix()
	} else if previousJSON != "" {
		var prev remote.Health
		if json.Unmarshal([]byte(previousJSON), &prev) == nil && prev.Updates >= 0 {
			h.Updates, h.UpdatesAt = prev.Updates, prev.UpdatesAt
		}
	}
	data, err := json.Marshal(h)
	return string(data), err
}

// RunMonitor runs the scheduler for the three background checks:
//   - host health check (every minute, first round after 5 seconds)
//   - Proxmox Terraform drift check (every 15 minutes)
//   - nightly Ansible compliance check (time configured in Settings)
//
// It records last and next run times on the server and stops when ctx ends.
func (s *Server) RunMonitor(ctx context.Context) {
	now := time.Now()
	first := time.NewTimer(5 * time.Second)
	defer first.Stop()
	tick := time.NewTicker(monitorEvery)
	defer tick.Stop()
	driftTick := time.NewTicker(driftEvery)
	defer driftTick.Stop()

	s.setJobNext("health", now.Add(5*time.Second), "", true)
	s.setJobNext("drift", now.Add(driftEvery), "", true)

	compTimer := time.NewTimer(time.Hour)
	var compC <-chan time.Time
	armCompliance := func() {
		if !compTimer.Stop() {
			select {
			case <-compTimer.C:
			default:
			}
		}
		hhmm, enabled, _ := s.loadScheduleSettings()
		if !enabled {
			s.setJobNext("compliance", time.Time{}, "Nightly at "+hhmm, false)
			compC = nil
			return
		}
		next := nextDailyRun(time.Now(), hhmm)
		s.setJobNext("compliance", next, "Nightly at "+hhmm, true)
		compTimer.Reset(time.Until(next))
		compC = compTimer.C
	}
	armCompliance()
	defer compTimer.Stop()

	var healthBusy, driftBusy, compBusy atomic.Bool
	launch := func(busy *atomic.Bool, fn func()) {
		if !busy.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer busy.Store(false)
			fn()
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			launch(&healthBusy, s.runHealthJob)
		case <-tick.C:
			launch(&healthBusy, s.runHealthJob)
		case <-driftTick.C:
			s.setJobNext("drift", time.Now().Add(driftEvery), "", true)
			launch(&driftBusy, s.driftRound)
		case <-compC:
			armCompliance()
			launch(&compBusy, s.complianceRound)
		case <-s.schedWake:
			armCompliance()
		}
	}
}

func (s *Server) runHealthJob() {
	s.markJobStart("health")
	n := s.monitorRound()
	s.markJobDone("health", "ok", plural(n, "host")+" checked", time.Now().Add(monitorEvery))
}

// monitorRound checks every host that is due, and returns how many were checked.
// A round that takes longer than a minute makes the next one start late, never
// overlap it.
func (s *Server) monitorRound() int {
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		slog.Error("monitor: list hosts", "err", err)
		return 0
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, monitorWorkers)
	checked := 0
	for _, h := range hosts {
		if !s.due(h, time.Now()) {
			continue
		}
		checked++
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			s.probeHost(h)
		}()
	}
	wg.Wait()
	return checked
}

// due says whether a host is to be checked now.
func (s *Server) due(h store.Host, now time.Time) bool {
	s.mu.Lock()
	rebooting := s.rebooting[h.ID]
	s.mu.Unlock()
	if rebooting {
		return false // being waited for by its own watcher
	}
	broken := h.Status == remote.StatusAuthFailed || h.Status == remote.StatusKeyChanged
	return !broken || now.Sub(time.Unix(h.StatusAt, 0)) >= recheckBroken
}

// probeHost checks one host and records the result. An unreachable host is not
// an error: it is the result.
func (s *Server) probeHost(h store.Host) {
	now := time.Now()
	withUpdates := true
	if h.HealthJSON != "" {
		var prev remote.Health
		if json.Unmarshal([]byte(h.HealthJSON), &prev) == nil && prev.Updates >= 0 {
			withUpdates = now.Sub(time.Unix(prev.UpdatesAt, 0)) >= updatesEvery
		}
	}

	health, err := s.remote.Probe(targetOf(h), withUpdates)
	if err != nil {
		p := remote.Classify(err)
		if err := store.SetHostStatus(s.db, h.ID, p.Status, p.Message, p.PresentedFP, now); err != nil {
			slog.Error("monitor: record the status", "host", h.Name, "err", err)
		}
		return
	}
	healthJSON, err := mergeHealth(health, h.HealthJSON, now)
	if err == nil {
		err = store.SetHostHealth(s.db, h.ID, healthJSON, now)
	}
	if err != nil {
		slog.Error("monitor: record the health", "host", h.Name, "err", err)
	}
}

// ------------------------------------------------------------------ reboot

// beginReboot marks a host as being rebooted. False when it already is.
func (s *Server) beginReboot(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rebooting[id] {
		return false
	}
	s.rebooting[id] = true
	return true
}

func (s *Server) endReboot(id int64) {
	s.mu.Lock()
	delete(s.rebooting, id)
	s.mu.Unlock()
}

// hasRebooted: a host that answers has been through a reboot only if it has been
// up for less time than has passed since it was told to. One that answers with a
// long uptime has not shut down yet, which it takes a few seconds to do. The
// margin is for the clock of the reading, which is taken a moment after the
// asking.
func hasRebooted(uptime, sinceAsked time.Duration) bool {
	return uptime < sinceAsked+15*time.Second
}

// watchReboot is waitForReboot in its own goroutine, after the request that
// started it is over, so the person is not kept waiting and a closed page does
// not stop it. Who asked and from where are passed in for the line of History it
// writes.
func (s *Server) watchReboot(h store.Host, asked time.Time, who store.User, ip string) {
	defer s.endReboot(h.ID)
	back, detail := s.waitForReboot(h, asked)
	result := store.ResultOK
	if !back {
		result = store.ResultFailed
	}
	s.recordFrom(ip, who, "host.reboot.done", "host "+h.Name, result, detail)
}

// waitForReboot waits for a host that was told to reboot, and records how it
// went in the host's row. It answers whether the host came back, and a sentence
// for History. The wait is shared by the single Reboot button (watchReboot) and
// by "Reboot one by one", which goes to the next host only when this one is back.
func (s *Server) waitForReboot(h store.Host, asked time.Time) (bool, string) {
	t := targetOf(h)

	time.Sleep(s.reboot.settle)
	var last error
	var stillUp *remote.Health // the host answered, but its uptime says it never went down
	for time.Since(asked) < s.reboot.timeout {
		health, err := s.remote.Probe(t, false)
		if err == nil && !hasRebooted(time.Duration(health.UptimeS)*time.Second, time.Since(asked)) {
			stillUp = &health
		}
		if err == nil && hasRebooted(time.Duration(health.UptimeS)*time.Second, time.Since(asked)) {
			now := time.Now()
			healthJSON, merr := mergeHealth(health, h.HealthJSON, now)
			if merr == nil {
				merr = store.SetHostHealth(s.db, h.ID, healthJSON, now)
			}
			if merr != nil {
				slog.Error("reboot: record the health", "host", h.Name, "err", merr)
			}
			return true, "back after " + time.Since(asked).Round(time.Second).String()
		}
		last = err
		time.Sleep(s.reboot.poll)
	}

	if stillUp != nil && last == nil {
		// It never went down: the reboot command was accepted and did nothing.
		now := time.Now()
		if healthJSON, err := mergeHealth(*stillUp, h.HealthJSON, now); err == nil {
			_ = store.SetHostHealth(s.db, h.ID, healthJSON, now)
		}
		return false, "the host kept running: it did not reboot"
	}

	detail := "did not come back within " + s.reboot.timeout.String()
	status, message := remote.StatusOffline, "Rebooted, and did not come back in time. Is it starting? Look at its console."
	if last != nil {
		p := remote.Classify(last)
		status, message = p.Status, p.Message
		detail += ": " + p.Message
	}
	if err := store.SetHostStatus(s.db, h.ID, status, message, "", time.Now()); err != nil {
		slog.Error("reboot: record the status", "host", h.Name, "err", err)
	}
	return false, detail
}
