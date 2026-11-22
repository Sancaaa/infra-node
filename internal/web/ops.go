package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"infra-manager/internal/remote"
	"infra-manager/internal/store"
)

// The quick actions of the Hosts page. Details, services and logs only read.
// Restart and Reboot are an operator's: the fixed actions the roadmap lists.
// Run a command is an admin's, because it is free text. Each connects with the
// dashboard's key, and each one that does something is written to History.

const noSudoMessage = "This host has no sudo for the dashboard, so that cannot be done. " +
	"Edit the host and let the dashboard use sudo without a password, or give that user passwordless sudo."

// usesSudo: commands go through "sudo -n" unless the user is root.
func usesSudo(h store.Host) bool { return h.User != "root" }

// canRoot reports whether the dashboard can do things as root on a host.
func canRoot(h store.Host) bool { return h.User == "root" || h.SudoOK }

// hostDetails is the live picture for the Details dialog: read from the host
// now, and not stored. A host that cannot be reached answers 502, and the page
// shows what it has.
func (s *Server) hostDetails(w http.ResponseWriter, r *http.Request, me store.User) {
	host, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	d, err := s.remote.Details(targetOf(host), usesSudo(host) && host.SudoOK)
	if err != nil {
		writeError(w, http.StatusBadGateway, remote.Classify(err).Message)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"facts": d.Facts, "health": d.Health, "ports": d.Ports})
}

func (s *Server) hostServices(w http.ResponseWriter, r *http.Request, me store.User) {
	host, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	services, err := s.remote.Services(targetOf(host))
	if err != nil {
		writeError(w, http.StatusBadGateway, remote.Classify(err).Message)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": services})
}

func (s *Server) serviceLogs(w http.ResponseWriter, r *http.Request, me store.User) {
	host, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	unit := r.URL.Query().Get("unit")
	target := "host " + host.Name
	if err := remote.CheckUnit(unit); err != nil {
		s.failHost(w, r, me, "host.service.logs", target, http.StatusBadRequest, err.Error())
		return
	}
	// With sudo when the dashboard has it: a plain user may not read the journal.
	logs, err := s.remote.ServiceLogs(targetOf(host), unit, usesSudo(host) && host.SudoOK)
	if err != nil {
		s.sshFailed(w, r, me, "host.service.logs", target, err)
		return
	}
	s.record(r, me, "host.service.logs", target, store.ResultOK, unit)
	writeJSON(w, http.StatusOK, map[string]any{"unit": unit, "logs": logs})
}

func (s *Server) restartService(w http.ResponseWriter, r *http.Request, me store.User) {
	host, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	var req struct {
		Unit string `json:"unit"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	target := "host " + host.Name
	if err := remote.CheckUnit(req.Unit); err != nil {
		s.failHost(w, r, me, "host.service.restart", target, http.StatusBadRequest, err.Error())
		return
	}
	if !canRoot(host) {
		s.record(r, me, "host.service.restart", target, store.ResultRefused, req.Unit+": "+noSudoMessage)
		writeError(w, http.StatusConflict, noSudoMessage)
		return
	}

	res, state, err := s.remote.RestartService(targetOf(host), req.Unit, usesSudo(host))
	if err != nil {
		s.sshFailed(w, r, me, "host.service.restart", target, err)
		return
	}
	result, detail := store.ResultOK, fmt.Sprintf("%s is %s", req.Unit, state)
	if res.Exit != 0 {
		result = store.ResultFailed
		detail = fmt.Sprintf("%s: restart exited with %d: %s", req.Unit, res.Exit, firstLine(res.Stderr))
	}
	s.record(r, me, "host.service.restart", target, result, detail)
	writeJSON(w, http.StatusOK, map[string]any{
		"unit": req.Unit, "state": state, "exit": res.Exit, "output": strings.TrimSpace(res.Stdout + res.Stderr),
	})
}

// rebootHost tells a host to reboot and answers at once (202). Waiting for it to
// come back takes a minute or more, so a goroutine does it (watchReboot): the
// host shows as "rebooting" until it answers again with a short uptime.
func (s *Server) rebootHost(w http.ResponseWriter, r *http.Request, me store.User) {
	host, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	target := "host " + host.Name
	if !canRoot(host) {
		s.record(r, me, "host.reboot", target, store.ResultRefused, noSudoMessage)
		writeError(w, http.StatusConflict, noSudoMessage)
		return
	}
	if !s.beginReboot(host.ID) {
		s.record(r, me, "host.reboot", target, store.ResultRefused, "it is already rebooting")
		writeError(w, http.StatusConflict, "That host is already rebooting.")
		return
	}

	asked := time.Now()
	if err := s.remote.Reboot(targetOf(host)); err != nil {
		s.endReboot(host.ID)
		s.sshFailed(w, r, me, "host.reboot", target, err)
		return
	}
	if err := store.SetHostStatus(s.db, host.ID, statusRebooting, "Rebooting: waiting for the host to answer again.", "", asked); err != nil {
		slog.Error("record the reboot", "err", err)
	}
	s.record(r, me, "host.reboot", target, store.ResultOK, "the reboot was sent")
	go s.watchReboot(host, asked, me, clientIP(r))

	fresh, err := store.GetHost(s.db, host.ID)
	if err != nil {
		serverError(w, "read the host", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"host": viewOf(fresh)})
}

// statusRebooting is a status that only a reboot sets, and only until the host
// answers again (or the wait runs out).
const statusRebooting = "rebooting"

const (
	maxCommandLen  = 1000
	defaultTimeout = 30
	maxTimeout     = 120
	maxAnswerBytes = 200 << 10
)

// runCommand runs what the admin typed, in the host's shell, word for word. The
// one place free text goes to a host: it is audited with the command in full.
func (s *Server) runCommand(w http.ResponseWriter, r *http.Request, me store.User) {
	host, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	var req struct {
		Command string `json:"command"`
		Root    bool   `json:"root"`
		Timeout int    `json:"timeout"` // seconds
	}
	if !readJSON(w, r, &req) {
		return
	}
	target := "host " + host.Name
	command := strings.TrimSpace(req.Command)
	switch {
	case command == "":
		s.failHost(w, r, me, "host.run", target, http.StatusBadRequest, "Type a command.")
		return
	case len(command) > maxCommandLen || strings.ContainsRune(command, 0):
		s.failHost(w, r, me, "host.run", target, http.StatusBadRequest, fmt.Sprintf("A command is at most %d characters, with no NUL byte.", maxCommandLen))
		return
	}
	if req.Timeout == 0 {
		req.Timeout = defaultTimeout
	}
	if req.Timeout < 1 || req.Timeout > maxTimeout {
		s.failHost(w, r, me, "host.run", target, http.StatusBadRequest, fmt.Sprintf("The timeout is 1 to %d seconds.", maxTimeout))
		return
	}
	asRoot := req.Root && usesSudo(host)
	if asRoot && !host.SudoOK {
		s.record(r, me, "host.run", target, store.ResultRefused, noSudoMessage)
		writeError(w, http.StatusConflict, noSudoMessage)
		return
	}

	// What is written down is what was typed: "$ command", with "sudo" when it
	// ran as root, and how it ended.
	logged := "$ " + command
	if asRoot {
		logged = "sudo " + logged
	}

	res, err := s.remote.Run(targetOf(host), command, req.Root, time.Duration(req.Timeout)*time.Second)
	if errors.Is(err, remote.ErrTimeout) {
		s.record(r, me, "host.run", target, store.ResultFailed, logged+"\n(no answer in "+fmt.Sprint(req.Timeout)+" s: stopped)")
		writeJSON(w, http.StatusOK, map[string]any{"timed_out": true, "timeout": req.Timeout, "stdout": "", "stderr": "", "exit": -1})
		return
	}
	if err != nil {
		s.record(r, me, "host.run", target, store.ResultFailed, logged+"\n("+remote.Classify(err).Message+")")
		writeError(w, http.StatusBadGateway, remote.Classify(err).Message)
		return
	}

	s.record(r, me, "host.run", target, store.ResultOK, fmt.Sprintf("%s\n(exit %d)", logged, res.Exit))
	writeJSON(w, http.StatusOK, map[string]any{
		"stdout": truncate(res.Stdout), "stderr": truncate(res.Stderr), "exit": res.Exit,
		"truncated": len(res.Stdout) > maxAnswerBytes || len(res.Stderr) > maxAnswerBytes,
	})
}

func truncate(s string) string {
	if len(s) > maxAnswerBytes {
		return s[:maxAnswerBytes]
	}
	return s
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if line, _, found := strings.Cut(s, "\n"); found {
		s = line
	}
	if s == "" {
		return "no reason given"
	}
	return s
}
