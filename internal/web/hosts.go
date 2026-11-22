package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"infra-manager/internal/remote"
	"infra-manager/internal/store"
)

// The Hosts page. A host is added with a form: where it is, who to log in as,
// and either its password (used once, to install the dashboard's key) or the
// key put there by hand. After that the dashboard logs in with its own key and
// the password is gone: it is never stored, logged, written to History or sent
// back (tests check this).

// hostView is what the page gets: the host, with its facts as JSON.
type hostView struct {
	store.Host
	Facts       json.RawMessage `json:"facts,omitempty"`
	Health      json.RawMessage `json:"health,omitempty"`
	Groups      []string        `json:"groups"` // names; filled in by the list
	Config      *configView     `json:"config,omitempty"`
	MachineID   int64           `json:"machine_id,omitempty"`
	MachineName string          `json:"machine_name,omitempty"`
}

func viewOf(h store.Host) hostView {
	v := hostView{Host: h}
	if h.FactsJSON != "" {
		v.Facts = json.RawMessage(h.FactsJSON)
	}
	if h.HealthJSON != "" {
		v.Health = json.RawMessage(h.HealthJSON)
	}
	return v
}

func targetOf(h store.Host) remote.Target {
	return remote.Target{Address: h.Address, Port: h.Port, User: h.User}
}

// hostForm is the body of Add host and Edit host.
type hostForm struct {
	Name           string `json:"name"`
	Address        string `json:"address"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	Method         string `json:"method"`   // Add: "password" or "key"
	Password       string `json:"password"` // used once, then forgotten
	SudoNoPassword bool   `json:"sudo_nopasswd"`
}

func (f *hostForm) clean(defaultPort int) {
	f.Name = strings.TrimSpace(f.Name)
	f.Address = strings.TrimSpace(f.Address)
	f.User = strings.TrimSpace(f.User)
	if f.Port == 0 {
		f.Port = defaultPort
	}
}

func (f *hostForm) check() error {
	for _, err := range []error{remote.CheckName(f.Name), remote.CheckAddress(f.Address), remote.CheckPort(f.Port), remote.CheckUser(f.User)} {
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) loadHost(w http.ResponseWriter, r *http.Request) (store.Host, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "There is no such host.")
		return store.Host{}, false
	}
	h, err := store.GetHost(s.db, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "There is no such host.")
		return store.Host{}, false
	}
	if err != nil {
		serverError(w, "read the host", err)
		return store.Host{}, false
	}
	return h, true
}

// failHost answers a request that was refused or did not work, and writes it to
// History.
func (s *Server) failHost(w http.ResponseWriter, r *http.Request, me store.User, action, target string, status int, message string) {
	s.record(r, me, action, target, store.ResultFailed, message)
	writeError(w, status, message)
}

// sshFailed is failHost for a connection that did not work: 502, with the
// sentence that says what to do about it. The tool's own text is not sent: it
// is not needed to act, and it has never been checked for what it contains.
func (s *Server) sshFailed(w http.ResponseWriter, r *http.Request, me store.User, action, target string, err error) {
	s.failHost(w, r, me, action, target, http.StatusBadGateway, remote.Classify(err).Message)
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request, me store.User) {
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		serverError(w, "list hosts", err)
		return
	}
	groups, err := store.HostGroupNames(s.db)
	if err != nil {
		serverError(w, "list the groups of hosts", err)
		return
	}
	configs, _, err := s.configViews()
	if err != nil {
		serverError(w, "work out the configuration states", err)
		return
	}
	machineMap, err := store.HostMachineMap(s.db)
	if err != nil {
		serverError(w, "list machine hosts", err)
		return
	}
	views := make([]hostView, len(hosts))
	for i, h := range hosts {
		views[i] = viewOf(h)
		views[i].Groups = groups[h.ID]
		if views[i].Groups == nil {
			views[i].Groups = []string{}
		}
		if c, ok := configs[h.ID]; ok {
			views[i].Config = &c
		}
		if m, ok := machineMap[h.ID]; ok {
			views[i].MachineID = m.ID
			views[i].MachineName = m.Name
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": views})
}

// sshKey is the dashboard's public key, for the hosts that are given the key by
// hand. The private key is never sent anywhere.
func (s *Server) sshKey(w http.ResponseWriter, r *http.Request, me store.User) {
	writeJSON(w, http.StatusOK, map[string]string{
		"public_key":  s.remote.PublicKey(),
		"fingerprint": s.remote.Fingerprint(),
	})
}

func (s *Server) addHost(w http.ResponseWriter, r *http.Request, me store.User) {
	var req hostForm
	if !readJSON(w, r, &req) {
		return
	}
	req.clean(22)
	target := "host " + req.Name
	if err := req.check(); err != nil {
		s.failHost(w, r, me, "host.add", target, http.StatusBadRequest, err.Error())
		return
	}
	password := ""
	switch req.Method {
	case "password":
		password = req.Password
		if password == "" {
			s.failHost(w, r, me, "host.add", target, http.StatusBadRequest, "Enter the host's password, or choose \"I added the key myself\".")
			return
		}
	case "key":
	default:
		s.failHost(w, r, me, "host.add", target, http.StatusBadRequest, "Choose how the dashboard gets its key onto the host.")
		return
	}
	if err := store.HostConflict(s.db, req.Name, req.Address, req.Port, 0); err != nil {
		s.failHost(w, r, me, "host.add", target, http.StatusConflict, err.Error())
		return
	}

	t := remote.Target{Address: req.Address, Port: req.Port, User: req.User}
	// No host has this address (just checked), so a saved key for it is a leftover
	// of something removed by hand. Trust on first use means a first use.
	if err := s.remote.Forget(t); err != nil {
		slog.Warn("forget a leftover host key", "err", err)
	}
	res, err := s.remote.Enroll(remote.EnrollRequest{Target: t, Password: password, SudoNoPassword: req.SudoNoPassword && password != ""}, true)
	if err != nil {
		s.sshFailed(w, r, me, "host.add", target, err)
		return
	}

	factsJSON, err := json.Marshal(res.Facts)
	if err != nil {
		serverError(w, "encode the facts", err)
		return
	}
	now := time.Now()
	healthJSON, err := mergeHealth(res.Health, "", now)
	if err != nil {
		serverError(w, "encode the health", err)
		return
	}
	host, err := store.CreateHost(s.db, store.Host{
		Name: req.Name, Address: req.Address, Port: req.Port, User: req.User,
		SudoOK: res.SudoOK, SudoersInstalled: res.SudoersInstalled,
		Status: remote.StatusOnline, StatusAt: now.Unix(),
		HostKeyFP: res.HostKeyFP, FactsJSON: string(factsJSON), FactsAt: now.Unix(),
		HealthJSON: healthJSON, HealthAt: now.Unix(), LastSeen: now.Unix(),
	}, now)
	if errors.Is(err, store.ErrHostNameTaken) || errors.Is(err, store.ErrHostAddressTaken) {
		s.failHost(w, r, me, "host.add", target, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		serverError(w, "save the host", err)
		return
	}

	how := "key added by hand"
	if password != "" {
		how = "key installed with the password"
	}
	s.record(r, me, "host.add", target, store.ResultOK,
		fmt.Sprintf("%s@%s:%d; %s; %s", host.User, host.Address, host.Port, how, sudoText(res.SudoOK, res.SudoersInstalled)))
	writeJSON(w, http.StatusCreated, map[string]any{"host": viewOf(host), "warnings": res.Warnings})
}

func sudoText(ok, ruleWritten bool) string {
	text := "no sudo"
	if ok {
		text = "sudo ok"
	}
	if ruleWritten {
		text += ", sudo rule written"
	}
	return text
}

// editHost changes a host's name, address, port or user. A name alone needs no
// connection. Anything that changes how to reach it is tested first, and
// nothing is saved if the test fails. A password, if one is given, installs the
// dashboard's key again (a reinstalled machine has lost it).
func (s *Server) editHost(w http.ResponseWriter, r *http.Request, me store.User) {
	host, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	var req hostForm
	if !readJSON(w, r, &req) {
		return
	}
	req.clean(host.Port)
	target := "host " + host.Name
	if err := req.check(); err != nil {
		s.failHost(w, r, me, "host.edit", target, http.StatusBadRequest, err.Error())
		return
	}
	if m, owned, err := store.GetMachineByHostID(s.db, host.ID); err != nil {
		serverError(w, "check machine ownership", err)
		return
	} else if owned && req.Address != host.Address {
		s.failHost(w, r, me, "host.edit", target, http.StatusConflict,
			"This host belongs to the Proxmox machine "+m.Name+". Its address is owned by the machine and cannot be edited here.")
		return
	}
	if err := store.HostConflict(s.db, req.Name, req.Address, req.Port, host.ID); err != nil {
		s.failHost(w, r, me, "host.edit", target, http.StatusConflict, err.Error())
		return
	}

	old := host
	moved := req.Address != host.Address || req.Port != host.Port
	needsConnection := moved || req.User != host.User || req.Password != ""
	host.Name, host.Address, host.Port, host.User = req.Name, req.Address, req.Port, req.User

	var res remote.EnrollResult
	var factsJSON []byte
	if needsConnection {
		t := targetOf(host)
		if moved {
			// A new address is a first use of whatever answers there.
			if err := s.remote.Forget(t); err != nil {
				slog.Warn("forget a leftover host key", "err", err)
			}
		}
		var err error
		res, err = s.remote.Enroll(remote.EnrollRequest{Target: t, Password: req.Password, SudoNoPassword: req.SudoNoPassword && req.Password != ""}, moved)
		if err != nil {
			s.sshFailed(w, r, me, "host.edit", target, err)
			return
		}
		if factsJSON, err = json.Marshal(res.Facts); err != nil {
			serverError(w, "encode the facts", err)
			return
		}
		host.SudoOK, host.HostKeyFP = res.SudoOK, res.HostKeyFP
		host.SudoersInstalled = res.SudoersInstalled || (old.SudoersInstalled && req.User == old.User)
	}

	if err := store.UpdateHostConnection(s.db, host); err != nil {
		if errors.Is(err, store.ErrHostNameTaken) || errors.Is(err, store.ErrHostAddressTaken) {
			s.failHost(w, r, me, "host.edit", target, http.StatusConflict, err.Error())
			return
		}
		serverError(w, "save the host", err)
		return
	}
	if needsConnection {
		now := time.Now()
		if err := store.SetHostFacts(s.db, host.ID, string(factsJSON), res.SudoOK, now); err != nil {
			serverError(w, "save the facts", err)
			return
		}
		healthJSON, err := mergeHealth(res.Health, "", now)
		if err != nil {
			serverError(w, "encode the health", err)
			return
		}
		if err := store.SetHostHealth(s.db, host.ID, healthJSON, now); err != nil {
			serverError(w, "save the health", err)
			return
		}
		if moved {
			if err := s.remote.Forget(targetOf(old)); err != nil {
				slog.Warn("forget the old host key", "err", err)
			}
		}
	}

	var changes []string
	if old.Name != host.Name {
		changes = append(changes, "name "+old.Name+" → "+host.Name)
	}
	if moved {
		changes = append(changes, fmt.Sprintf("address %s:%d → %s:%d", old.Address, old.Port, host.Address, host.Port))
	}
	if old.User != host.User {
		changes = append(changes, "user "+old.User+" → "+host.User)
	}
	if req.Password != "" {
		changes = append(changes, "key installed again with a password")
	}
	s.record(r, me, "host.edit", target, store.ResultOK, strings.Join(changes, "; "))

	fresh, err := store.GetHost(s.db, host.ID)
	if err != nil {
		serverError(w, "read the host", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": viewOf(fresh), "warnings": res.Warnings})
}

// refreshHost connects with the dashboard's key and records the result: the
// facts when it worked, the reason when it did not. A host that cannot be
// reached is a result, not an error of this request.
func (s *Server) refreshHost(h store.Host) (store.Host, error) {
	now := time.Now()
	res, err := s.remote.Check(targetOf(h))
	if err != nil {
		p := remote.Classify(err)
		if err := store.SetHostStatus(s.db, h.ID, p.Status, p.Message, p.PresentedFP, now); err != nil {
			return h, err
		}
	} else {
		factsJSON, err := json.Marshal(res.Facts)
		if err != nil {
			return h, fmt.Errorf("encode the facts: %w", err)
		}
		if err := store.SetHostFacts(s.db, h.ID, string(factsJSON), res.SudoOK, now); err != nil {
			return h, err
		}
		healthJSON, err := mergeHealth(res.Health, h.HealthJSON, now)
		if err != nil {
			return h, err
		}
		if err := store.SetHostHealth(s.db, h.ID, healthJSON, now); err != nil {
			return h, err
		}
	}
	return store.GetHost(s.db, h.ID)
}

// checkHost is "Check now". It changes no setting, so it is not written to
// History (the health check of IM3 will do it every minute).
func (s *Server) checkHost(w http.ResponseWriter, r *http.Request, me store.User) {
	host, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	fresh, err := s.refreshHost(host)
	if err != nil {
		serverError(w, "check the host", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": viewOf(fresh)})
}

// trustHostKey saves the key a host shows now, in place of the old one. Only an
// admin may, and only for the fingerprint they were shown: the page sends back
// the one it displayed. It is the one way past a refused key, so it is written
// to History with both fingerprints.
func (s *Server) trustHostKey(w http.ResponseWriter, r *http.Request, me store.User) {
	host, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	target := "host " + host.Name

	if host.Status != remote.StatusKeyChanged || host.PresentedFP == "" {
		s.failHost(w, r, me, "host.trust_key", target, http.StatusConflict, "This host's key has not changed.")
		return
	}
	if req.Fingerprint != host.PresentedFP {
		s.failHost(w, r, me, "host.trust_key", target, http.StatusConflict, "The key on your screen is out of date. Reload the page and look at it again.")
		return
	}
	if err := s.remote.TrustNewKey(targetOf(host), req.Fingerprint); err != nil {
		if errors.Is(err, remote.ErrKeyChangedAgain) {
			s.failHost(w, r, me, "host.trust_key", target, http.StatusConflict, err.Error())
			return
		}
		s.sshFailed(w, r, me, "host.trust_key", target, err)
		return
	}

	oldFP := host.HostKeyFP
	host.HostKeyFP = req.Fingerprint
	if err := store.UpdateHostConnection(s.db, host); err != nil {
		serverError(w, "save the host", err)
		return
	}
	s.record(r, me, "host.trust_key", target, store.ResultOK, "was "+oldFP+", now "+req.Fingerprint)

	// The key is trusted; whether the dashboard can log in is the next question.
	// (A reinstalled machine has lost the dashboard's key: the status then says so.)
	fresh, err := s.refreshHost(host)
	if err != nil {
		serverError(w, "check the host", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": viewOf(fresh)})
}

// removeHost removes a host from the dashboard, and when asked also takes the
// dashboard's key (and the sudo rule it wrote) off the host. If that fails the
// host stays, so nothing is half done: the person can try again, or choose to
// remove it from the dashboard only.
func (s *Server) removeHost(w http.ResponseWriter, r *http.Request, me store.User) {
	host, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	var req struct {
		RemoveKey bool `json:"remove_key"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	target := "host " + host.Name

	if req.RemoveKey {
		if err := s.remote.RemoveKey(targetOf(host), host.SudoersInstalled); err != nil {
			message := remote.Classify(err).Message + " The host was not removed. Untick \"Also take the key off the host\" to remove it from the dashboard only."
			s.failHost(w, r, me, "host.remove", target, http.StatusBadGateway, message)
			return
		}
	}
	if err := s.remote.Forget(targetOf(host)); err != nil {
		slog.Warn("forget the host key", "err", err)
	}
	if err := store.DeleteHost(s.db, host.ID); err != nil {
		serverError(w, "delete the host", err)
		return
	}
	s.clearHostCompliance(host.ID)

	detail := "the key was left on the host"
	if req.RemoveKey {
		detail = "the key was taken off the host"
		if host.SudoersInstalled {
			detail += ", and the sudo rule too"
		}
	}
	s.record(r, me, "host.remove", target, store.ResultOK, detail)
	w.WriteHeader(http.StatusNoContent)
}
