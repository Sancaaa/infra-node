package web

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"infra-manager/internal/ansible"
	"infra-manager/internal/remote"
	"infra-manager/internal/store"
	"infra-manager/internal/tf"
)

// Server holds what every request needs.
type Server struct {
	db         *sql.DB
	remote     *remote.Remote // the dashboard's SSH key, and what it does over SSH
	loginLimit *loginLimiter
	clock      func() time.Time // time source for TOTP and sessions; tests may override
	// checks limits how many passwords are being checked at once. bcrypt is slow
	// on purpose, so a flood of logins would keep every CPU busy; the others wait
	// their turn, and give up if it takes too long.
	checks chan struct{}
	anon   *eventCap

	// Hosts that were told to reboot and are being waited for. The check every
	// minute leaves them alone: a host that is down on purpose is not an alarm.
	mu        sync.Mutex
	rebooting map[int64]bool
	reboot    rebootTiming

	// Ansible (IM4). genMu makes the files be written one run at a time;
	// ansibleMu lets one Ansible run go at a time: two would fight over the same
	// hosts, and over the same SSH connections.
	ansible   ansible.Runner
	genMu     sync.Mutex
	ansibleMu sync.Mutex
	version   versionCache
	// rebootSeq lets one "Reboot one by one" go at a time.
	rebootSeq sync.Mutex

	// Proxmox and Terraform (IM7). tfMu lets one Terraform job go at a time
	// (OD-04's rule). pendingPlan holds the one saved plan that may be applied,
	// once, within 15 minutes.
	tf          tf.Runner
	tfGenMu     sync.Mutex
	tfMu        sync.Mutex
	tfVersion   versionCache
	planMu      sync.Mutex
	pendingPlan *savedPlan
	driftMu        sync.Mutex
	lastDrift      *driftReport
	provision      provisionTiming
	hostTarget     func(m store.Machine, ip string) remote.Target

	// Compliance checks and scheduler (IM9).
	schedMu        sync.Mutex
	schedJobs      map[string]*scheduleJob
	schedWake      chan struct{}
	compMu         sync.Mutex
	lastCompliance *complianceReport
}

// provisionTiming controls wait loops after a container is created and how long
// a saved Terraform plan stays valid. Tests shorten these so they run quickly.
type provisionTiming struct {
	sshWait  time.Duration
	sshPoll  time.Duration
	dhcpWait time.Duration
	dhcpPoll time.Duration
	planTTL  time.Duration
}

// rebootTiming is how a reboot is waited for. It is a field so a test can make
// it fast.
type rebootTiming struct {
	settle  time.Duration // before the first look: the host is still shutting down
	poll    time.Duration // between looks
	timeout time.Duration // after this, the host is called offline
}

func NewServer(db *sql.DB, rem *remote.Remote) *Server {
	return &Server{
		db:         db,
		remote:     rem,
		loginLimit: newLoginLimiter(),
		clock:      time.Now,
		checks:     make(chan struct{}, 4),
		anon:       &eventCap{now: time.Now},
		rebooting:  map[int64]bool{},
		reboot:     rebootTiming{settle: 10 * time.Second, poll: 5 * time.Second, timeout: 10 * time.Minute},
		ansible:    ansible.NewRunner(filepath.Join(rem.DataDir(), "ansible")),
		tf:         tf.NewRunner(filepath.Join(rem.DataDir(), "terraform"), tf.SecretPath(rem.DataDir())),
		provision: provisionTiming{
			sshWait:  60 * time.Second,
			sshPoll:  3 * time.Second,
			dhcpWait: 30 * time.Second,
			dhcpPoll: 2 * time.Second,
			planTTL:  15 * time.Minute,
		},
		schedJobs: defaultSchedJobs(),
		schedWake: make(chan struct{}, 1),
	}
}

func (s *Server) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// handler is what a route does once the person is known and allowed.
type handler func(w http.ResponseWriter, r *http.Request, me store.User)

// route is one line of the API. The table in routes() is the whole API, so a
// route cannot be added without saying who may use it, and a test can walk it.
type route struct {
	pattern string
	action  Action
	public  bool // only login: no session needed
	handle  handler
}

func (s *Server) routes() []route {
	return []route{
		{pattern: "POST /api/login", public: true},

		{pattern: "POST /api/logout", action: ActionSelf, handle: s.logout},
		{pattern: "GET /api/me", action: ActionSelf, handle: s.me},
		{pattern: "POST /api/me/password", action: ActionSelf, handle: s.changePassword},
		{pattern: "POST /api/me/totp/reset", action: ActionSelf, handle: s.resetMyTOTP},
		{pattern: "GET /api/me/sessions", action: ActionSelf, handle: s.mySessions},
		{pattern: "POST /api/me/sessions/revoke-others", action: ActionSelf, handle: s.revokeOtherSessions},

		{pattern: "GET /api/history", action: ActionView, handle: s.history},
		{pattern: "GET /api/overview", action: ActionView, handle: s.overview},

		{pattern: "GET /api/ssh-key", action: ActionSettings, handle: s.sshKey},

		{pattern: "GET /api/hosts", action: ActionView, handle: s.listHosts},
		{pattern: "POST /api/hosts", action: ActionManageHosts, handle: s.addHost},
		{pattern: "POST /api/hosts/{id}/edit", action: ActionManageHosts, handle: s.editHost},
		{pattern: "POST /api/hosts/{id}/check", action: ActionOperate, handle: s.checkHost},
		{pattern: "POST /api/hosts/{id}/trust-key", action: ActionManageHosts, handle: s.trustHostKey},
		{pattern: "POST /api/hosts/{id}/remove", action: ActionManageHosts, handle: s.removeHost},

		// The quick actions (IM3).
		{pattern: "GET /api/hosts/{id}/details", action: ActionView, handle: s.hostDetails},
		{pattern: "GET /api/hosts/{id}/services", action: ActionOperate, handle: s.hostServices},
		{pattern: "GET /api/hosts/{id}/logs", action: ActionOperate, handle: s.serviceLogs},
		{pattern: "POST /api/hosts/{id}/restart", action: ActionOperate, handle: s.restartService},
		{pattern: "POST /api/hosts/{id}/reboot", action: ActionOperate, handle: s.rebootHost},
		{pattern: "POST /api/hosts/{id}/run", action: ActionRun, handle: s.runCommand},

		// Groups and variables (IM4). Looking at who is in a group is for
		// everyone; variables and the generated files are an operator's to read,
		// because a value may be something that is not for every viewer.
		{pattern: "GET /api/groups", action: ActionView, handle: s.listGroups},
		{pattern: "POST /api/groups", action: ActionManageGroups, handle: s.createGroup},
		{pattern: "POST /api/groups/{id}/rename", action: ActionManageGroups, handle: s.renameGroup},
		{pattern: "POST /api/groups/{id}/delete", action: ActionManageGroups, handle: s.deleteGroup},
		{pattern: "POST /api/groups/{id}/hosts", action: ActionManageGroups, handle: s.changeGroupHosts},
		{pattern: "GET /api/groups/{id}/vars", action: ActionOperate, handle: s.groupVars},
		{pattern: "POST /api/groups/{id}/vars", action: ActionManageGroups, handle: s.setGroupVars},
		{pattern: "GET /api/hosts/{id}/vars", action: ActionOperate, handle: s.hostVars},
		{pattern: "POST /api/hosts/{id}/vars", action: ActionManageGroups, handle: s.setHostVars},

		// Profiles and configuring hosts (IM5). Anybody who may look sees the
		// library; a profile's parameters are an operator's to read, like the
		// variables; changing a profile is an admin's, and so is nothing else:
		// Preview and Apply are an operator's.
		{pattern: "GET /api/library", action: ActionView, handle: s.library},
		{pattern: "GET /api/groups/{id}/profile", action: ActionOperate, handle: s.groupProfile},
		{pattern: "POST /api/groups/{id}/profile", action: ActionManageGroups, handle: s.setGroupProfile},
		{pattern: "GET /api/hosts/{id}/profile", action: ActionOperate, handle: s.hostProfile},
		{pattern: "POST /api/hosts/{id}/profile", action: ActionManageGroups, handle: s.setHostProfile},
		{pattern: "POST /api/configure", action: ActionOperate, handle: s.configure},

		// Operations at scale (IM6). Updating packages and rebooting are an
		// operator's, like Apply. Access, secrets and custom playbooks are an
		// admin's, to look at as well as to change: who may log in where, which
		// secrets exist and free-form Ansible are not for every operator.
		{pattern: "POST /api/patch", action: ActionOperate, handle: s.patch},
		{pattern: "POST /api/patch/reboot", action: ActionOperate, handle: s.rebootSequence},

		{pattern: "GET /api/access", action: ActionAccess, handle: s.listAccess},
		{pattern: "POST /api/access/keys", action: ActionAccess, handle: s.addAccessKey},
		{pattern: "POST /api/access/keys/{id}/grants", action: ActionAccess, handle: s.setAccessGrants},
		{pattern: "POST /api/access/keys/{id}/delete", action: ActionAccess, handle: s.deleteAccessKey},
		{pattern: "POST /api/access/keys/{id}/revoke", action: ActionAccess, handle: s.revokeAccessKey},
		{pattern: "POST /api/access/apply", action: ActionAccess, handle: s.applyAccess},

		{pattern: "GET /api/secrets", action: ActionSecrets, handle: s.listSecrets},
		{pattern: "POST /api/secrets", action: ActionSecrets, handle: s.setSecret},
		{pattern: "POST /api/secrets/{name}/delete", action: ActionSecrets, handle: s.deleteSecret},

		{pattern: "GET /api/playbooks", action: ActionPlaybooks, handle: s.listPlaybooks},
		{pattern: "GET /api/playbooks/{name}", action: ActionPlaybooks, handle: s.getPlaybook},
		{pattern: "POST /api/playbooks", action: ActionPlaybooks, handle: s.savePlaybook},
		{pattern: "POST /api/playbooks/{name}/delete", action: ActionPlaybooks, handle: s.deletePlaybook},
		{pattern: "POST /api/playbooks/{name}/run", action: ActionPlaybooks, handle: s.runPlaybook},

		{pattern: "GET /api/ansible", action: ActionView, handle: s.ansibleInfo},
		{pattern: "POST /api/ansible/ping", action: ActionOperate, handle: s.ansiblePing},
		{pattern: "POST /api/ansible/facts", action: ActionOperate, handle: s.ansibleFacts},
		{pattern: "GET /api/code", action: ActionOperate, handle: s.viewCode},

		// Proxmox settings and Terraform machines (IM7).
		{pattern: "GET /api/proxmox", action: ActionSettings, handle: s.getProxmox},
		{pattern: "POST /api/proxmox", action: ActionSettings, handle: s.saveProxmox},
		{pattern: "POST /api/proxmox/test", action: ActionSettings, handle: s.testProxmox},

		{pattern: "GET /api/machines", action: ActionView, handle: s.listMachines},
		{pattern: "POST /api/machines", action: ActionManageMachines, handle: s.createMachine},
		{pattern: "POST /api/machines/{id}/resize", action: ActionManageMachines, handle: s.resizeMachine},
		{pattern: "POST /api/machines/{id}/remove", action: ActionManageMachines, handle: s.removeMachine},
		{pattern: "POST /api/machines/{id}/cancel", action: ActionManageMachines, handle: s.cancelMachine},
		{pattern: "POST /api/machines/{id}/start", action: ActionOperate, handle: s.startMachine},
		{pattern: "POST /api/machines/{id}/stop", action: ActionOperate, handle: s.stopMachine},

		{pattern: "POST /api/terraform/plan", action: ActionManageMachines, handle: s.terraformPlan},
		{pattern: "POST /api/terraform/apply", action: ActionManageMachines, handle: s.terraformApply},

		// Drift, rebuild, adopt and state backups (IM8).
		{pattern: "POST /api/terraform/drift", action: ActionOperate, handle: s.checkDrift},
		{pattern: "POST /api/machines/{id}/accept-drift", action: ActionManageMachines, handle: s.acceptDrift},
		{pattern: "POST /api/machines/adopt/preview", action: ActionManageMachines, handle: s.adoptPreview},
		{pattern: "GET /api/terraform/backups", action: ActionManageMachines, handle: s.listBackups},
		{pattern: "POST /api/terraform/backups/{id}/preview", action: ActionManageMachines, handle: s.previewRestore},
		{pattern: "POST /api/terraform/backups/{id}/restore", action: ActionManageMachines, handle: s.restoreBackup},

		// Compliance and scheduler (IM9).
		{pattern: "POST /api/compliance/check", action: ActionOperate, handle: s.checkCompliance},
		{pattern: "GET /api/schedule", action: ActionView, handle: s.getSchedule},
		{pattern: "POST /api/schedule", action: ActionSettings, handle: s.saveSchedule},

		{pattern: "GET /api/users", action: ActionManageUsers, handle: s.listUsers},
		{pattern: "POST /api/users", action: ActionManageUsers, handle: s.createUser},
		{pattern: "POST /api/users/{id}/role", action: ActionManageUsers, handle: s.setUserRole},
		{pattern: "POST /api/users/{id}/password", action: ActionManageUsers, handle: s.resetUserPassword},
		{pattern: "POST /api/users/{id}/totp-reset", action: ActionManageUsers, handle: s.resetUserTOTP},
		{pattern: "POST /api/users/{id}/disable", action: ActionManageUsers, handle: s.disableUser},
		{pattern: "POST /api/users/{id}/enable", action: ActionManageUsers, handle: s.enableUser},

		// Everything else under /api: a person who is not logged in gets the same
		// 401 as for a real route (nothing about the API is learned without a
		// login), and a logged-in one gets a plain 404.
		{pattern: "/api/", action: ActionSelf, handle: notFound},
	}
}

// Routes registers the API.
func (s *Server) Routes(mux *http.ServeMux) {
	for _, rt := range s.routes() {
		switch {
		case rt.public:
			mux.HandleFunc(rt.pattern, s.login)
		default:
			mux.HandleFunc(rt.pattern, s.api(rt.action, rt.handle))
		}
	}
}

// api wraps every route except login: it finds the person behind the session
// cookie (401 if there is none), asks can() whether their role allows the
// action (403 if not), and only then runs the handler. A change from another
// website is already refused before this, by Secure.
//
// A refusal is written to History, so it can be seen who tried what.
func (s *Server) api(action Action, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		me, err := s.sessionUser(r)
		if errors.Is(err, store.ErrNotFound) {
			s.recordCapped(r, store.User{}, "unauthenticated", store.ResultRefused, r.Method+" "+r.URL.Path)
			writeError(w, http.StatusUnauthorized, "Log in first.")
			return
		}
		if err != nil {
			serverError(w, "check the session", err)
			return
		}
		if !can(me, action) {
			s.record(r, me, string(action), "", store.ResultRefused, r.Method+" "+r.URL.Path)
			writeError(w, http.StatusForbidden, "Your role is not allowed to do that.")
			return
		}
		h(w, r, me)
	}
}

func notFound(w http.ResponseWriter, r *http.Request, me store.User) {
	writeError(w, http.StatusNotFound, "There is nothing at that address.")
}

// record writes one line of History. A failure to write is logged and
// otherwise ignored: the action it describes has already happened (or been
// refused), and failing the request now would not undo it.
func (s *Server) record(r *http.Request, who store.User, action, target, result, detail string) {
	s.recordFrom(clientIP(r), who, action, target, result, detail)
}

// maxDetail is as long as a line of History may be. A command that an admin
// ran is written in full, so it is generous; it is still a limit, because the
// text comes from a request.
const maxDetail = 2000

// recordFrom is record for something that happens after the request is over
// (a reboot that finished): there is no request any more, only who asked and
// from where.
func (s *Server) recordFrom(ip string, who store.User, action, target, result, detail string) {
	if len(detail) > maxDetail {
		detail = detail[:maxDetail]
	}
	err := store.AddEvent(s.db, store.Event{
		UserID: who.ID, Username: who.Username,
		Action: action, Target: target, Result: result, Detail: detail,
		IP: ip,
	})
	if err != nil {
		slog.Error("write history", "err", err)
	}
}

// recordCapped is record for requests nobody is logged in for (who is the zero
// User, or the account a login was refused for), within the cap of eventCap.
func (s *Server) recordCapped(r *http.Request, who store.User, action, result, detail string) {
	if !s.anon.allow() {
		return
	}
	s.record(r, who, action, "", result, detail)
}

// ------------------------------------------------------------- requests

// readJSON reads a small JSON body. The cap stops anyone from making the
// server read a huge one.
func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	return readJSONLimit(w, r, into, 4096)
}

// readJSONLimit is readJSON for a body that may be bigger: a playbook is text of
// some pages.
func readJSONLimit(w http.ResponseWriter, r *http.Request, into any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, "The request is not valid JSON.")
		return false
	}
	return true
}

func serverError(w http.ResponseWriter, what string, err error) {
	slog.Error(what, "err", err)
	writeError(w, http.StatusInternalServerError, "Something went wrong on the server.")
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// fromLocalProxy: Caddy runs on this machine, so a request that came from
// loopback may carry X-Forwarded-For. From anywhere else the header is a
// client's own claim and is ignored.
func fromLocalProxy(r *http.Request) bool {
	ip := net.ParseIP(remoteIP(r))
	return ip != nil && ip.IsLoopback()
}

// clientIP is the address of the person, for the login limiter and History.
// Caddy puts the real address last in X-Forwarded-For.
func clientIP(r *http.Request) string {
	if fromLocalProxy(r) {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return remoteIP(r)
}
