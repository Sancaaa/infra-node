package ansible

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// The library of roles that comes with the dashboard: what a profile is made
// from. The roles are Ansible roles, embedded in the program (roles/), so
// installing the dashboard is copying one file; they are written to the
// generated folder with everything else, and View code shows them.
//
// A role's parameters are described here, in Go: that is what the form shows and
// what the server checks. Every value that reaches a role passes through
// Param.clean first, because it ends up in configuration files on a host.

//go:embed roles
var rolesFS embed.FS

type ParamType string

const (
	TypeString ParamType = "string"
	TypeBool   ParamType = "bool"
	TypeInt    ParamType = "int"
	TypeChoice ParamType = "choice"
	TypeList   ParamType = "list" // a list of strings, one per line in the form
)

// Param is one setting of a role.
type Param struct {
	Key     string    `json:"key"` // the Ansible variable; it starts with the role's name
	Label   string    `json:"label"`
	Help    string    `json:"help"`
	Type    ParamType `json:"type"`
	Default any       `json:"default"`
	Choices []string  `json:"choices,omitempty"`
	// Secret: the setting holds a secret, so it takes a reference to one
	// ("secret:name", chosen in the form) or nothing, and never a plain value. The
	// role's tasks that use it must have no_log, or a dry run's diff would show it.
	Secret bool `json:"secret,omitempty"`

	pattern  *regexp.Regexp // what a string, or each item of a list, must look like
	min, max int            // bounds of an int
	maxItems int            // of a list
}

// Role is one entry of the library.
type Role struct {
	Name        string  `json:"name"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Params      []Param `json:"params"`

	// check looks at all the resolved parameters together.
	check func(values map[string]any) error
}

var (
	pkgRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,60}$`)
	tzRe       = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$`)
	loginRe    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	sshKeyRe   = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/]+={0,3}( [^\r\n]{0,100})?$`)
	portRe     = regexp.MustCompile(`^[0-9]{1,5}(/(tcp|udp))?$`)
	siteRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	domainRe   = regexp.MustCompile(`^(_|[A-Za-z0-9*][A-Za-z0-9._*-]{0,100})( [A-Za-z0-9*][A-Za-z0-9._*-]{0,100}){0,9}$`)
	rootRe     = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,100}$`)
	upstreamRe = regexp.MustCompile(`^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$`)
	listenRe   = regexp.MustCompile(`^([A-Za-z0-9._-]*:[0-9]{1,5})?$`)
)

// Library lists the roles in the order they are applied: what the others rely on
// (packages, users) comes before what uses it, and the firewall comes after the
// services whose ports it opens.
var Library = []Role{
	{
		Name: "base", Title: "Base system",
		Description: "The package list, a few everyday packages, the time zone, and time synchronisation (chrony).",
		Params: []Param{
			{Key: "base_update_cache", Label: "Refresh the package list", Type: TypeBool, Default: true,
				Help: "Runs apt update, at most once an hour."},
			{Key: "base_upgrade", Label: "Install pending upgrades", Type: TypeBool, Default: false,
				Help: "A safe upgrade of every installed package. Off by default: patching a group one host at a time comes later."},
			{Key: "base_packages", Label: "Packages", Type: TypeList, Default: []string{"curl", "vim", "htop", "ca-certificates", "unzip"},
				pattern: pkgRe, maxItems: 50, Help: "One package name per line."},
			{Key: "base_timezone", Label: "Time zone", Type: TypeString, Default: "UTC", pattern: tzRe,
				Help: "A name from /usr/share/zoneinfo, such as UTC or Asia/Makassar."},
			{Key: "base_ntp", Label: "Keep the clock right with chrony", Type: TypeBool, Default: true,
				Help: "Installs chrony and runs it."},
		},
	},
	{
		Name: "users", Title: "A user with SSH keys and sudo",
		Description: "Creates a user, adds SSH public keys to it (never replacing the keys that are there), and lets it use sudo.",
		Params: []Param{
			{Key: "users_name", Label: "User name", Type: TypeString, Default: "deploy", pattern: loginRe,
				Help: "Lowercase letters, digits, dash and underscore. Not root."},
			{Key: "users_shell", Label: "Shell", Type: TypeChoice, Default: "/bin/bash", Choices: []string{"/bin/bash", "/bin/sh", "/usr/sbin/nologin"}},
			{Key: "users_ssh_keys", Label: "SSH public keys", Type: TypeList, Default: []string{}, pattern: sshKeyRe, maxItems: 20,
				Help: "One public key per line, as in authorized_keys (ssh-ed25519 AAAA… name)."},
			{Key: "users_sudo", Label: "Allow sudo without a password", Type: TypeBool, Default: true},
		},
		check: func(v map[string]any) error {
			if v["users_name"] == "root" {
				return errors.New("The users role makes a new user. It cannot be root.")
			}
			return nil
		},
	},
	{
		Name: "ssh_hardening", Title: "SSH hardening",
		Description: "No root login and no password login over SSH. The dashboard applies it only to a host it has just logged in to with its key, and never turns off root login on a host it logs in to as root.",
		Params: []Param{
			{Key: "ssh_disable_root", Label: "No root login", Type: TypeBool, Default: true},
			{Key: "ssh_disable_password", Label: "No password login (keys only)", Type: TypeBool, Default: true},
		},
	},
	{
		Name: "firewall", Title: "Firewall (ufw)",
		Description: "Turns on ufw and refuses what is not allowed. The SSH port is always open; the ports of the nginx and node_exporter roles are opened when those roles are on the host.",
		Params: []Param{
			{Key: "firewall_allow_ports", Label: "More ports to allow", Type: TypeList, Default: []string{}, pattern: portRe, maxItems: 50,
				Help: "One per line, such as 8080/tcp or 53/udp. Without /tcp or /udp, tcp is meant."},
		},
		check: func(v map[string]any) error {
			for _, p := range v["firewall_allow_ports"].([]string) {
				n, _ := strconv.Atoi(strings.SplitN(p, "/", 2)[0])
				if n < 1 || n > 65535 {
					return fmt.Errorf("%s is not a port: use 1 to 65535.", p)
				}
			}
			return nil
		},
	},
	{
		Name: "nginx", Title: "nginx web server",
		Description: "Installs nginx and sets up one site: static files, or a reverse proxy to an upstream.",
		Params: []Param{
			{Key: "nginx_site_name", Label: "Site file name", Type: TypeString, Default: "app", pattern: siteRe,
				Help: "The file in /etc/nginx/sites-available."},
			{Key: "nginx_domain", Label: "Domain name", Type: TypeString, Default: "_", pattern: domainRe,
				Help: "The server_name, such as app.example.com. _ means any name."},
			{Key: "nginx_mode", Label: "What the site does", Type: TypeChoice, Default: "static", Choices: []string{"static", "proxy"},
				Help: "static: serve files from a folder. proxy: pass requests to another program."},
			{Key: "nginx_root", Label: "Folder of the static files", Type: TypeString, Default: "/var/www/html", pattern: rootRe,
				Help: "Used when the site is static."},
			{Key: "nginx_upstream", Label: "Proxy to", Type: TypeString, Default: "http://127.0.0.1:3000", pattern: upstreamRe,
				Help: "Used when the site is a proxy, such as http://127.0.0.1:3000."},
			{Key: "nginx_remove_default", Label: "Remove nginx's default site", Type: TypeBool, Default: true},
			{Key: "nginx_proxy_token", Label: "Token to send to the upstream", Type: TypeString, Default: "", Secret: true,
				Help: "A secret, sent as \"Authorization: Bearer …\" to the upstream (cannot contain \", ;, $, \\, or newlines). Used when the site is a proxy."},
		},
		check: func(v map[string]any) error {
			if strings.Contains(v["nginx_root"].(string), "..") {
				return errors.New("The folder of the static files cannot contain \"..\".")
			}
			return nil
		},
	},
	{
		Name: "docker", Title: "Docker",
		Description: "Docker Engine and the compose plugin, from Docker's own apt repository. The host needs internet access.",
		Params: []Param{
			{Key: "docker_users", Label: "Users who may use Docker without sudo", Type: TypeList, Default: []string{}, pattern: loginRe, maxItems: 20,
				Help: "One user name per line. They must exist."},
		},
	},
	{
		Name: "node_exporter", Title: "Prometheus node exporter",
		Description: "Metrics about the host on port 9100, from the distribution's own package.",
		Params: []Param{
			{Key: "node_exporter_listen", Label: "Listen on", Type: TypeString, Default: "", pattern: listenRe,
				Help: "Empty: every address. Or an address and port, such as 127.0.0.1:9100."},
		},
	},
}

// FindRole looks a role up by name.
func FindRole(name string) (Role, bool) {
	for _, r := range Library {
		if r.Name == name {
			return r, true
		}
	}
	return Role{}, false
}

// ------------------------------------------------------------------ checking

// clean checks one value and returns it in the type the role gets. JSON gives
// numbers as float64 and lists as []any: both are accepted.
func (p Param) clean(v any) (any, error) {
	bad := func(format string, args ...any) (any, error) {
		return nil, fmt.Errorf("%s: %s", p.Label, fmt.Sprintf(format, args...))
	}
	switch p.Type {
	case TypeBool:
		b, ok := v.(bool)
		if !ok {
			return bad("it must be on or off.")
		}
		return b, nil
	case TypeInt:
		var n float64
		switch t := v.(type) {
		case float64:
			n = t
		case int:
			n = float64(t)
		default:
			return bad("it must be a number.")
		}
		if n != math.Trunc(n) || int(n) < p.min || int(n) > p.max {
			return bad("it must be a whole number from %d to %d.", p.min, p.max)
		}
		return int(n), nil
	case TypeString, TypeChoice:
		s, ok := v.(string)
		if !ok {
			return bad("it must be text.")
		}
		s = strings.TrimSpace(s)
		if p.Type == TypeChoice {
			for _, c := range p.Choices {
				if s == c {
					return s, nil
				}
			}
			return bad("it must be one of %s.", strings.Join(p.Choices, ", "))
		}
		if len(s) > 200 {
			return bad("it is too long.")
		}
		if p.Secret {
			// A secret is never typed into a profile: it is chosen from the secrets
			// the dashboard keeps, and this is where a typed one is refused.
			if _, ok := SecretRef(s); ok || s == "" {
				return s, nil
			}
			return bad("pick one of the secrets (or none). A value typed here would be stored in the clear.")
		}
		if p.pattern != nil && !p.pattern.MatchString(s) {
			return bad("%q is not allowed here. %s", s, p.Help)
		}
		return s, nil
	case TypeList:
		var items []string
		switch t := v.(type) {
		case []string:
			items = t
		case []any:
			for _, x := range t {
				s, ok := x.(string)
				if !ok {
					return bad("every line must be text.")
				}
				items = append(items, s)
			}
		default:
			return bad("it must be a list.")
		}
		out := []string{}
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if len(item) > 800 || (p.pattern != nil && !p.pattern.MatchString(item)) {
				return bad("%q is not allowed here. %s", shorten(item), p.Help)
			}
			out = append(out, item)
		}
		if p.maxItems > 0 && len(out) > p.maxItems {
			return bad("at most %d lines.", p.maxItems)
		}
		return out, nil
	}
	return bad("unknown type")
}

func shorten(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// Resolve fills a role's parameters: what was given (checked), and the default
// for the rest. A parameter the role does not have is an error, so a typo is
// not silently ignored.
func (r Role) Resolve(given map[string]any) (map[string]any, error) {
	out := map[string]any{}
	known := map[string]Param{}
	for _, p := range r.Params {
		known[p.Key] = p
		out[p.Key] = copyDefault(p.Default)
	}
	for key, v := range given {
		p, ok := known[key]
		if !ok {
			return nil, fmt.Errorf("%s has no setting called %q.", r.Title, key)
		}
		clean, err := p.clean(v)
		if err != nil {
			return nil, err
		}
		out[key] = clean
	}
	if r.check != nil {
		if err := r.check(out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func copyDefault(v any) any {
	if list, ok := v.([]string); ok {
		return append([]string{}, list...)
	}
	return v
}

// ProfileRole is a role in a profile with the parameters somebody set. Only what
// was set is kept: a parameter left alone follows the default of the role.
type ProfileRole struct {
	Role   string         `json:"role"`
	Params map[string]any `json:"params"`
}

// CheckProfile checks a whole profile and returns it cleaned (each given value
// in its proper type, and no defaults added).
func CheckProfile(roles []ProfileRole) ([]ProfileRole, error) {
	seen := map[string]bool{}
	out := make([]ProfileRole, 0, len(roles))
	for _, pr := range roles {
		role, ok := FindRole(pr.Role)
		if !ok {
			return nil, fmt.Errorf("There is no role called %q.", pr.Role)
		}
		if seen[pr.Role] {
			return nil, fmt.Errorf("%s is in the profile twice.", role.Title)
		}
		seen[pr.Role] = true
		if _, err := role.Resolve(pr.Params); err != nil { // checks every value and the whole
			return nil, err
		}
		given := map[string]any{}
		for _, p := range role.Params {
			if v, ok := pr.Params[p.Key]; ok {
				given[p.Key], _ = p.clean(v) // checked by Resolve above
			}
		}
		out = append(out, ProfileRole{Role: pr.Role, Params: given})
	}
	return out, nil
}

// ---------------------------------------------------------------------- plans

// HostPlan is what a host is to be configured with: the roles of its groups'
// profiles and of its own, with their parameters filled in.
type HostPlan struct {
	Roles  []string                  `json:"roles"`  // in the order of the library
	Params map[string]map[string]any `json:"params"` // role → every parameter
	Hashes map[string]string         `json:"hashes"` // role → a fingerprint of the role's files and its parameters
}

// BuildPlan merges profiles. groups are the profiles of the host's groups, in
// the order of the groups' names; own is the host's own. A role in several
// profiles is merged parameter by parameter, and a later profile wins: so a
// host's own setting beats its groups', and of two groups the one that comes
// last by name wins.
func BuildPlan(groups [][]ProfileRole, own []ProfileRole) (HostPlan, error) {
	return BuildPlanWith(groups, own, nil)
}

// BuildPlanWith is BuildPlan that knows the version of each secret (by name), so
// that changing a secret's value changes the fingerprint of the roles that use
// it: they have changes waiting, though no setting changed.
func BuildPlanWith(groups [][]ProfileRole, own []ProfileRole, secretVersions map[string]string) (HostPlan, error) {
	given := map[string]map[string]any{}
	for _, profile := range append(append([][]ProfileRole{}, groups...), own) {
		for _, pr := range profile {
			if given[pr.Role] == nil {
				given[pr.Role] = map[string]any{}
			}
			for k, v := range pr.Params {
				given[pr.Role][k] = v
			}
		}
	}

	plan := HostPlan{Roles: []string{}, Params: map[string]map[string]any{}, Hashes: map[string]string{}}
	for _, role := range Library {
		g, present := given[role.Name]
		if !present {
			continue
		}
		resolved, err := role.Resolve(g)
		if err != nil {
			return HostPlan{}, err
		}
		plan.Roles = append(plan.Roles, role.Name)
		plan.Params[role.Name] = resolved

		// What is hashed has each secret reference followed by its version.
		hashed := map[string]any{}
		for k, v := range resolved {
			hashed[k] = v
		}
		for _, p := range role.Params {
			if s, ok := resolved[p.Key].(string); ok && p.Secret {
				if name, isRef := SecretRef(s); isRef {
					hashed[p.Key] = s + "@" + secretVersions[name]
				}
			}
		}
		plan.Hashes[role.Name] = roleHash(role.Name, hashed)
	}
	return plan, nil
}

// Without is the plan with one role left out (one the dashboard would not apply
// to this host just now).
func (p HostPlan) Without(role string) HostPlan {
	out := HostPlan{Roles: []string{}, Params: map[string]map[string]any{}, Hashes: map[string]string{}}
	for _, r := range p.Roles {
		if r != role {
			out.Roles = append(out.Roles, r)
			out.Params[r] = p.Params[r]
			out.Hashes[r] = p.Hashes[r]
		}
	}
	return out
}

func (p HostPlan) Has(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// roleHash fingerprints what a role would do: its files in this version of the
// dashboard, and the parameters it is given. A host whose applied fingerprint
// differs from the current one has "changes waiting".
func roleHash(role string, params map[string]any) string {
	data, _ := json.Marshal(params) // maps are written with sorted keys
	sum := sha256.Sum256([]byte(roleDigest(role) + "|" + string(data)))
	return hex.EncodeToString(sum[:8])
}

var digests = sync.OnceValue(func() map[string]string {
	hashes := map[string]*strings.Builder{}
	files := RoleFiles()
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		role := strings.SplitN(strings.TrimPrefix(p, "roles/"), "/", 2)[0]
		if hashes[role] == nil {
			hashes[role] = &strings.Builder{}
		}
		hashes[role].WriteString(p + "\x00" + files[p] + "\x00")
	}
	out := map[string]string{}
	for role, b := range hashes {
		sum := sha256.Sum256([]byte(b.String()))
		out[role] = hex.EncodeToString(sum[:8])
	}
	return out
})

func roleDigest(role string) string { return digests()[role] }

// RoleFiles returns the files of every role, as "roles/<role>/<path>" → text.
func RoleFiles() map[string]string {
	out := map[string]string{}
	_ = fs.WalkDir(rolesFS, "roles", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := rolesFS.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = string(data)
		return nil
	})
	return out
}

// yamlParam writes a resolved parameter as YAML.
func yamlParam(v any) string {
	switch t := v.(type) {
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case string:
		// A reference to a secret becomes the variable that holds it (a !vault
		// value in group_vars/all.yml), which Ansible decrypts while it runs.
		if name, ok := SecretRef(t); ok {
			return strconv.Quote("{{ " + SecretVar(name) + " }}")
		}
		return strconv.Quote(t)
	case []string:
		quoted := make([]string, len(t))
		for i, s := range t {
			quoted[i] = strconv.Quote(s)
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	}
	return strconv.Quote(fmt.Sprint(v))
}
