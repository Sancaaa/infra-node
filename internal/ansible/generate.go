package ansible

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The files Ansible reads are written from the dashboard's own data, never read
// back and never edited by hand (OD-06): the database is the truth, and these
// are a rendering of it. They are written again before every use, so they can
// not be stale, and atomically, so Ansible never reads half a file.

// Var is a variable of a host or a group. The value is text; Render writes a
// number or true/false bare and everything else as a quoted string.
type Var struct {
	Key   string
	Value string
}

type Host struct {
	Name    string
	Address string
	Port    int
	User    string
	Vars    []Var
}

type Group struct {
	Name  string
	Hosts []string // host names
	Vars  []Var
}

// Input is everything the files are made of.
type Input struct {
	Hosts  []Host
	Groups []Group
	// Plans is what each host is configured with (by host name): its roles and
	// their parameters. A host with no entry has no profile.
	Plans          map[string]HostPlan
	KeyPath        string // the dashboard's private key
	KnownHostsPath string // the host keys it trusts

	// Serial, when above 0, makes the playbooks work through the hosts that many
	// at a time and stop at the first failure (rolling). It is written into the
	// playbooks themselves: Ansible reads it as a plain number.
	Serial int
	// VaultPasswordPath is the file Ansible reads to decrypt secrets. Secrets are
	// the encrypted values (name → the lines of the !vault block).
	VaultPasswordPath string
	Secrets           map[string]string
	// Access is the SSH keys of people to put on each host and to take off it
	// (by host name). Playbooks are the custom playbooks (name → text).
	Access    map[string]HostAccess
	Playbooks map[string]string
}

// AccessKey is a person's SSH public key, and the account it is for on a host.
type AccessKey struct {
	Name string // who it belongs to, for the log
	Key  string // the public key line
	User string // the account on the host
}

// HostAccess is what the access playbook does to a host.
type HostAccess struct {
	Add    []AccessKey
	Remove []AccessKey
}

// ---------------------------------------------------------------- the checks

var (
	groupRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	varKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	intRe    = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,14})$`)
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	addrRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]*$`)
	userRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*$`)
)

// These are sentences: the page shows them as they are.
var (
	ErrBadGroupName = errors.New("A group name is 1 to 32 characters: lowercase letters, digits and underscore, starting with a letter. (Ansible does not like dashes in group names.)")
	ErrReservedName = errors.New("Ansible keeps \"all\" and \"ungrouped\" for itself.")
	ErrBadVarKey    = errors.New("A variable name is letters, digits and underscore, starting with a letter or underscore, at most 64 characters.")
	ErrVarValue     = errors.New("A value is at most 1000 characters, without a NUL byte.")
)

// reservedVarPrefixes are variable namespaces owned by Ansible or by the
// dashboard itself. Allowing user-defined variables in these namespaces would
// let a group or host variable override SSH/connection settings, privilege
// escalation or interpreter commands, dashboard-managed SSH access lists
// (im_roles, im_access, im_access_remove), or vault secrets (secret_*).
var reservedVarPrefixes = []string{"ansible_", "im_", "secret_"}

func isReservedVar(key string) bool {
	low := strings.ToLower(key)
	for _, prefix := range reservedVarPrefixes {
		if strings.HasPrefix(low, prefix) {
			return true
		}
	}
	return false
}

// CheckError is a refused variable, with the sentence that says why. It is a
// type of its own so that a caller can tell "the person typed something wrong"
// from "something broke".
type CheckError string

func (e CheckError) Error() string { return string(e) }

func CheckGroupName(name string) error {
	if name == "all" || name == "ungrouped" {
		return ErrReservedName
	}
	if !groupRe.MatchString(name) {
		return ErrBadGroupName
	}
	return nil
}

func CheckVar(key, value string) error {
	if !varKeyRe.MatchString(key) {
		return ErrBadVarKey
	}
	if isReservedVar(key) {
		return CheckError(fmt.Sprintf("The dashboard sets %s itself; variable names starting with ansible_, im_, or secret_ are reserved.", key))
	}
	if len(value) > 1000 || strings.ContainsRune(value, 0) {
		return ErrVarValue
	}
	return nil
}

// CheckVars checks a whole list: every variable, and no name twice.
func CheckVars(vars []Var) error {
	seen := map[string]bool{}
	for _, v := range vars {
		if err := CheckVar(v.Key, v.Value); err != nil {
			return err
		}
		if seen[v.Key] {
			return CheckError(fmt.Sprintf("The variable %s is there twice.", v.Key))
		}
		seen[v.Key] = true
	}
	return nil
}

// yamlValue writes a value as YAML. Whole numbers and true/false are written
// bare (a port, a switch); everything else is a double-quoted string, which
// also keeps YAML 1.1's yes, no, on and off from turning into booleans.
func yamlValue(v string) string {
	if intRe.MatchString(v) || v == "true" || v == "false" {
		return v
	}
	// "secret:name" is a reference: the variable that holds the decrypted secret.
	if name, ok := SecretRef(v); ok {
		return strconv.Quote("{{ " + SecretVar(name) + " }}")
	}
	return strconv.Quote(v)
}

// ------------------------------------------------------------------ rendering

const header = "# Generated by infra-manager from its own data. Changes made here are overwritten.\n"

// Render makes the files Ansible reads, as path → text, from nothing but its
// input, and the same input always gives the same text.
func Render(in Input) (map[string]string, error) {
	for _, p := range []string{in.KeyPath, in.KnownHostsPath} {
		if p == "" || strings.ContainsAny(p, " \t\r\n'\"#;%") {
			return nil, fmt.Errorf("The data directory path %q has a space or a quote in it, which Ansible's settings cannot hold. Use a plain path for -data.", p)
		}
	}
	// The keys of people go into files that Ansible reads: check them once more here.
	for host, a := range in.Access {
		for _, k := range append(append([]AccessKey(nil), a.Add...), a.Remove...) {
			if !accessNameRe.MatchString(k.Name) || !sshKeyRe.MatchString(k.Key) || !userRe.MatchString(k.User) {
				return nil, fmt.Errorf("An SSH key for the host %q cannot go in a file.", host)
			}
		}
	}
	files := map[string]string{}

	vault := ""
	if in.VaultPasswordPath != "" {
		if strings.ContainsAny(in.VaultPasswordPath, " \t\r\n'\"#;%") {
			return nil, fmt.Errorf("The data directory path %q has a space or a quote in it, which Ansible's settings cannot hold. Use a plain path for -data.", in.VaultPasswordPath)
		}
		vault = "vault_password_file = " + in.VaultPasswordPath + "\n"
	}

	files["ansible.cfg"] = header + `[defaults]
inventory = inventory.ini
private_key_file = ` + in.KeyPath + `
` + vault + `host_key_checking = True
interpreter_python = auto_silent
deprecation_warnings = False
nocolor = True

[ssh_connection]
ssh_args = -o UserKnownHostsFile=` + in.KnownHostsPath + ` -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o BatchMode=yes
pipelining = True

[privilege_escalation]
become_method = sudo
`

	hosts := append([]Host(nil), in.Hosts...)
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	groups := append([]Group(nil), in.Groups...)
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })

	// Every host is listed first, with how to reach it (a host that is in no group
	// is "ungrouped"), then each group names its members.
	var inv strings.Builder
	inv.WriteString(header)
	for _, h := range hosts {
		// The values were checked when they were typed; these checks are for the
		// day somebody adds a way in that forgets to.
		if !nameRe.MatchString(h.Name) || !addrRe.MatchString(h.Address) || !userRe.MatchString(h.User) || h.Port < 1 || h.Port > 65535 {
			return nil, fmt.Errorf("The host %q has a name, address, port or user that cannot go in an inventory.", h.Name)
		}
		if err := CheckVars(h.Vars); err != nil {
			return nil, fmt.Errorf("The host %q has an invalid variable: %w", h.Name, err)
		}
		fmt.Fprintf(&inv, "%s ansible_host=%s ansible_port=%d ansible_user=%s\n", h.Name, h.Address, h.Port, h.User)
		if text := renderHostVars(in.Plans[h.Name], h.Vars, in.Access[h.Name]); text != "" {
			files["host_vars/"+h.Name+".yml"] = text
		}
	}
	for _, g := range groups {
		if CheckGroupName(g.Name) != nil {
			return nil, fmt.Errorf("The group %q cannot go in an inventory.", g.Name)
		}
		if err := CheckVars(g.Vars); err != nil {
			return nil, fmt.Errorf("The group %q has an invalid variable: %w", g.Name, err)
		}
		members := append([]string(nil), g.Hosts...)
		sort.Strings(members)
		fmt.Fprintf(&inv, "\n[%s]\n", g.Name)
		for _, m := range members {
			inv.WriteString(m + "\n")
		}
		if text := renderVars(g.Vars); text != "" {
			files["group_vars/"+g.Name+".yml"] = text
		}
	}
	files["inventory.ini"] = inv.String()

	// The playbook and the roles it uses. A host has no roles unless its
	// host_vars file says so, which is what the default here is for.
	files["site.yml"] = renderSite(in.Serial)
	files["patch.yml"] = renderPatch(in.Serial)
	files["access.yml"] = renderAccess(in.Serial)
	files["group_vars/all.yml"] = renderAll(in.Secrets)
	for path, text := range RoleFiles() {
		files[path] = text
	}
	for name, text := range in.Playbooks {
		if !customRe.MatchString(name) {
			return nil, fmt.Errorf("The playbook %q cannot be written: its name is not allowed.", name)
		}
		files["custom/"+name+".yml"] = text
	}
	return files, nil
}

// customRe is the name of a custom playbook, without its .yml.
var customRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,40}$`)

// accessNameRe is how a person's key is named: it is shown and written to the log
// of a run, so it is plain.
var accessNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,63}$`)

// CheckAccessName and CheckSSHKey are the checks of what is typed on the Access page.
func CheckAccessName(name string) error {
	if !accessNameRe.MatchString(name) {
		return errors.New("A key's name is 1 to 64 characters: letters, digits, space, dot, dash, underscore and @, starting with a letter or digit.")
	}
	return nil
}

func CheckSSHKey(key string) error {
	if len(key) > 800 || !sshKeyRe.MatchString(key) {
		return errors.New("That is not an SSH public key. Paste one line, as in authorized_keys: ssh-ed25519 AAAA… name")
	}
	return nil
}

// CheckAccessUser checks the account a key is for.
func CheckAccessUser(user string) error {
	if user != "" && !userRe.MatchString(user) {
		return errors.New("The account is 1 to 32 characters: letters, digits, dot, dash and underscore, starting with a letter or underscore. Leave it empty to use the user the dashboard logs in as.")
	}
	return nil
}

func CheckPlaybookName(name string) error {
	if !customRe.MatchString(name) {
		return errors.New("A playbook's name is 1 to 41 characters: lowercase letters, digits, dash and underscore, starting with a letter.")
	}
	return nil
}

// renderAll is group_vars/all.yml: the default of im_roles, and every secret as
// a !vault value, encrypted. Every play can use secret_<name>, so a custom
// playbook can; which hosts' settings point at a secret is in their host_vars.
func renderAll(secrets map[string]string) string {
	var b strings.Builder
	b.WriteString("---\n" + header + "im_roles: []\n")
	names := make([]string, 0, len(secrets))
	for n := range secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > 0 {
		b.WriteString("\n# Secrets, encrypted with ansible-vault. Their values are not shown anywhere.\n")
	}
	for _, n := range names {
		fmt.Fprintf(&b, "%s: !vault |\n", SecretVar(n))
		for _, line := range strings.Split(secrets[n], "\n") {
			b.WriteString("  " + line + "\n")
		}
	}
	return b.String()
}

// rolling is the lines of a play that make it work through the hosts N at a
// time and stop at the first failure: what is not reached is left as it was.
func rolling(serial int) string {
	if serial <= 0 {
		return ""
	}
	return fmt.Sprintf("  serial: %d\n  max_fail_percentage: 0\n", serial)
}

// renderPatch is "Update packages": the package list, then a safe upgrade.
func renderPatch(serial int) string {
	return "---\n" + header + `- name: Update the packages
  hosts: all
  become: true
  gather_facts: false
` + rolling(serial) + `  tasks:
    - name: Refresh the package list
      ansible.builtin.apt:
        update_cache: true

    - name: Install the pending package upgrades
      ansible.builtin.apt:
        upgrade: safe
`
}

// renderAccess puts people's SSH keys on hosts and takes them off, with
// authorized_key (from the ansible.posix collection, which the Debian and Ubuntu
// package "ansible" has). The lists are in each host's host_vars: im_access is
// what should be there, im_access_remove what the dashboard put there before and
// should not be any more. Removing comes first.
func renderAccess(serial int) string {
	return "---\n" + header + `- name: Give and take away SSH access
  hosts: all
  become: true
  gather_facts: false
` + rolling(serial) + `  tasks:
    - name: Take away the SSH key of {{ item.name }}
      ansible.posix.authorized_key:
        user: "{{ item.user }}"
        key: "{{ item.key }}"
        state: absent
      loop: "{{ im_access_remove | default([]) }}"

    - name: Give the SSH key of {{ item.name }}
      ansible.posix.authorized_key:
        user: "{{ item.user }}"
        key: "{{ item.key }}"
        state: present
      loop: "{{ im_access | default([]) }}"
`
}

// renderSite is the playbook: every role of the library, each run only on the
// hosts whose im_roles has it, and tagged with its own name so that one role can
// be applied alone (--tags nginx).
func renderSite(serial int) string {
	var b strings.Builder
	b.WriteString("---\n" + header)
	b.WriteString(`- name: Configure the hosts that have a profile
  hosts: all
  become: true
  gather_facts: true
` + rolling(serial) + `  pre_tasks:
    - name: Check that the host is Debian or Ubuntu
      ansible.builtin.assert:
        that: ansible_facts['os_family'] == 'Debian'
        fail_msg: "The built-in roles support Debian and Ubuntu only."
        quiet: true
  roles:
`)
	for _, r := range Library {
		fmt.Fprintf(&b, "    - role: %s\n      tags: [%s]\n      when: \"'%s' in im_roles\"\n", r.Name, r.Name, r.Name)
	}
	return b.String()
}

// renderHostVars is the host_vars file of a host: the roles of its profile, the
// parameters of those roles (all of them, defaults included, so the file shows
// what really applies), and the variables somebody set on the host, which win
// over a parameter of the same name.
func renderHostVars(plan HostPlan, manual []Var, access HostAccess) string {
	if len(plan.Roles) == 0 && len(manual) == 0 && len(access.Add) == 0 && len(access.Remove) == 0 {
		return ""
	}
	own := map[string]bool{}
	for _, v := range manual {
		own[v.Key] = true
	}

	var b strings.Builder
	b.WriteString("---\n" + header)
	if len(plan.Roles) > 0 {
		quoted := make([]string, len(plan.Roles))
		for i, r := range plan.Roles {
			quoted[i] = strconv.Quote(r)
		}
		fmt.Fprintf(&b, "\n# The profile of this host: its groups' roles and its own.\nim_roles: [%s]\n", strings.Join(quoted, ", "))
		for _, role := range plan.Roles {
			keys := make([]string, 0, len(plan.Params[role]))
			for k := range plan.Params[role] {
				if !own[k] {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			fmt.Fprintf(&b, "\n# %s\n", role)
			for _, k := range keys {
				fmt.Fprintf(&b, "%s: %s\n", k, yamlParam(plan.Params[role][k]))
			}
		}
	}
	if len(access.Add) > 0 || len(access.Remove) > 0 {
		b.WriteString("\n# SSH access given by the dashboard (the Access page): the keys to have, and the ones it put here before and takes away.\n")
		fmt.Fprintf(&b, "im_access: %s\nim_access_remove: %s\n", yamlKeys(access.Add), yamlKeys(access.Remove))
	}
	if len(manual) > 0 {
		sorted := append([]Var(nil), manual...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
		b.WriteString("\n# Variables set on this host.\n")
		for _, v := range sorted {
			fmt.Fprintf(&b, "%s: %s\n", v.Key, yamlValue(v.Value))
		}
	}
	return b.String()
}

// yamlKeys writes a list of keys as a YAML flow list of maps, in the order given.
func yamlKeys(keys []AccessKey) string {
	items := make([]string, len(keys))
	for i, k := range keys {
		items[i] = fmt.Sprintf("{name: %s, key: %s, user: %s}", strconv.Quote(k.Name), strconv.Quote(k.Key), strconv.Quote(k.User))
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func renderVars(vars []Var) string {
	if len(vars) == 0 {
		return ""
	}
	sorted := append([]Var(nil), vars...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	var b strings.Builder
	b.WriteString("---\n" + header)
	for _, v := range sorted {
		fmt.Fprintf(&b, "%s: %s\n", v.Key, yamlValue(v.Value))
	}
	return b.String()
}

// ------------------------------------------------------------------ writing

// managedDirs are the folders the dashboard owns completely: what is in them
// and not in the generated set is removed (a deleted group's variables, a role
// file that a new version of the dashboard no longer has). Everything else in
// the folder is left alone.
var managedDirs = []string{"group_vars", "host_vars", "roles", "custom"}

// Write puts the files in dir. Each is written to a temporary file and renamed,
// so Ansible never reads half of one (also not when two runs overlap), and a
// file whose text did not change is left alone. Files in the managed folders
// that are no longer generated are removed.
func Write(dir string, files map[string]string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	for path, text := range files {
		target := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(target), err)
		}
		if err := writeFile(target, []byte(text)); err != nil {
			return err
		}
	}
	for _, sub := range managedDirs {
		root := filepath.Join(dir, sub)
		if err := os.MkdirAll(root, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", root, err)
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(dir, path)
			if _, wanted := files[filepath.ToSlash(rel)]; !wanted {
				if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("remove %s: %w", rel, err)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*") // 0600
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer os.Remove(tmp.Name()) // nothing left behind if a step fails; no-op after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("put %s in place: %w", path, err)
	}
	return nil
}

// isManaged: rel is a managed folder or inside one.
func isManaged(rel string) bool {
	rel = filepath.ToSlash(rel)
	for _, m := range managedDirs {
		if rel == m || strings.HasPrefix(rel, m+"/") {
			return true
		}
	}
	return false
}

// Read returns every generated file under dir as path → text, in order: for
// the View code page. Hidden files (the temporary ones) are left out.
func Read(dir string) ([][2]string, error) {
	var out [][2]string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		switch {
		case d.IsDir():
			// Only the places the dashboard writes to.
			if rel != "." && !isManaged(rel) {
				return filepath.SkipDir
			}
			return nil
		case strings.HasPrefix(d.Name(), "."):
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out = append(out, [2]string{filepath.ToSlash(rel), string(data)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	// The order a person would read them: the settings, the inventory, the
	// playbook, the variables, then the roles.
	rank := func(p string) int {
		switch {
		case p == "ansible.cfg":
			return 0
		case p == "inventory.ini":
			return 1
		case p == "site.yml" || p == "patch.yml" || p == "access.yml":
			return 2
		case strings.HasPrefix(p, "group_vars/"):
			return 3
		case strings.HasPrefix(p, "host_vars/"):
			return 4
		case strings.HasPrefix(p, "custom/"):
			return 5
		}
		return 6
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := rank(out[i][0]), rank(out[j][0]); ri != rj {
			return ri < rj
		}
		return out[i][0] < out[j][0]
	})
	return out, nil
}
