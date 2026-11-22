package ansible

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const goodKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@laptop"

// The schema in Go and the YAML of the roles are two places that must agree.
func TestEveryRoleHasFilesAndTheSettingsItReads(t *testing.T) {
	files := RoleFiles()
	if len(Library) < 7 {
		t.Fatalf("%d roles", len(Library))
	}
	for _, role := range Library {
		prefix := "roles/" + role.Name + "/"
		tasks := files[prefix+"tasks/main.yml"]
		if tasks == "" {
			t.Errorf("%s has no tasks/main.yml", role.Name)
		}
		var all strings.Builder
		for path, text := range files {
			if strings.HasPrefix(path, prefix) {
				all.WriteString(text)
			}
		}
		for _, p := range role.Params {
			if !strings.Contains(all.String(), p.Key) {
				t.Errorf("%s: no file of the role reads %s", role.Name, p.Key)
			}
		}
		// The defaults must pass the role's own checks, or a profile with the role
		// and nothing else could not be applied.
		if _, err := role.Resolve(nil); err != nil {
			t.Errorf("%s: its defaults are refused: %v", role.Name, err)
		}
		for _, p := range role.Params {
			if _, err := p.clean(p.Default); err != nil && p.Default != nil {
				t.Errorf("%s: the default of %s is refused: %v", role.Name, p.Key, err)
			}
		}
		// A role that is meant to be idempotent uses modules: no shell, no raw.
		for path, text := range files {
			if strings.HasPrefix(path, prefix) && (strings.Contains(text, "ansible.builtin.shell") || strings.Contains(text, "ansible.builtin.raw")) {
				t.Errorf("%s uses shell or raw", path)
			}
		}
	}
	// The library is in the order it is applied.
	var names []string
	for _, r := range Library {
		names = append(names, r.Name)
	}
	if got := strings.Join(names, " "); got != "base users ssh_hardening firewall nginx docker node_exporter" {
		t.Errorf("order: %s", got)
	}
}

func TestResolveChecksWhatGoesIntoFiles(t *testing.T) {
	role := func(name string) Role {
		r, ok := FindRole(name)
		if !ok {
			t.Fatalf("no role %s", name)
		}
		return r
	}
	good := []struct {
		role  string
		given map[string]any
	}{
		{"base", map[string]any{"base_timezone": "Asia/Makassar", "base_packages": []any{"git", "tmux"}, "base_upgrade": true}},
		{"users", map[string]any{"users_name": "deploy", "users_ssh_keys": []any{goodKey}}},
		{"firewall", map[string]any{"firewall_allow_ports": []any{"8080/tcp", "53/udp", "9000"}}},
		{"nginx", map[string]any{"nginx_domain": "app.example.com www.example.com", "nginx_mode": "proxy", "nginx_upstream": "http://127.0.0.1:3000/api"}},
		{"docker", map[string]any{"docker_users": []any{"deploy"}}},
		{"node_exporter", map[string]any{"node_exporter_listen": "127.0.0.1:9100"}},
	}
	for _, g := range good {
		if _, err := role(g.role).Resolve(g.given); err != nil {
			t.Errorf("%s %v: %v", g.role, g.given, err)
		}
	}

	bad := []struct {
		role  string
		given map[string]any
		why   string
	}{
		{"base", map[string]any{"base_timezone": "../etc/passwd"}, "path in a time zone"},
		{"base", map[string]any{"base_timezone": "UTC; reboot"}, "command in a time zone"},
		{"base", map[string]any{"base_packages": []any{"curl; rm -rf /"}}, "command in a package"},
		{"base", map[string]any{"base_packages": []any{"-oAPT::x"}}, "option as a package"},
		{"base", map[string]any{"base_upgrade": "yes"}, "text for a switch"},
		{"base", map[string]any{"base_ntp": 1.0}, "a number for a switch"},
		{"base", map[string]any{"base_packages": "curl"}, "text for a list"},
		{"base", map[string]any{"no_such_setting": true}, "unknown setting"},
		{"users", map[string]any{"users_name": "root"}, "root as the new user"},
		{"users", map[string]any{"users_name": "Bad Name"}, "bad user name"},
		{"users", map[string]any{"users_name": "a;id"}, "command in a user name"},
		{"users", map[string]any{"users_shell": "/bin/zsh"}, "shell not in the list"},
		{"users", map[string]any{"users_ssh_keys": []any{"not a key"}}, "not a key"},
		{"users", map[string]any{"users_ssh_keys": []any{`command="rm -rf /" ` + goodKey}}, "options in front of a key"},
		{"users", map[string]any{"users_ssh_keys": []any{goodKey + "\nssh-rsa AAAA x"}}, "two keys in one line"},
		{"firewall", map[string]any{"firewall_allow_ports": []any{"70000"}}, "port too big"},
		{"firewall", map[string]any{"firewall_allow_ports": []any{"0"}}, "port zero"},
		{"firewall", map[string]any{"firewall_allow_ports": []any{"80/icmp"}}, "protocol"},
		{"firewall", map[string]any{"firewall_allow_ports": []any{"22; ufw disable"}}, "command in a port"},
		{"nginx", map[string]any{"nginx_domain": "example.com; return 301 http://evil"}, "directive in a domain"},
		{"nginx", map[string]any{"nginx_domain": "a{b}"}, "brace in a domain"},
		{"nginx", map[string]any{"nginx_site_name": "../app"}, "path in a site name"},
		{"nginx", map[string]any{"nginx_root": "/var/www/../etc"}, "dots in a root"},
		{"nginx", map[string]any{"nginx_root": "var/www"}, "relative root"},
		{"nginx", map[string]any{"nginx_upstream": "ftp://x"}, "scheme"},
		{"nginx", map[string]any{"nginx_upstream": "http://x; y"}, "directive in an upstream"},
		{"nginx", map[string]any{"nginx_mode": "cgi"}, "mode not in the list"},
		{"docker", map[string]any{"docker_users": []any{"a b"}}, "bad user name"},
		{"node_exporter", map[string]any{"node_exporter_listen": "0.0.0.0"}, "no port"},
		{"node_exporter", map[string]any{"node_exporter_listen": "a b:9100"}, "space"},
	}
	for _, b := range bad {
		if _, err := role(b.role).Resolve(b.given); err == nil {
			t.Errorf("%s: %s was accepted (%v)", b.role, b.why, b.given)
		}
	}

	// What comes back is typed for the role, with the defaults filled in.
	got, err := role("base").Resolve(map[string]any{"base_packages": []any{" git ", "", "tmux"}})
	if err != nil {
		t.Fatal(err)
	}
	if list := got["base_packages"].([]string); strings.Join(list, ",") != "git,tmux" || got["base_timezone"] != "UTC" || got["base_ntp"] != true {
		t.Errorf("resolved: %#v", got)
	}
	// The defaults are copied, not shared: changing one result changes no other.
	a, _ := role("base").Resolve(nil)
	a["base_packages"].([]string)[0] = "changed"
	if b, _ := role("base").Resolve(nil); b["base_packages"].([]string)[0] == "changed" {
		t.Error("a default list is shared between results")
	}
}

func TestBuildPlanMergesProfilesTheHostsOwnWinning(t *testing.T) {
	groupA := []ProfileRole{{Role: "nginx", Params: map[string]any{"nginx_domain": "a.example.com"}}}
	groupB := []ProfileRole{
		{Role: "nginx", Params: map[string]any{"nginx_domain": "b.example.com", "nginx_mode": "proxy"}},
		{Role: "base", Params: map[string]any{}},
	}
	own := []ProfileRole{{Role: "nginx", Params: map[string]any{"nginx_site_name": "mine"}}}

	plan, err := BuildPlan([][]ProfileRole{groupA, groupB}, own)
	if err != nil {
		t.Fatal(err)
	}
	// In the order of the library, whatever the order in the profiles.
	if strings.Join(plan.Roles, " ") != "base nginx" {
		t.Errorf("roles: %v", plan.Roles)
	}
	ngx := plan.Params["nginx"]
	if ngx["nginx_domain"] != "b.example.com" || ngx["nginx_mode"] != "proxy" || ngx["nginx_site_name"] != "mine" || ngx["nginx_remove_default"] != true {
		t.Errorf("nginx: %#v (later group beats earlier, own is merged in, defaults fill the rest)", ngx)
	}

	// The host's own setting beats its groups'.
	own2 := []ProfileRole{{Role: "nginx", Params: map[string]any{"nginx_domain": "c.example.com"}}}
	plan2, _ := BuildPlan([][]ProfileRole{groupA, groupB}, own2)
	if plan2.Params["nginx"]["nginx_domain"] != "c.example.com" {
		t.Errorf("own: %v", plan2.Params["nginx"])
	}

	// No profile, no roles (and non-nil, for JSON).
	empty, err := BuildPlan(nil, nil)
	if err != nil || len(empty.Roles) != 0 || empty.Roles == nil {
		t.Errorf("empty: %+v %v", empty, err)
	}
	// A stored value that no longer passes the checks is an error, not a surprise at apply time.
	if _, err := BuildPlan(nil, []ProfileRole{{Role: "users", Params: map[string]any{"users_name": "root"}}}); err == nil {
		t.Error("an invalid profile was planned")
	}
}

// "changes waiting" is a comparison of these.
func TestRoleHashesFollowTheParametersAndOnlyTheirRole(t *testing.T) {
	plan := func(domain string) HostPlan {
		p, err := BuildPlan(nil, []ProfileRole{
			{Role: "base"},
			{Role: "nginx", Params: map[string]any{"nginx_domain": domain}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b, c := plan("a.example.com"), plan("a.example.com"), plan("b.example.com")
	if a.Hashes["nginx"] == "" || a.Hashes["nginx"] != b.Hashes["nginx"] {
		t.Errorf("the same profile gave two fingerprints: %v %v", a.Hashes, b.Hashes)
	}
	if a.Hashes["nginx"] == c.Hashes["nginx"] {
		t.Error("a changed parameter did not change the fingerprint")
	}
	if a.Hashes["base"] != c.Hashes["base"] {
		t.Error("a change to nginx changed the fingerprint of base")
	}
	if a.Hashes["base"] == a.Hashes["nginx"] {
		t.Error("two roles share a fingerprint")
	}

	without := a.Without("nginx")
	if without.Has("nginx") || !without.Has("base") || len(without.Hashes) != 1 || !a.Has("nginx") {
		t.Errorf("Without: %+v (and the original must be untouched)", without)
	}
}

func TestCheckProfile(t *testing.T) {
	cleaned, err := CheckProfile([]ProfileRole{
		{Role: "nginx", Params: map[string]any{"nginx_domain": " app.example.com "}},
		{Role: "base", Params: nil},
	})
	if err != nil || len(cleaned) != 2 {
		t.Fatalf("%+v %v", cleaned, err)
	}
	// Only what was given is kept, cleaned.
	if cleaned[0].Params["nginx_domain"] != "app.example.com" || len(cleaned[0].Params) != 1 || len(cleaned[1].Params) != 0 {
		t.Errorf("cleaned: %+v", cleaned)
	}

	for name, profile := range map[string][]ProfileRole{
		"unknown role":  {{Role: "kubernetes"}},
		"twice":         {{Role: "base"}, {Role: "base"}},
		"bad parameter": {{Role: "users", Params: map[string]any{"users_name": "root"}}},
		"unknown key":   {{Role: "base", Params: map[string]any{"colour": "red"}}},
	} {
		if _, err := CheckProfile(profile); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestRenderWritesThePlanAndTheManualVariablesWin(t *testing.T) {
	plan, err := BuildPlan(nil, []ProfileRole{
		{Role: "base"},
		{Role: "nginx", Params: map[string]any{"nginx_domain": "app.example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := sampleInput()
	in.Plans = map[string]HostPlan{"web-1": plan}
	in.Hosts[1].Vars = []Var{{"nginx_domain", "from-the-host.example.com"}} // web-1

	files, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	vars := files["host_vars/web-1.yml"]
	for _, want := range []string{
		`im_roles: ["base", "nginx"]`,
		"\n# base\n", "base_ntp: true\n", `base_packages: ["curl", "vim", "htop", "ca-certificates", "unzip"]`, `base_timezone: "UTC"`,
		"\n# nginx\n", `nginx_mode: "static"`, "nginx_remove_default: true\n",
		"\n# Variables set on this host.\n", `nginx_domain: "from-the-host.example.com"`,
	} {
		if !strings.Contains(vars, want) {
			t.Errorf("host_vars/web-1.yml has no %q:\n%s", want, vars)
		}
	}
	// One value for a name: YAML refuses a key twice, and the manual one wins.
	if strings.Count(vars, "nginx_domain:") != 1 || strings.Contains(vars, "app.example.com") {
		t.Errorf("nginx_domain is not written once, by the host:\n%s", vars)
	}
	// A host with no plan has no roles.
	if _, ok := files["host_vars/web-2.yml"]; ok {
		t.Error("a host without a profile has a host_vars file")
	}

	if files["group_vars/all.yml"] != "---\n"+header+"im_roles: []\n" {
		t.Errorf("group_vars/all.yml: %q", files["group_vars/all.yml"])
	}
	site := files["site.yml"]
	for _, r := range Library {
		want := "    - role: " + r.Name + "\n      tags: [" + r.Name + "]\n      when: \"'" + r.Name + "' in im_roles\"\n"
		if !strings.Contains(site, want) {
			t.Errorf("site.yml does not run %s on the hosts that have it:\n%s", r.Name, site)
		}
	}
	if !strings.Contains(site, "become: true") || !strings.Contains(site, "hosts: all") {
		t.Errorf("site.yml:\n%s", site)
	}
	if files["roles/nginx/templates/site.conf.j2"] == "" || files["roles/firewall/vars/main.yml"] == "" {
		t.Error("the roles are not in the generated files")
	}

	// im_roles is the profile's: a variable of that name would silently replace it.
	if err := CheckVar("im_roles", "[]"); err == nil {
		t.Error("a variable called im_roles was accepted")
	}
}

func TestYAMLParams(t *testing.T) {
	cases := map[string]string{
		yamlParam(true):                     "true",
		yamlParam(false):                    "false",
		yamlParam(8080):                     "8080",
		yamlParam("a \"b\""):                `"a \"b\""`,
		yamlParam([]string{}):               "[]",
		yamlParam([]string{"a", "b c"}):     `["a", "b c"]`,
		yamlParam([]string{`say "hi"`}):     `["say \"hi\""]`,
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}

// With Ansible on the machine, the generated playbook and roles must at least
// parse. (Without it, this test is skipped: it is a check on the YAML.)
func TestGeneratedPlaybookPassesAnsiblesSyntaxCheck(t *testing.T) {
	bin, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook is not installed here")
	}
	var profile []ProfileRole
	for _, r := range Library {
		profile = append(profile, ProfileRole{Role: r.Name})
	}
	plan, err := BuildPlan(nil, profile)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "ansible")
	in := Input{
		Hosts:          []Host{{Name: "web-1", Address: "10.0.0.1", Port: 22, User: "deploy"}},
		Plans:          map[string]HostPlan{"web-1": plan},
		KeyPath:        filepath.Join(dir, "key"),
		KnownHostsPath: filepath.Join(dir, "known_hosts"),
	}
	files, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, files); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "site.yml", "--syntax-check")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+filepath.Join(dir, "ansible.cfg"), "ANSIBLE_NOCOLOR=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "couldn't resolve module/action") {
			t.Skip("an Ansible collection the roles use (community.general) is not installed here")
		}
		t.Fatalf("ansible-playbook --syntax-check failed:\n%s", out)
	}
}
