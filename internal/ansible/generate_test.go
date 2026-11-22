package ansible

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func sampleInput() Input {
	return Input{
		Hosts: []Host{
			{Name: "web-2", Address: "10.0.0.2", Port: 22, User: "deploy"},
			{Name: "web-1", Address: "10.0.0.1", Port: 2222, User: "deploy", Vars: []Var{{"role", "primary"}, {"weight", "10"}}},
			{Name: "db-1", Address: "db.lab.example", Port: 22, User: "root"},
		},
		Groups: []Group{
			{Name: "web", Hosts: []string{"web-2", "web-1"}, Vars: []Var{{"nginx_port", "80"}, {"domain", "app.example.com"}}},
			{Name: "empty"},
		},
		KeyPath:        "/var/lib/infra-manager/keys/id_ed25519",
		KnownHostsPath: "/var/lib/infra-manager/keys/known_hosts",
	}
}

func TestRenderTheInventoryAndTheVariables(t *testing.T) {
	files, err := Render(sampleInput())
	if err != nil {
		t.Fatal(err)
	}

	// Every host with how to reach it, sorted; then each group with its members, sorted.
	wantInventory := header + `db-1 ansible_host=db.lab.example ansible_port=22 ansible_user=root
web-1 ansible_host=10.0.0.1 ansible_port=2222 ansible_user=deploy
web-2 ansible_host=10.0.0.2 ansible_port=22 ansible_user=deploy

[empty]

[web]
web-1
web-2
`
	if files["inventory.ini"] != wantInventory {
		t.Errorf("inventory:\n%s\nwant:\n%s", files["inventory.ini"], wantInventory)
	}

	wantGroupVars := "---\n" + header + "domain: \"app.example.com\"\nnginx_port: 80\n"
	if files["group_vars/web.yml"] != wantGroupVars {
		t.Errorf("group_vars/web.yml:\n%s\nwant:\n%s", files["group_vars/web.yml"], wantGroupVars)
	}
	if got := files["host_vars/web-1.yml"]; got != "---\n"+header+"\n# Variables set on this host.\nrole: \"primary\"\nweight: 10\n" {
		t.Errorf("host_vars/web-1.yml:\n%s", got)
	}
	// No variables, no file.
	for _, p := range []string{"group_vars/empty.yml", "host_vars/db-1.yml", "host_vars/web-2.yml"} {
		if _, ok := files[p]; ok {
			t.Errorf("%s was written although there is nothing in it", p)
		}
	}

	cfg := files["ansible.cfg"]
	for _, want := range []string{
		"private_key_file = /var/lib/infra-manager/keys/id_ed25519\n",
		"host_key_checking = True\n",
		"-o UserKnownHostsFile=/var/lib/infra-manager/keys/known_hosts ",
		"-o StrictHostKeyChecking=yes",
		"inventory = inventory.ini\n",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("ansible.cfg has no %q:\n%s", want, cfg)
		}
	}

	// The same input, the same files: the order of the input does not matter.
	in := sampleInput()
	in.Hosts[0], in.Hosts[2] = in.Hosts[2], in.Hosts[0]
	in.Groups[0].Hosts = []string{"web-1", "web-2"}
	again, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for path, text := range files {
		if again[path] != text {
			t.Errorf("%s depends on the order of the input", path)
		}
	}
}

func TestYAMLValues(t *testing.T) {
	cases := map[string]string{
		"80":              `80`,
		"-5":              `-5`,
		"0":               `0`,
		"007":             `"007"`, // not an octal number
		"1.5":             `"1.5"`,
		"true":            `true`,
		"false":           `false`,
		"True":            `"True"`,
		"yes":             `"yes"`, // YAML 1.1 would make it a boolean
		"no":              `"no"`,
		"null":            `"null"`,
		"":                `""`,
		"app.example.com": `"app.example.com"`,
		`say "hi"`:        `"say \"hi\""`,
		`back\slash`:      `"back\\slash"`,
		"two\nlines":      `"two\nlines"`,
		"{{ other }}":     `"{{ other }}"`,
		"a: b # c":        `"a: b # c"`,
		"- item":          `"- item"`,
		"99999999999999999999": `"99999999999999999999"`, // too long to be sure of
	}
	for in, want := range cases {
		if got := yamlValue(in); got != want {
			t.Errorf("yamlValue(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestChecksOfNamesAndVariables(t *testing.T) {
	for _, ok := range []string{"web", "db_servers", "a", "web2"} {
		if err := CheckGroupName(ok); err != nil {
			t.Errorf("group %q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Web", "web-1", "1web", "web servers", "web;id", "a.b", strings.Repeat("a", 33)} {
		if !errors.Is(CheckGroupName(bad), ErrBadGroupName) {
			t.Errorf("group %q accepted", bad)
		}
	}
	for _, reserved := range []string{"all", "ungrouped"} {
		if !errors.Is(CheckGroupName(reserved), ErrReservedName) {
			t.Errorf("%q is Ansible's", reserved)
		}
	}

	if err := CheckVar("nginx_port", "80"); err != nil {
		t.Error(err)
	}
	for _, key := range []string{"", "1port", "a-b", "a b", "a.b", "a:b", strings.Repeat("a", 65)} {
		if !errors.Is(CheckVar(key, "x"), ErrBadVarKey) {
			t.Errorf("variable %q accepted", key)
		}
	}
	for _, key := range []string{
		"ansible_host", "ANSIBLE_USER", "ansible_ssh_private_key_file", "ansible_password",
		"ansible_ssh_common_args", "ansible_ssh_extra_args", "ansible_connection",
		"ansible_python_interpreter", "ansible_shell_executable",
		"ansible_become", "ansible_become_exe", "ansible_become_user",
		"ansible_become_flags", "ansible_become_method", "ansible_become_pass", "ansible_become_password",
		"im_roles", "im_access", "im_access_remove", "IM_CUSTOM",
		"secret_db_pass", "SECRET_TOKEN",
	} {
		if err := CheckVar(key, "x"); err == nil || !strings.Contains(err.Error(), "sets") {
			t.Errorf("%q: %v (reserved namespace)", key, err)
		}
	}
	// Normal variables (including ones containing "ansible" not as a prefix) are fine.
	for _, okKey := range []string{"nginx_port", "app_env", "my_ansible_note"} {
		if err := CheckVar(okKey, "value"); err != nil {
			t.Errorf("%q: %v", okKey, err)
		}
	}
	if !errors.Is(CheckVar("a", strings.Repeat("x", 1001)), ErrVarValue) || !errors.Is(CheckVar("a", "x\x00y"), ErrVarValue) {
		t.Error("a bad value was accepted")
	}
	if err := CheckVars([]Var{{"a", "1"}, {"b", "2"}, {"a", "3"}}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate: %v", err)
	}
}

func TestRenderRefusesWhatCouldBreakTheFiles(t *testing.T) {
	bad := func(mutate func(*Input)) {
		t.Helper()
		in := sampleInput()
		mutate(&in)
		if _, err := Render(in); err == nil {
			t.Error("Render accepted input that cannot go in a file")
		}
	}
	bad(func(in *Input) { in.Hosts[0].Name = "web\n[all:vars]" })
	bad(func(in *Input) { in.Hosts[0].Address = "10.0.0.1 ansible_user=root" })
	bad(func(in *Input) { in.Hosts[0].User = "a b" })
	bad(func(in *Input) { in.Hosts[0].Port = 0 })
	bad(func(in *Input) { in.Groups[0].Name = "web]\n[all" })
	bad(func(in *Input) { in.KeyPath = "/data dir/keys/id_ed25519" })
	bad(func(in *Input) { in.KnownHostsPath = "" })
	bad(func(in *Input) { in.Hosts[0].Vars = []Var{{"ansible_become_exe", "/bin/sh"}} })
	bad(func(in *Input) { in.Hosts[0].Vars = []Var{{"im_access", "[]"}} })
	bad(func(in *Input) { in.Groups[0].Vars = []Var{{"ansible_python_interpreter", "/bin/sh"}} })
}

func TestWriteIsPrivateAtomicAndTidy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ansible")
	files, err := Render(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, files); err != nil {
		t.Fatal(err)
	}
	for path, text := range files {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil || string(got) != text {
			t.Errorf("%s: %q %v", path, got, err)
		}
		if runtime.GOOS != "windows" {
			if info, _ := os.Stat(filepath.Join(dir, filepath.FromSlash(path))); info.Mode().Perm() != 0o600 {
				t.Errorf("%s has mode %04o, want 0600", path, info.Mode().Perm())
			}
		}
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
			t.Errorf("the folder has mode %04o, want 0700", info.Mode().Perm())
		}
	}

	// Something of somebody else's in the folder is left alone (a folder the
	// dashboard does not manage: the generated ones are group_vars, host_vars,
	// roles and custom), a role file this version does not have is removed (the
	// roles folder is the dashboard's), and an old temporary file is cleaned up.
	if err := os.MkdirAll(filepath.Join(dir, "other", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other", "x", "main.yml"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "roles", "old"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "roles", "old", "main.yml"), []byte("from an older version"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "group_vars", ".tmp-old"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A custom playbook that is no longer in the input goes, like a deleted group's variables.
	if err := os.WriteFile(filepath.Join(dir, "custom", "stale.yml"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The group is gone and the host has no variables any more: their files go.
	in := sampleInput()
	in.Groups = in.Groups[1:]
	in.Hosts[1].Vars = nil
	files, err = Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, files); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"group_vars/web.yml", "host_vars/web-1.yml", "group_vars/.tmp-old", "roles/old/main.yml", "custom/stale.yml"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(gone))); err == nil {
			t.Errorf("%s is still there", gone)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "other", "x", "main.yml")); string(data) != "keep" {
		t.Error("a file that is not the dashboard's was touched")
	}
	if _, err := os.Stat(filepath.Join(dir, "roles", "base", "tasks", "main.yml")); err != nil {
		t.Errorf("a role of the library is not there: %v", err)
	}
	inv, _ := os.ReadFile(filepath.Join(dir, "inventory.ini"))
	if strings.Contains(string(inv), "[web]") {
		t.Errorf("the inventory still has the group:\n%s", inv)
	}
	// Nothing temporary is left in the places the dashboard writes to.
	for _, sub := range []string{".", "group_vars", "host_vars"} {
		entries, _ := os.ReadDir(filepath.Join(dir, sub))
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".tmp-") {
				t.Errorf("%s/%s was left behind", sub, e.Name())
			}
		}
	}
}

func TestReadListsTheFilesInTheOrderOfReading(t *testing.T) {
	dir := t.TempDir()
	files, err := Render(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, files); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".tmp-x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A folder the dashboard does not write to is not listed; custom/ is.
	if err := os.MkdirAll(filepath.Join(dir, "other"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other", "mine.yml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "custom", "mine.yml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range got {
		paths = append(paths, f[0])
	}
	// The settings, the inventory, the playbooks, the variables, the custom
	// playbooks, then the roles.
	want := []string{"ansible.cfg", "inventory.ini", "access.yml", "patch.yml", "site.yml", "group_vars/all.yml", "group_vars/web.yml", "host_vars/web-1.yml", "custom/mine.yml"}
	if len(paths) <= len(want) || strings.Join(paths[:len(want)], " ") != strings.Join(want, " ") {
		t.Fatalf("paths: %v\nwant first %v", paths, want)
	}
	for _, p := range paths[len(want):] {
		if !strings.HasPrefix(p, "roles/") {
			t.Errorf("%s is not a role file (and nothing else should be listed: hidden and unmanaged files are left out)", p)
		}
	}
}

func TestRunnerCommands(t *testing.T) {
	r := NewRunner("/var/lib/infra-manager/ansible")
	c, err := r.PingCmd("web")
	if err != nil {
		t.Fatal(err)
	}
	shown := c.Shown()
	if shown.Command != "ansible web -m ping" || shown.Extra != "-o" {
		t.Errorf("shown: %+v", shown)
	}
	if c.Dir != r.Dir {
		t.Errorf("it runs in %q", c.Dir)
	}
	foundCfg := false
	for _, e := range c.Env {
		if e == "ANSIBLE_CONFIG="+filepath.Join(r.Dir, "ansible.cfg") {
			foundCfg = true
		}
	}
	if !foundCfg {
		t.Errorf("Ansible would read some other config: %v", c.Env)
	}
	if f, err := r.FactsCmd("web-1"); err != nil || f.Shown().Command != "ansible web-1 -m setup" {
		t.Errorf("facts: %+v %v", f.Shown(), err)
	}
	for _, bad := range []string{"", "-m shell", "web;id", "a b", "web\n", "$(id)", "--version"} {
		if _, err := r.PingCmd(bad); !errors.Is(err, ErrBadTarget) {
			t.Errorf("target %q accepted", bad)
		}
	}
}

func TestVersionOfAnsibleThatIsNotThere(t *testing.T) {
	r := Runner{Dir: t.TempDir(), Bin: "ansible-that-does-not-exist"}
	if v := r.Version(); v != "" {
		t.Errorf("version %q", v)
	}
}
