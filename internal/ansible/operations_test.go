package ansible

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Operations at scale (IM6): rolling playbooks, patching, access, secrets and
// custom playbooks, as the files and commands the dashboard makes of them.

func TestRollingIsWrittenIntoEveryPlaybookOrNone(t *testing.T) {
	rolling := "  serial: 2\n  max_fail_percentage: 0\n"
	for _, serial := range []int{0, 2} {
		in := sampleInput()
		in.Serial = serial
		files, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"site.yml", "patch.yml", "access.yml"} {
			got := strings.Contains(files[p], "serial")
			if got != (serial > 0) {
				t.Errorf("%s with serial %d:\n%s", p, serial, files[p])
			}
			if serial > 0 && !strings.Contains(files[p], rolling) {
				t.Errorf("%s is not rolling:\n%s", p, files[p])
			}
		}
	}
	// "serial" is a number written by the dashboard, never text from outside.
	files, _ := Render(Input{KeyPath: "/k", KnownHostsPath: "/h", Serial: 3})
	if !strings.Contains(files["patch.yml"], "  serial: 3\n") {
		t.Errorf("patch.yml:\n%s", files["patch.yml"])
	}
}

func TestPatchPlaybookRefreshesThenUpgradesSafely(t *testing.T) {
	files, _ := Render(sampleInput())
	patch := files["patch.yml"]
	for _, want := range []string{"hosts: all", "become: true", "update_cache: true", "upgrade: safe"} {
		if !strings.Contains(patch, want) {
			t.Errorf("patch.yml has no %q:\n%s", want, patch)
		}
	}
	// "dist" and "full" can remove packages; the dashboard does not offer them.
	if strings.Contains(patch, "upgrade: dist") || strings.Contains(patch, "upgrade: full") {
		t.Errorf("an upgrade that can remove packages:\n%s", patch)
	}
}

func TestAccessIsInTheHostVarsAndTheAccessPlaybook(t *testing.T) {
	in := sampleInput()
	in.Access = map[string]HostAccess{
		"web-1": {
			Add:    []AccessKey{{Name: "Dewi", Key: "ssh-ed25519 AAAAdewi", User: "deploy"}},
			Remove: []AccessKey{{Name: "Budi", Key: "ssh-ed25519 AAAAbudi", User: "deploy"}},
		},
		"db-1": {Remove: []AccessKey{{Name: "Budi", Key: "ssh-ed25519 AAAAbudi", User: "root"}}},
	}
	files, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	vars := files["host_vars/web-1.yml"]
	if !strings.Contains(vars, `im_access: [{name: "Dewi", key: "ssh-ed25519 AAAAdewi", user: "deploy"}]`) ||
		!strings.Contains(vars, `im_access_remove: [{name: "Budi", key: "ssh-ed25519 AAAAbudi", user: "deploy"}]`) {
		t.Errorf("host_vars/web-1.yml:\n%s", vars)
	}
	// A host with only something to take away still gets a file (it had none).
	if !strings.Contains(files["host_vars/db-1.yml"], `im_access: []`) {
		t.Errorf("host_vars/db-1.yml:\n%s", files["host_vars/db-1.yml"])
	}
	if _, ok := files["host_vars/web-2.yml"]; ok {
		t.Error("a host with nothing to do got a file")
	}
	access := files["access.yml"]
	// Taking away comes before giving, and both use the real module.
	if !strings.Contains(access, "ansible.posix.authorized_key") || strings.Index(access, "state: absent") > strings.Index(access, "state: present") || !strings.Contains(access, "become: true") {
		t.Errorf("access.yml:\n%s", access)
	}

	// What goes into a file is checked once more here: nothing that could break out of a YAML string.
	for _, bad := range []AccessKey{
		{Name: "Dewi", Key: "ssh-ed25519 AAAA", User: "$(id)"},
		{Name: "De\nwi", Key: "ssh-ed25519 AAAA", User: "deploy"},
		{Name: "Dewi", Key: "ssh-ed25519 AAAA", User: "dep loy"},
		{Name: "Dewi", Key: "ssh-ed25519 AAAA\nssh-rsa BBBB", User: "deploy"},
	} {
		in.Access = map[string]HostAccess{"web-1": {Add: []AccessKey{bad}}}
		if _, err := Render(in); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestSecretsAreWrittenAsVaultValuesAndTheirNamesAreChecked(t *testing.T) {
	in := sampleInput()
	in.VaultPasswordPath = "/var/lib/infra-manager/secrets/vault_password"
	in.Secrets = map[string]string{
		"db_pass":   "$ANSIBLE_VAULT;1.1;AES256\n6162\n6364",
		"api_token": "$ANSIBLE_VAULT;1.1;AES256\n6566",
	}
	files, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files["ansible.cfg"], "vault_password_file = /var/lib/infra-manager/secrets/vault_password\n") {
		t.Errorf("ansible.cfg:\n%s", files["ansible.cfg"])
	}
	all := files["group_vars/all.yml"]
	// Sorted by name, each a !vault block, each line indented under it.
	i, j := strings.Index(all, "secret_api_token: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6566\n"), strings.Index(all, "secret_db_pass: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162\n  6364\n")
	if i < 0 || j < 0 || i > j || !strings.Contains(all, "im_roles: []") {
		t.Errorf("group_vars/all.yml:\n%s", all)
	}
	// Without a vault password there is no setting for it.
	in.VaultPasswordPath = ""
	if files, _ = Render(in); strings.Contains(files["ansible.cfg"], "vault_password_file") {
		t.Error("a vault password file without a path")
	}
	in.VaultPasswordPath = "/var/lib/a b/vault"
	if _, err := Render(in); err == nil {
		t.Error("a path with a space in ansible.cfg was accepted")
	}

	for name, ok := range map[string]bool{
		"db_pass": true, "a": true, "x_1": true, "": false, "Db": false, "1a": false, "a-b": false, "a b": false,
		strings.Repeat("a", 33): false, "a\nb": false, "../x": false,
	} {
		if (CheckSecretName(name) == nil) != ok {
			t.Errorf("CheckSecretName(%q) = %v", name, CheckSecretName(name))
		}
	}
	for value, ok := range map[string]bool{
		"hunter2": true, "with spaces and \"quotes\"": true, "": false, "two\nlines": false, "cr\rlf": false, "nul\x00": false,
		strings.Repeat("a", 3001): false,
	} {
		if (CheckSecretValue(value) == nil) != ok {
			t.Errorf("CheckSecretValue(%q) = %v", value, CheckSecretValue(value))
		}
	}
	if name, ok := SecretRef("secret:db_pass"); !ok || name != "db_pass" {
		t.Errorf("SecretRef: %q %v", name, ok)
	}
	for _, v := range []string{"secret:", "secret:Db", "Secret:db", " secret:db", "secret:db ", "secret:a-b", "db_pass"} {
		if _, ok := SecretRef(v); ok {
			t.Errorf("%q is a reference", v)
		}
	}
	if SecretVar("db_pass") != "secret_db_pass" {
		t.Error("SecretVar")
	}
}

func TestParseVaultBlockReadsWhatAnsibleVaultPrints(t *testing.T) {
	real := "secret_db_pass: !vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          61626364\n          65666768\n\n"
	got, err := ParseVaultBlock(real)
	if err != nil || got != "$ANSIBLE_VAULT;1.1;AES256\n61626364\n65666768" {
		t.Errorf("parse: %q %v", got, err)
	}
	// Without the trailing blank line, and with Windows line ends.
	if got, err = ParseVaultBlock(strings.ReplaceAll(strings.TrimSuffix(real, "\n\n"), "\n", "\r\n")); err != nil || !strings.HasPrefix(got, "$ANSIBLE_VAULT;1.1;AES256\n") {
		t.Errorf("parse without the end: %q %v", got, err)
	}
	for _, bad := range []string{
		"", "nothing here\n", "x: !vault |\n", "x: !vault |\n  not a vault header\n  6162\n",
		"x: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n", "x: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  61 62\n",
	} {
		if got, err := ParseVaultBlock(bad); err == nil {
			t.Errorf("%q gave %q", bad, got)
		}
	}
}

func TestTheVaultPasswordIsMadeOnceAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "vault_password")
	if err := EnsureVaultPassword(path); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil || len(strings.TrimSpace(string(first))) < 64 {
		t.Fatalf("the password: %q %v", first, err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("the file is %v", info.Mode().Perm())
		}
		if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
			t.Errorf("the folder is %v", info.Mode().Perm())
		}
	}
	// Making it again must not replace it: every stored secret would be lost.
	if err := EnsureVaultPassword(path); err != nil {
		t.Fatal(err)
	}
	if second, _ := os.ReadFile(path); string(second) != string(first) {
		t.Error("the vault password was replaced")
	}
}

func TestTheValueOfASecretIsNeverOnACommandLine(t *testing.T) {
	r := NewRunner("/var/lib/infra-manager/ansible")
	const value = "s3cr3t-Value"
	c, err := r.EncryptCmd("/var/lib/infra-manager/secrets/vault_password", "db_pass", value)
	if err != nil {
		t.Fatal(err)
	}
	shown := c.Shown()
	if strings.Contains(shown.Command, value) || strings.Contains(c.Line(), value) {
		t.Errorf("the value is on the command line: %s", c.Line())
	}
	if shown.Command != "ansible-vault encrypt_string --vault-password-file /var/lib/infra-manager/secrets/vault_password --stdin-name secret_db_pass" {
		t.Errorf("command: %s", shown.Command)
	}
	if c.Stdin != value {
		t.Errorf("the value is not on standard input: %q", c.Stdin)
	}
	if _, err := r.EncryptCmd("/p", "Bad Name", value); err == nil {
		t.Error("a bad name was accepted")
	}
}

func TestEncryptDoesNotPassTheValueOnInAnError(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil || runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nvalue=$(cat)\necho \"ERROR! cannot encrypt $value\" >&2\nexit 1\n"
	bin := filepath.Join(dir, "ansible-vault")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(dir)
	r.VaultBin = bin
	const value = "s3cr3t-Value-42"
	_, err := r.Encrypt(filepath.Join(dir, "pw"), "db_pass", value)
	if err == nil || strings.Contains(err.Error(), value) || !strings.Contains(err.Error(), "cannot encrypt") {
		t.Errorf("error: %v", err)
	}
}

func TestPlaybooksTheDashboardMayRun(t *testing.T) {
	r := NewRunner("/var/lib/infra-manager/ansible")
	for _, ok := range []string{"site.yml", "patch.yml", "access.yml", "custom/tune.yml", "custom/a-b_1.yml"} {
		c, err := r.PlaybookRun(ok, []string{"web-1"}, "", false)
		if err != nil || c.Shown().Command != "ansible-playbook "+ok+" --limit web-1" {
			t.Errorf("%s: %v %v", ok, c.Shown(), err)
		}
	}
	for _, bad := range []string{"", "other.yml", "custom/../site.yml", "custom/Tune.yml", "custom/a/b.yml", "/etc/x.yml", "-x", "custom/tune.yml; id", "custom/.yml", "custom/tune.yaml", "site.yml --check"} {
		if _, err := r.PlaybookRun(bad, []string{"web-1"}, "", false); err == nil {
			t.Errorf("%q was accepted", bad)
		}
		if _, err := r.SyntaxCheckCmd(bad); err == nil {
			t.Errorf("%q was accepted for a syntax check", bad)
		}
	}
	if _, err := r.PlaybookRun("patch.yml", nil, "", false); err == nil {
		t.Error("a run on no hosts was accepted")
	}
	if _, err := r.PlaybookRun("patch.yml", []string{"-evil"}, "", false); err == nil {
		t.Error("a host name that looks like an option was accepted")
	}
	c, err := r.SyntaxCheckCmd("custom/tune.yml")
	if err != nil || c.Shown().Command != "ansible-playbook custom/tune.yml --syntax-check" {
		t.Errorf("syntax check: %v %v", c.Shown(), err)
	}
	// The playbook of the profiles still takes a role and a dry run.
	c, _ = r.PlaybookCmd([]string{"web-1"}, "nginx", true)
	if c.Shown().Command != "ansible-playbook site.yml --limit web-1 --tags nginx --check --diff" {
		t.Errorf("site.yml: %s", c.Shown().Command)
	}
}

func TestCustomPlaybooksAreWrittenUnderCustom(t *testing.T) {
	in := sampleInput()
	in.Playbooks = map[string]string{"tune": "- hosts: all\n  tasks: []\n"}
	files, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if files["custom/tune.yml"] != "- hosts: all\n  tasks: []\n" {
		t.Errorf("custom/tune.yml: %q", files["custom/tune.yml"])
	}
	for _, bad := range []string{"../x", "Tune", "a/b", "", "a b", strings.Repeat("a", 42)} {
		in.Playbooks = map[string]string{bad: "x"}
		if _, err := Render(in); err == nil {
			t.Errorf("the name %q was accepted", bad)
		}
		if bad != "" && CheckPlaybookName(bad) == nil {
			t.Errorf("CheckPlaybookName accepted %q", bad)
		}
	}
	if CheckPlaybookName("tune") != nil || CheckPlaybookName("a-b_1") != nil {
		t.Error("a good name was refused")
	}
}

func TestAccessInputIsChecked(t *testing.T) {
	good := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample"
	for _, key := range []string{good, good + " dewi@laptop", "ssh-rsa AAAAB3NzaC1yc2E=", "ecdsa-sha2-nistp256 AAAAE2VjZHNh"} {
		if err := CheckSSHKey(key); err != nil {
			t.Errorf("%q: %v", key, err)
		}
	}
	for _, key := range []string{"", "ssh-ed25519", "AAAA", good + "\nssh-rsa AAAA", "command=\"id\" " + good, "ssh-dss AAAA", "ssh-ed25519 AAAA$(id)", good + strings.Repeat("a", 900)} {
		if CheckSSHKey(key) == nil {
			t.Errorf("%q was accepted", key)
		}
	}
	for name, ok := range map[string]bool{"Dewi": true, "Dewi S. (laptop)": false, "dewi@example.com": true, "a b": true, "": false, " x": false, "a\nb": false, `a"b`: false, strings.Repeat("a", 65): false} {
		if (CheckAccessName(name) == nil) != ok {
			t.Errorf("CheckAccessName(%q) = %v", name, CheckAccessName(name))
		}
	}
	for user, ok := range map[string]bool{"": true, "deploy": true, "_x": true, "a.b-c": true, "1a": false, "a b": false, "a;b": false, "$(id)": false} {
		if (CheckAccessUser(user) == nil) != ok {
			t.Errorf("CheckAccessUser(%q) = %v", user, CheckAccessUser(user))
		}
	}
}

func TestSecretParametersTakeOnlyAReference(t *testing.T) {
	nginx, _ := FindRole("nginx")
	var token Param
	for _, p := range nginx.Params {
		if p.Key == "nginx_proxy_token" {
			token = p
		}
	}
	if !token.Secret {
		t.Fatal("the proxy token is not a secret parameter")
	}
	const typed = "Bearer-s3cr3t-typed-here"
	if _, err := nginx.Resolve(map[string]any{"nginx_proxy_token": typed}); err == nil || strings.Contains(err.Error(), typed) {
		t.Errorf("a typed value: %v", err)
	}
	for _, ok := range []string{"", "secret:api_token"} {
		if _, err := nginx.Resolve(map[string]any{"nginx_proxy_token": ok}); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	if _, err := nginx.Resolve(map[string]any{"nginx_proxy_token": "secret:Bad Name"}); err == nil {
		t.Error("a reference to a name that cannot exist was accepted")
	}

	// The reference reaches the host's variables as the secret's variable, and the
	// fingerprint of the role follows the secret's version, not only the reference.
	own := []ProfileRole{{Role: "nginx", Params: map[string]any{"nginx_proxy_token": "secret:api_token"}}}
	v1, err := BuildPlanWith(nil, own, map[string]string{"api_token": "aaa"})
	if err != nil {
		t.Fatal(err)
	}
	v1again, _ := BuildPlanWith(nil, own, map[string]string{"api_token": "aaa"})
	v2, _ := BuildPlanWith(nil, own, map[string]string{"api_token": "bbb"})
	if v1.Hashes["nginx"] != v1again.Hashes["nginx"] || v1.Hashes["nginx"] == v2.Hashes["nginx"] {
		t.Errorf("hashes: %s %s %s", v1.Hashes["nginx"], v1again.Hashes["nginx"], v2.Hashes["nginx"])
	}
	// A role without a secret does not depend on secrets' versions.
	plain := []ProfileRole{{Role: "base", Params: map[string]any{}}}
	p1, _ := BuildPlanWith(nil, plain, map[string]string{"api_token": "aaa"})
	p2, _ := BuildPlanWith(nil, plain, map[string]string{"api_token": "bbb"})
	if p1.Hashes["base"] != p2.Hashes["base"] {
		t.Error("a role that uses no secret changed with one")
	}

	in := sampleInput()
	in.Plans = map[string]HostPlan{"web-1": v1}
	files, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if vars := files["host_vars/web-1.yml"]; !strings.Contains(vars, `nginx_proxy_token: "{{ secret_api_token }}"`) {
		t.Errorf("host_vars/web-1.yml:\n%s", vars)
	}
	// A variable of the same kind: "secret:name" is the secret too.
	in.Groups[0].Vars = []Var{{"token", "secret:api_token"}}
	files, _ = Render(in)
	if !strings.Contains(files["group_vars/web.yml"], `token: "{{ secret_api_token }}"`) {
		t.Errorf("group_vars/web.yml:\n%s", files["group_vars/web.yml"])
	}
}

func TestTheNginxRoleKeepsAProxyTokenOutOfWorldReadableFilesAndOutOfLogs(t *testing.T) {
	files := RoleFiles()
	tasks := files["roles/nginx/tasks/main.yml"]
	if !strings.Contains(tasks, "no_log:") || !strings.Contains(tasks, "0600") {
		t.Errorf("the site task:\n%s", tasks)
	}
	if !strings.Contains(tasks, "ansible.builtin.assert:") || !strings.Contains(tasks, "nginx_proxy_token is not search") {
		t.Errorf("nginx tasks missing proxy token character assertion:\n%s", tasks)
	}
	tpl := files["roles/nginx/templates/site.conf.j2"]
	if !strings.Contains(tpl, "nginx_proxy_token") || !strings.Contains(tpl, "regex_replace") {
		t.Errorf("the template does not guard the proxy token:\n%s", tpl)
	}
}
