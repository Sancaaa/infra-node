package remote

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"infra-manager/internal/remote/remotetest"
)

// ------------------------------------------------------------ pure functions

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"":              `''`,
		"plain":         `'plain'`,
		"two words":     `'two words'`,
		"it's":          `'it'\''s'`,
		"$(id)":         `'$(id)'`,
		"`id`":          "'`id`'",
		"a;b && c | d":  `'a;b && c | d'`,
		"line1\nline2":  "'line1\nline2'",
		`back\slash`:    `'back\slash'`,
		`"double"`:      `'"double"'`,
		"*.txt ~ #":     `'*.txt ~ #'`,
		"-rf /":         `'-rf /'`,
		"'; rm -rf /;'": `''\''; rm -rf /;'\'''`,
	}
	for in, want := range cases {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// What a quoting function has to do is give back exactly what went in, after a
// real shell has read it.
func TestShellQuoteSurvivesARealShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh here")
	}
	values := []string{"", "plain", "two  words", "it's", "$(echo pwned)", "`echo pwned`", "$HOME", "a;b", "a|b", "a&b",
		"line1\nline2", `back\slash`, `"quoted"`, "*", "~", "#comment", "-n", "é ü 日本", "'; echo pwned; '"}
	for _, v := range values {
		out, err := exec.Command("sh", "-c", "printf %s "+ShellQuote(v)).Output()
		if err != nil || string(out) != v {
			t.Errorf("a shell read %q back as %q (%v)", v, out, err)
		}
	}
}

func TestShellQuoteRefusesNUL(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a NUL byte was quoted")
		}
	}()
	ShellQuote("a\x00b")
}

func TestShellCommand(t *testing.T) {
	got := shellCommand("sudo -S -p '' ", `echo "$1"`, []string{"it's", "b c"})
	want := `sudo -S -p '' sh -c 'echo "$1"' sh 'it'\''s' 'b c'`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if got := shellCommand("", "true", nil); got != "sh -c 'true' sh" {
		t.Errorf("no arguments: %s", got)
	}
}

func TestChecks(t *testing.T) {
	good := func(err error) bool { return err == nil }
	for _, n := range []string{"web-1", "db.lab", "a", "x_y-z.9"} {
		if !good(CheckName(n)) {
			t.Errorf("name %q refused", n)
		}
	}
	for _, n := range []string{"", "Web", "-web", ".web", "a b", "a;b", "a/b", strings.Repeat("a", 64), "web\n"} {
		if good(CheckName(n)) {
			t.Errorf("name %q accepted", n)
		}
	}
	for _, a := range []string{"10.0.0.5", "web-1.lab.example", "localhost", "::1", "2001:db8::1", "a"} {
		if !good(CheckAddress(a)) {
			t.Errorf("address %q refused", a)
		}
	}
	for _, a := range []string{"", "-oProxyCommand=x", "a b", "a;b", "a$(id)", "fe80::1%eth0", "a..b", "-a", "a-", "a/b", "http://x", "x\n"} {
		if good(CheckAddress(a)) {
			t.Errorf("address %q accepted", a)
		}
	}
	for _, u := range []string{"root", "deploy", "john.doe", "_apt", "a-b"} {
		if !good(CheckUser(u)) {
			t.Errorf("user %q refused", u)
		}
	}
	for _, u := range []string{"", "Root", "1abc", "a b", "a;b", "$(id)", "a/b", strings.Repeat("a", 33), "-x"} {
		if good(CheckUser(u)) {
			t.Errorf("user %q accepted", u)
		}
	}
	if CheckPort(22) != nil || CheckPort(65535) != nil || CheckPort(0) == nil || CheckPort(65536) == nil || CheckPort(-1) == nil {
		t.Error("port limits are wrong")
	}
}

// sudo ignores a sudoers.d file with a dot in its name, so a rule for "john.doe"
// would silently do nothing.
func TestSudoersFileHasNoDot(t *testing.T) {
	if got := sudoersPath("john.doe"); got != "/etc/sudoers.d/infra-manager-john_doe" {
		t.Errorf("got %s", got)
	}
	if got := sudoersPath("deploy"); got != "/etc/sudoers.d/infra-manager-deploy" {
		t.Errorf("got %s", got)
	}
	if text := sudoersText("john.doe"); !strings.HasSuffix(text, "\njohn.doe ALL=(ALL) NOPASSWD:ALL") {
		t.Errorf("rule: %q", text)
	}
}

func TestParseFacts(t *testing.T) {
	out := strings.Join([]string{
		"hostname=web-1",
		"os=Debian GNU/Linux 12 (bookworm)",
		"kernel=Linux 6.1.0-18-amd64",
		"arch=x86_64",
		"cpus=4",
		"mem_kb=8147392",
		"uptime_s=93211",
		"disk=51474044 12345678 /",
		"disk=999 1 /mnt/with space",
		"disk=garbage",
		"ip=eth0 192.168.5.20/24",
		"ip=nonsense",
		"some warning from a login script",
	}, "\n")
	f := ParseFacts(out)
	if f.Hostname != "web-1" || f.OS != "Debian GNU/Linux 12 (bookworm)" || f.Kernel != "Linux 6.1.0-18-amd64" || f.Arch != "x86_64" {
		t.Errorf("text facts: %+v", f)
	}
	if f.CPUs != 4 || f.MemKB != 8147392 || f.UptimeS != 93211 {
		t.Errorf("number facts: %+v", f)
	}
	if len(f.Disks) != 2 || f.Disks[0] != (Disk{Mount: "/", Size: 51474044 * 1024, Used: 12345678 * 1024}) || f.Disks[1].Mount != "/mnt/with space" {
		t.Errorf("disks: %+v", f.Disks)
	}
	if len(f.IPs) != 1 || f.IPs[0] != (IP{Interface: "eth0", CIDR: "192.168.5.20/24"}) {
		t.Errorf("ips: %+v", f.IPs)
	}
	if empty := ParseFacts(""); empty.Disks == nil || empty.IPs == nil {
		t.Error("an empty answer should give empty lists, not nil (they are sent as JSON)")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		err    error
		status string
		says   string
	}{
		{&HostKeyChangedError{Address: "x:22", Presented: "SHA256:new", Known: []string{"SHA256:old"}}, StatusKeyChanged, "Trust the new key"},
		{errors.New("ssh: handshake failed: ssh: unable to authenticate"), StatusOffline, "handshake failed"},
		{wrapAuth(errors.New("ssh: unable to authenticate, attempted methods [none password], no supported methods remain"), ErrPasswordRejected), StatusAuthFailed, "user name and password"},
		{wrapAuth(errors.New("ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain"), ErrKeyRejected), StatusAuthFailed, "dashboard's key"},
		{errors.New("dial tcp 10.0.0.9:22: connect: connection refused"), StatusOffline, "Nothing answers"},
		{errors.New("dial tcp 10.0.0.9:22: i/o timeout"), StatusOffline, "did not answer in time"},
		{errors.New("dial tcp: lookup nope.invalid: no such host"), StatusOffline, "cannot be resolved"},
		{errors.New("something else entirely"), StatusOffline, "something else entirely"},
	}
	for _, c := range cases {
		p := Classify(c.err)
		if p.Status != c.status || !strings.Contains(p.Message, c.says) {
			t.Errorf("Classify(%v) = %+v, want status %s and %q", c.err, p, c.status, c.says)
		}
	}
	if p := Classify(&HostKeyChangedError{Presented: "SHA256:new"}); p.PresentedFP != "SHA256:new" {
		t.Errorf("the new key's fingerprint was not passed on: %+v", p)
	}
	// Only a refused login is an auth problem; wrapAuth leaves other errors alone.
	other := errors.New("connection reset")
	if wrapAuth(other, ErrKeyRejected) != other {
		t.Error("a network error was marked as a refused login")
	}
}

// ------------------------------------------------------------------ the key

func TestOpenMakesTheKeyOnceAndKeepsIt(t *testing.T) {
	dir := t.TempDir()
	r1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r1.PublicKey(), "ssh-ed25519 ") || !strings.HasSuffix(r1.PublicKey(), " infra-manager") {
		t.Errorf("public key line: %q", r1.PublicKey())
	}
	if !strings.HasPrefix(r1.Fingerprint(), "SHA256:") {
		t.Errorf("fingerprint: %q", r1.Fingerprint())
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]fs.FileMode{
			filepath.Join(dir, "keys"):                0o700,
			filepath.Join(dir, "keys", "id_ed25519"):  0o600,
			filepath.Join(dir, "keys", "known_hosts"): 0o600,
		} {
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != want {
				t.Errorf("%s: %v %v, want %04o", path, info, err, want)
			}
		}
	}

	r2, err := Open(dir)
	if err != nil || r2.Fingerprint() != r1.Fingerprint() {
		t.Errorf("a second start made another key: %v %v", err, r2)
	}
	// The private key is not in the public file.
	pub, _ := os.ReadFile(filepath.Join(dir, "keys", "id_ed25519.pub"))
	if bytes.Contains(pub, []byte("PRIVATE")) || strings.TrimSpace(string(pub)) != r1.PublicKey() {
		t.Errorf("public file: %q", pub)
	}
}

func TestOpenNeverOverwritesAKeyItCannotRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "keys", "id_ed25519")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("a broken key was accepted (or replaced)")
	}
	if data, _ := os.ReadFile(path); string(data) != "not a key" {
		t.Errorf("the file was overwritten: %q", data)
	}
}

// ------------------------------------------------------- against a real server

const testUser = "tester"

func newRemote(t *testing.T) (*Remote, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r, dir
}

func targetOf(s *remotetest.Server) Target {
	return Target{Address: s.Host, Port: s.Port, User: testUser}
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func knownHostsText(t *testing.T, r *Remote) string {
	t.Helper()
	data, err := os.ReadFile(r.KnownHostsPath())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func publicLineOf(t *testing.T, key ssh.Signer) string {
	t.Helper()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))) + " someone-else"
}

// "adding the same host twice keeps one copy of the key", with the real script,
// on a file that has another key and no newline at its end.
func TestEnrollWithAPasswordInstallsTheKeyOnce(t *testing.T) {
	r, _ := newRemote(t)
	home := t.TempDir()
	s := remotetest.Start(t, home, remotetest.Options{})

	other := publicLineOf(t, remotetest.NewHostKey(t))
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(other), 0o600); err != nil { // no newline
		t.Fatal(err)
	}

	for i := 1; i <= 2; i++ {
		res, err := r.Enroll(EnrollRequest{Target: targetOf(s), Password: s.Password}, true)
		if err != nil {
			t.Fatalf("enroll #%d: %v", i, err)
		}
		if res.HostKeyFP == "" || res.Facts.Arch == "" {
			t.Errorf("enroll #%d found nothing out: %+v", i, res)
		}
	}

	got := lines(s.AuthorizedKeys())
	if len(got) != 2 || got[0] != other || got[1] != r.PublicKey() {
		t.Fatalf("authorized_keys has %d lines after adding twice: %q", len(got), s.AuthorizedKeys())
	}
	if n := strings.Count(s.AuthorizedKeys(), r.PublicKey()); n != 1 {
		t.Errorf("the key is there %d times", n)
	}

	// Saved on first use, in OpenSSH's format, for this address and port.
	if kh := knownHostsText(t, r); !strings.Contains(kh, "["+s.Host+"]:"+strconv.Itoa(s.Port)+" ssh-ed25519 ") || len(lines(kh)) != 1 {
		t.Errorf("known_hosts: %q", kh)
	}
}

func TestEnrollKeepsNoPasswordOnDisk(t *testing.T) {
	r, dir := newRemote(t)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{Password: "a-very-distinct-password-7391"})
	if _, err := r.Enroll(EnrollRequest{Target: targetOf(s), Password: s.Password}, true); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if data, _ := os.ReadFile(path); bytes.Contains(data, []byte(s.Password)) {
			t.Errorf("the password is in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWrongPasswordLeavesNoTrace(t *testing.T) {
	r, _ := newRemote(t)
	home := t.TempDir()
	s := remotetest.Start(t, home, remotetest.Options{})

	_, err := r.Enroll(EnrollRequest{Target: targetOf(s), Password: "wrong"}, true)
	if !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("err = %v", err)
	}
	if Classify(err).Status != StatusAuthFailed {
		t.Errorf("status %s", Classify(err).Status)
	}
	if kh := knownHostsText(t, r); strings.TrimSpace(kh) != "" {
		t.Errorf("a failed add left a host key behind: %q", kh)
	}
	if s.AuthorizedKeys() != "" {
		t.Errorf("a failed add put a key on the host: %q", s.AuthorizedKeys())
	}
}

func TestEnrollByHandChecksTheKeyLogin(t *testing.T) {
	r, _ := newRemote(t)
	home := t.TempDir()
	s := remotetest.Start(t, home, remotetest.Options{})

	// The key is not on the host yet.
	_, err := r.Enroll(EnrollRequest{Target: targetOf(s)}, true)
	if !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("err = %v", err)
	}
	if kh := knownHostsText(t, r); strings.TrimSpace(kh) != "" {
		t.Errorf("a failed add left a host key behind: %q", kh)
	}

	// The person pastes the line the dialog showed.
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(r.PublicKey()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := r.Enroll(EnrollRequest{Target: targetOf(s)}, true)
	if err != nil || res.HostKeyFP == "" {
		t.Fatalf("after adding the key: %+v %v", res, err)
	}
}

func TestStrictRefusesAnUnknownHost(t *testing.T) {
	r, _ := newRemote(t)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	_, err := r.Check(targetOf(s))
	var unknown *UnknownHostKeyError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v", err)
	}
	if kh := knownHostsText(t, r); strings.TrimSpace(kh) != "" {
		t.Errorf("a strict connection saved a key: %q", kh)
	}
}

// "Reinstalling the VM (new host key) makes the dashboard refuse it with the
// warning until an admin trusts the new key."
func TestChangedHostKeyIsRefusedUntilTrusted(t *testing.T) {
	r, _ := newRemote(t)
	home := t.TempDir()
	first := remotetest.Start(t, home, remotetest.Options{})
	target := targetOf(first)
	if _, err := r.Enroll(EnrollRequest{Target: target, Password: first.Password}, true); err != nil {
		t.Fatal(err)
	}
	oldFP := r.mustSavedFingerprint(t, target)
	if _, err := r.Check(target); err != nil {
		t.Fatalf("an unchanged host: %v", err)
	}

	// The same address, a different machine: new host key. (The home, with the
	// dashboard's key in it, stays, so only the host key tells them apart.)
	first.Close()
	second := remotetest.Start(t, home, remotetest.Options{Port: first.Port})

	_, err := r.Check(target)
	var changed *HostKeyChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("a changed host key was accepted: %v", err)
	}
	if changed.Presented == oldFP || len(changed.Known) != 1 || changed.Known[0] != oldFP {
		t.Errorf("fingerprints: %+v (old %s)", changed, oldFP)
	}
	p := Classify(err)
	if p.Status != StatusKeyChanged || p.PresentedFP != changed.Presented {
		t.Errorf("classified as %+v", p)
	}
	// Every kind of connection refuses it, not only Check.
	if _, err := r.Enroll(EnrollRequest{Target: target}, false); !errors.As(err, &changed) {
		t.Errorf("Enroll accepted it: %v", err)
	}
	// Even adding with a password, which would trust a host on first use: this
	// one is not new.
	if _, err := r.Enroll(EnrollRequest{Target: target, Password: second.Password}, true); !errors.As(err, &changed) {
		t.Errorf("Enroll with a password accepted it: %v", err)
	}

	// An admin looks at the fingerprint and trusts it. A different fingerprint than
	// the one they were shown is refused.
	if err := r.TrustNewKey(target, "SHA256:somethingelse"); !errors.Is(err, ErrKeyChangedAgain) {
		t.Errorf("TrustNewKey with the wrong fingerprint: %v", err)
	}
	if _, err := r.Check(target); !errors.As(err, &changed) {
		t.Fatalf("a refused TrustNewKey changed something: %v", err)
	}
	if err := r.TrustNewKey(target, changed.Presented); err != nil {
		t.Fatal(err)
	}
	res, err := r.Check(target)
	if err != nil || res.HostKeyFP != changed.Presented {
		t.Errorf("after trusting: %+v %v", res, err)
	}
	if n := len(lines(knownHostsText(t, r))); n != 1 {
		t.Errorf("known_hosts has %d lines, want the old one replaced", n)
	}
}

func (r *Remote) mustSavedFingerprint(t *testing.T, target Target) string {
	t.Helper()
	res, err := r.Check(target)
	if err != nil {
		t.Fatal(err)
	}
	return res.HostKeyFP
}

func TestRemoveKeyTakesOnlyTheDashboardsKey(t *testing.T) {
	r, _ := newRemote(t)
	home := t.TempDir()
	s := remotetest.Start(t, home, remotetest.Options{})
	other := publicLineOf(t, remotetest.NewHostKey(t))
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(other+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := targetOf(s)
	if _, err := r.Enroll(EnrollRequest{Target: target, Password: s.Password}, true); err != nil {
		t.Fatal(err)
	}

	if err := r.RemoveKey(target, false); err != nil {
		t.Fatal(err)
	}
	if got := lines(s.AuthorizedKeys()); len(got) != 1 || got[0] != other {
		t.Errorf("authorized_keys after removing: %q", s.AuthorizedKeys())
	}
	if _, err := r.Check(target); !errors.Is(err, ErrKeyRejected) {
		t.Errorf("the key still works: %v", err)
	}

	if err := r.Forget(target); err != nil {
		t.Fatal(err)
	}
	if kh := knownHostsText(t, r); strings.TrimSpace(kh) != "" {
		t.Errorf("Forget left %q", kh)
	}
}

func TestForgetOnlyRemovesThatAddress(t *testing.T) {
	r, _ := newRemote(t)
	a := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	b := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	for _, s := range []*remotetest.Server{a, b} {
		if _, err := r.Enroll(EnrollRequest{Target: targetOf(s), Password: s.Password}, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Forget(targetOf(a)); err != nil {
		t.Fatal(err)
	}
	kh := knownHostsText(t, r)
	if strings.Contains(kh, ":"+strconv.Itoa(a.Port)+" ") || !strings.Contains(kh, ":"+strconv.Itoa(b.Port)+" ") {
		t.Errorf("known_hosts: %q", kh)
	}
}
