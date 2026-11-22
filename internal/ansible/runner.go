package ansible

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"infra-manager/internal/run"
)

// InstallHint is what the page says when Ansible is not on the machine.
const InstallHint = "Ansible is not installed on the machine the dashboard runs on. Install it with:  sudo apt install -y ansible openssh-client"

// Runner starts Ansible's programs in the dashboard's generated directory. The
// arguments are passed one by one, never through a shell (internal/run).
type Runner struct {
	Dir         string // the generated directory: ansible.cfg, inventory.ini, ...
	Bin         string // the ansible program; a field so a test can point it at a stand-in
	PlaybookBin string // ansible-playbook, likewise
	VaultBin    string // ansible-vault
}

func NewRunner(dir string) Runner {
	return Runner{Dir: dir, Bin: "ansible", PlaybookBin: "ansible-playbook", VaultBin: "ansible-vault"}
}

// env makes Ansible read the dashboard's own ansible.cfg, and nothing else's: the
// ANSIBLE_CONFIG variable wins over every other place a config is looked for.
func (r Runner) env() []string {
	return []string{
		"ANSIBLE_CONFIG=" + filepath.Join(r.Dir, "ansible.cfg"),
		"ANSIBLE_NOCOLOR=1",
		"ANSIBLE_FORCE_COLOR=0",
		"ANSIBLE_DEPRECATION_WARNINGS=False",
		// Python holds back what it prints when it is not a terminal, which would
		// make a live log arrive in lumps at the end.
		"PYTHONUNBUFFERED=1",
	}
}

// PlaybookCmd is "ansible-playbook site.yml --limit <hosts> [--tags <role>]", as a
// dry run (--check --diff: what would change, with the file diffs) or for real.
// limit is the hosts to configure, by name. A role, if given, is run alone.
func (r Runner) PlaybookCmd(limit []string, role string, check bool) (run.Command, error) {
	return r.PlaybookRun("site.yml", limit, role, check)
}

// playbookRe is a playbook the dashboard may start: its own three, or a custom
// one in custom/.
var playbookRe = regexp.MustCompile(`^(site|patch|access)\.yml$|^custom/[a-z][a-z0-9_-]{0,40}\.yml$`)

// PlaybookRun is PlaybookCmd for any of the playbooks.
func (r Runner) PlaybookRun(playbook string, limit []string, role string, check bool) (run.Command, error) {
	if !playbookRe.MatchString(playbook) {
		return run.Command{}, errors.New("That is not a playbook the dashboard runs.")
	}
	if len(limit) == 0 {
		return run.Command{}, errors.New("There is no host to configure.")
	}
	for _, name := range limit {
		if !nameRe.MatchString(name) {
			return run.Command{}, ErrBadTarget
		}
	}
	args := []any{playbook, "--limit", strings.Join(limit, ",")}
	if role != "" {
		if _, ok := FindRole(role); !ok {
			return run.Command{}, errors.New("There is no such role.")
		}
		args = append(args, "--tags", role)
	}
	if check {
		args = append(args, "--check", "--diff")
	}
	c := run.New(r.Dir, r.PlaybookBin, args...)
	c.Env = r.env()
	return c, nil
}

// Version is the first line of "ansible --version", or "" when Ansible is not
// there.
func (r Runner) Version() string {
	res, err := run.Output(run.New("", r.Bin, "--version"), 10*time.Second)
	if err != nil || res.Exit != 0 {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(res.Stdout), "\n")
	return line
}

// ErrBadTarget: a host or group name that could not go on a command line.
var ErrBadTarget = errors.New("That is not a host or group name.")

// PingCmd is "ansible <target> -m ping": log in the way Ansible does, with
// Python, and answer pong. It proves the Ansible path, which the dashboard's own
// SSH check does not. -o gives one line per host, which is simple to read; it is
// marked as an extra, so the page shows it muted.
func (r Runner) PingCmd(target string) (run.Command, error) {
	return r.command(target, "ping")
}

// SyntaxCheckCmd is "ansible-playbook <playbook> --syntax-check": does it parse.
func (r Runner) SyntaxCheckCmd(playbook string) (run.Command, error) {
	if !playbookRe.MatchString(playbook) {
		return run.Command{}, errors.New("That is not a playbook the dashboard runs.")
	}
	c := run.New(r.Dir, r.PlaybookBin, playbook, "--syntax-check")
	c.Env = r.env()
	return c, nil
}

// FactsCmd is "ansible <host> -m setup": everything Ansible knows about a host.
func (r Runner) FactsCmd(host string) (run.Command, error) {
	return r.command(host, "setup")
}

func (r Runner) command(target, module string) (run.Command, error) {
	// A name starting with "-" would be read as an option. The names come from
	// the database, where they were checked; this is the last look.
	if !nameRe.MatchString(target) {
		return run.Command{}, ErrBadTarget
	}
	c := run.New(r.Dir, r.Bin, target, "-m", module, run.Extra("-o"))
	c.Env = r.env()
	return c, nil
}
