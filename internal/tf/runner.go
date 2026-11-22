package tf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"infra-manager/internal/run"
)

// Runner builds the terraform commands that run inside Dir, with arguments
// passed separately (never through a shell).
type Runner struct {
	Bin        string // "terraform" by default
	Dir        string // <data>/terraform
	SecretFile string // <data>/secrets/proxmox.tfvars.json (0600)
}

func NewRunner(dir, secretFile string) Runner {
	return Runner{Bin: "terraform", Dir: dir, SecretFile: secretFile}
}

func (r Runner) Version() string {
	res, err := run.Output(run.New("", r.Bin, "version"), 10*time.Second)
	if err != nil || res.Exit != 0 {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(res.Stdout), "\n")
	return strings.TrimSpace(line)
}

func (r Runner) IsInitialized() bool {
	info, err := os.Stat(filepath.Join(r.Dir, ".terraform"))
	return err == nil && info.IsDir()
}

func (r Runner) InitCmd() run.Command {
	return run.New(r.Dir, r.Bin, "init", run.Extra("-input=false"), run.Extra("-no-color"))
}

// PlanCmd builds "terraform plan [extra...] -var-file=<secret> -out=<outPath>".
// Extra flags are used for -replace=..., -refresh-only, or -state=<backup>.
func (r Runner) PlanCmd(outPath string, flags ...string) run.Command {
	args := []any{"plan"}
	if len(flags) > 0 {
		args = append(args, flags)
	}
	args = append(args, "-var-file="+r.SecretFile, "-out="+outPath, run.Extra("-input=false"), run.Extra("-no-color"))
	return run.New(r.Dir, r.Bin, args...)
}

func (r Runner) ShowPlanCmd(planPath string) run.Command {
	return run.New(r.Dir, r.Bin, "show", run.Extra("-json"), run.Extra("-no-color"), planPath)
}

func (r Runner) ShowStateCmd() run.Command {
	return run.New(r.Dir, r.Bin, "show", run.Extra("-json"), run.Extra("-no-color"))
}

// ApplyCmd builds "terraform apply -input=false -no-color <planPath>".
func (r Runner) ApplyCmd(planPath string) run.Command {
	return run.New(r.Dir, r.Bin, "apply", run.Extra("-input=false"), run.Extra("-no-color"), planPath)
}

// ------------------------------------------------------------ state backups

// MaxStateBackups is how many state snapshots are kept under <Dir>/backups/.
const MaxStateBackups = 30

var backupIDRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}(-[0-9]+)?\.tfstate$`)

// StateBackup describes one saved snapshot of terraform.tfstate.
type StateBackup struct {
	ID        string `json:"id"`
	CreatedAt int64  `json:"created_at"`
	Size      int64  `json:"size"`
}

func backupsDir(dir string) string { return filepath.Join(dir, "backups") }

func CheckBackupID(id string) error {
	if !backupIDRe.MatchString(id) {
		return CheckError("Invalid state backup name.")
	}
	return nil
}

func BackupPath(dir, id string) (string, error) {
	if err := CheckBackupID(id); err != nil {
		return "", err
	}
	return filepath.Join(backupsDir(dir), id), nil
}

// BackupState saves a copy of terraform.tfstate before an apply or restore,
// keeping at most MaxStateBackups (30) snapshots. Does nothing if no state
// exists yet.
func BackupState(dir string, now time.Time) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "terraform.tfstate"))
	if errors.Is(err, fs.ErrNotExist) || len(data) == 0 {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read state for backup: %w", err)
	}
	bdir := backupsDir(dir)
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		return "", fmt.Errorf("create backups directory: %w", err)
	}
	base := now.UTC().Format("20060102-150405")
	name := base + ".tfstate"
	for seq := 1; ; seq++ {
		if _, err := os.Stat(filepath.Join(bdir, name)); errors.Is(err, fs.ErrNotExist) {
			break
		}
		name = fmt.Sprintf("%s-%d.tfstate", base, seq)
	}
	if err := writePrivate(filepath.Join(bdir, name), data); err != nil {
		return "", fmt.Errorf("write state backup: %w", err)
	}
	pruneBackups(bdir, MaxStateBackups)
	return name, nil
}

func pruneBackups(bdir string, keep int) {
	entries, err := os.ReadDir(bdir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && backupIDRe.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // oldest timestamp first
	for len(names) > keep {
		_ = os.Remove(filepath.Join(bdir, names[0]))
		names = names[1:]
	}
}

// ListBackups returns all saved state backups, newest first.
func ListBackups(dir string) ([]StateBackup, error) {
	entries, err := os.ReadDir(backupsDir(dir))
	if errors.Is(err, fs.ErrNotExist) {
		return []StateBackup{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list state backups: %w", err)
	}
	var out []StateBackup
	for _, e := range entries {
		if e.IsDir() || !backupIDRe.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, StateBackup{ID: e.Name(), CreatedAt: info.ModTime().Unix(), Size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if out == nil {
		out = []StateBackup{}
	}
	return out, nil
}

// RestoreBackup backs up the current state (so a restore can be undone) and
// writes the chosen backup over terraform.tfstate.
func RestoreBackup(dir, id string, now time.Time) error {
	path, err := BackupPath(dir, id)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fs.ErrNotExist
	}
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	if _, err := BackupState(dir, now); err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, "terraform.tfstate"), data)
}
