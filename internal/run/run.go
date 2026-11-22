// Package run starts the command-line tools (terraform, ansible, git) and keeps
// a record of each command in the form a person would type it, because showing
// that command is the point of this dashboard (show-command mode, plan 3).
//
// Arguments are always passed one by one to exec, never joined into a string
// for `sh -c` (headnode's CLAUDE.md, hard rules).
package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ansi matches terminal colour codes such as ESC[31m. Terraform and Ansible
// are told not to colour (-no-color, ANSIBLE_NOCOLOR), but some messages
// (provider errors, plugins) still arrive coloured, and in a browser the codes
// show up as "□[31m". Every byte of output passes through StripANSI first.
var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func StripANSI(s string) string {
	return ansi.ReplaceAllString(s, "")
}

// stripWriter removes colour codes from a stream. A code can be cut in two by
// a write, so it passes on whole lines only and keeps the rest until the next
// write (or Flush at the end).
type stripWriter struct {
	w       io.Writer
	partial []byte
}

func (s *stripWriter) Write(p []byte) (int, error) {
	s.partial = append(s.partial, p...)
	if end := bytes.LastIndexByte(s.partial, '\n'); end >= 0 {
		if _, err := io.WriteString(s.w, StripANSI(string(s.partial[:end+1]))); err != nil {
			return 0, err
		}
		s.partial = append(s.partial[:0], s.partial[end+1:]...)
	}
	return len(p), nil
}

func (s *stripWriter) Flush() {
	if len(s.partial) > 0 {
		_, _ = io.WriteString(s.w, StripANSI(string(s.partial)))
		s.partial = nil
	}
}

// Extra marks an argument the dashboard adds only so it can read the answer
// (-no-color, -json, -o). The page shows it muted: a person typing the command
// by hand would leave it out.
type Extra string

type arg struct {
	value string
	extra bool
}

// Command is one command line, ready to run in Dir.
type Command struct {
	Dir  string
	Name string
	Env  []string // added to this program's own environment
	// Stdin is fed to the program's standard input. It is how a secret reaches a
	// program (ansible-vault): an argument would be visible to every user of the
	// machine in the process list while it runs.
	Stdin string
	args  []arg
}

// New builds a command. Each argument is a string (shown), an Extra (shown
// muted) or a []string (several shown arguments). Anything else is a bug in
// this program, so it panics at once instead of running a wrong command.
func New(dir, name string, args ...any) Command {
	c := Command{Dir: dir, Name: name}
	for _, a := range args {
		switch v := a.(type) {
		case string:
			c.args = append(c.args, arg{value: v})
		case Extra:
			c.args = append(c.args, arg{value: string(v), extra: true})
		case []string:
			for _, s := range v {
				c.args = append(c.args, arg{value: s})
			}
		default:
			panic(fmt.Sprintf("run.New: unexpected argument of type %T", a))
		}
	}
	return c
}

// Shown is a command as the page shows it.
type Shown struct {
	Command string `json:"command"`         // what a person types
	Extra   string `json:"extra,omitempty"` // what the dashboard adds to read the answer
}

func (c Command) Shown() Shown {
	shown := []string{c.Name}
	var extra []string
	for _, a := range c.args {
		if a.extra {
			extra = append(extra, Quote(a.value))
		} else {
			shown = append(shown, Quote(a.value))
		}
	}
	return Shown{Command: strings.Join(shown, " "), Extra: strings.Join(extra, " ")}
}

// Line is the whole command, extras included, as it really runs. It is what a
// task's log prints after "$ ".
func (c Command) Line() string {
	parts := []string{c.Name}
	for _, a := range c.args {
		parts = append(parts, Quote(a.value))
	}
	return strings.Join(parts, " ")
}

// Quote writes an argument the way a POSIX shell needs it, so a command copied
// from the page can be pasted into a terminal as it is.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, " \t\n'\"$`\\|&;<>()*?[]{}!#~") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

func (c Command) exec(ctx context.Context) *exec.Cmd {
	argv := make([]string, len(c.args))
	for i, a := range c.args {
		argv[i] = a.value
	}
	cmd := exec.CommandContext(ctx, c.Name, argv...)
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	return cmd
}

// Result is what a command printed and how it ended. A non-zero exit is not an
// error here: `terraform plan -detailed-exitcode` exits 2 on purpose, and
// `terraform validate -json` exits 1 with a useful answer on stdout.
type Result struct {
	Stdout string
	Stderr string
	Exit   int
}

// Message is the most useful text to show when the command failed.
func (r Result) Message() string {
	if text := strings.TrimSpace(r.Stderr); text != "" {
		return text
	}
	return strings.TrimSpace(r.Stdout)
}

// startError explains a command that could not run at all.
func startError(c Command, err error) error {
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("%s is not installed on this machine (it is not in PATH)", c.Name)
	}
	return fmt.Errorf("cannot run %s: %w", c.Name, err)
}

// Output runs the command and waits for it, for at most timeout.
func Output(c Command, timeout time.Duration) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := c.exec(ctx)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	r := Result{Stdout: StripANSI(stdout.String()), Stderr: StripANSI(stderr.String())}
	var exit *exec.ExitError
	switch {
	case err == nil:
		return r, nil
	case ctx.Err() == context.DeadlineExceeded:
		return r, fmt.Errorf("%s did not finish within %s", c.Name, timeout)
	case errors.As(err, &exit):
		r.Exit = exit.ExitCode()
		return r, nil
	default:
		return r, startError(c, err)
	}
}

// DefaultStreamTimeout bounds streamed commands (terraform apply,
// ansible-playbook) so a hung child cannot permanently hold tfMu/ansibleMu.
const DefaultStreamTimeout = 30 * time.Minute

// Stream runs the command for at most timeout (defaulting to DefaultStreamTimeout
// when <= 0) and writes its output to w as it comes, after a "$ <command>" line,
// so a task's log reads like a terminal session. It returns the exit code.
func Stream(c Command, w io.Writer, timeout time.Duration) (int, error) {
	if timeout <= 0 {
		timeout = DefaultStreamTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(w, "$ "+c.Line())
	cmd := c.exec(ctx)
	// One writer for both: os/exec then uses one pipe, so a line of stdout and
	// a line of stderr are never cut into each other.
	clean := &stripWriter{w: w}
	cmd.Stdout = clean
	cmd.Stderr = clean
	err := cmd.Run()
	clean.Flush()

	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case ctx.Err() == context.DeadlineExceeded:
		return -1, fmt.Errorf("%s did not finish within %s", c.Name, timeout)
	case errors.As(err, &exit):
		return exit.ExitCode(), nil
	default:
		return -1, startError(c, err)
	}
}
