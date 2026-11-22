package remote

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Target is where and who: a host as the dashboard connects to it.
type Target struct {
	Address string
	Port    int
	User    string
}

func (t Target) hostport() string {
	return net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
}

const (
	dialTimeout    = 10 * time.Second
	commandTimeout = 30 * time.Second
	maxOutput      = 1 << 20 // a host cannot make the dashboard keep more than this
)

// conn is a logged-in SSH connection.
type conn struct{ client *ssh.Client }

func (c *conn) close() { c.client.Close() }

// dial connects and logs in. The returned state says what was learned about the
// host's key even when the connection failed (an admin about to trust a new key
// needs to see it).
func (r *Remote) dial(t Target, auth []ssh.AuthMethod, mode hostKeyMode) (*conn, *dialState, error) {
	st := &dialState{}
	// Not when capturing a new key: that host may offer other key types than the
	// one that was saved, and the point is to see whatever it shows now.
	var algorithms []string
	if mode != captureKey {
		var err error
		if algorithms, err = r.known.algorithms(t.hostport()); err != nil {
			return nil, st, err
		}
	}
	cfg := &ssh.ClientConfig{
		User:              t.User,
		Auth:              auth,
		HostKeyCallback:   r.known.callback(mode, st),
		HostKeyAlgorithms: algorithms, // nil (the default list) when nothing is saved yet
		Timeout:           dialTimeout,
	}
	client, err := ssh.Dial("tcp", t.hostport(), cfg)
	if err != nil {
		// The library wraps what the key check said; ours is the clearer one.
		if st.err != nil {
			err = st.err
		}
		return nil, st, err
	}
	return &conn{client: client}, st, nil
}

// keyAuth logs in with the dashboard's key.
func (r *Remote) keyAuth() []ssh.AuthMethod {
	return []ssh.AuthMethod{ssh.PublicKeys(r.signer)}
}

// passwordAuth logs in with a password, once. Some servers only offer
// "keyboard-interactive" for it, so that is answered too, with the same
// password, and only for a single question.
func passwordAuth(password string) []ssh.AuthMethod {
	return []ssh.AuthMethod{
		ssh.Password(password),
		ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			if len(questions) != 1 {
				return answers, nil // not a password question: answer nothing
			}
			answers[0] = password
			return answers, nil
		}),
	}
}

// result is what a remote command printed and how it ended.
type result struct {
	stdout string
	stderr string
	exit   int
}

// limitedBuffer keeps at most maxOutput bytes and throws the rest away.
type limitedBuffer struct{ buf bytes.Buffer }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxOutput - l.buf.Len(); room > 0 {
		l.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// ErrTimeout: a command did not finish in the time it was given. The connection
// is closed, which ends the command on the host with it.
var ErrTimeout = errors.New("The host did not finish the command in time.")

// runRaw runs one command line, exactly as given, in the host's shell. Only
// this package's own constant commands, and the admin's Run a command, go
// through it; anything that includes a value goes through run, which quotes it.
func (c *conn) runRaw(command, stdin string) (result, error) {
	return c.runTimeout(command, stdin, commandTimeout)
}

func (c *conn) runTimeout(command, stdin string, timeout time.Duration) (result, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return result{}, err
	}
	defer session.Close()

	var stdout, stderr limitedBuffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if stdin != "" {
		session.Stdin = strings.NewReader(stdin)
	}

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case err = <-done:
	case <-time.After(timeout):
		c.client.Close() // ends the session, and the command with it
		return result{}, ErrTimeout
	}

	res := result{stdout: stdout.buf.String(), stderr: stderr.buf.String()}
	var exit *ssh.ExitError
	switch {
	case err == nil:
		return res, nil
	case errors.As(err, &exit):
		res.exit = exit.ExitStatus()
		return res, nil
	}
	return result{}, err
}

// run runs a script with its values as separate arguments:
//
//	sh -c '<script>' sh '<arg 1>' '<arg 2>'
//
// The script is a constant of this program that reads its values as $1, $2, and
// every value is quoted (see ShellQuote), so a value is never part of the
// script's text.
func (c *conn) run(script string, args []string, stdin string) (result, error) {
	return c.runRaw(shellCommand("", script, args), stdin)
}

// shellCommand builds the command line for run. prefix is put in front
// ("sudo -S -p '' " to run it as root), or "".
func shellCommand(prefix, script string, args []string) string {
	var b strings.Builder
	b.WriteString(prefix)
	b.WriteString("sh -c ")
	b.WriteString(ShellQuote(script))
	b.WriteString(" sh")
	for _, a := range args {
		b.WriteByte(' ')
		b.WriteString(ShellQuote(a))
	}
	return b.String()
}
