// Package remotetest is an SSH server for tests: it listens on 127.0.0.1,
// accepts one password and any key listed in its fake home's authorized_keys,
// and runs every command it is sent with the real "sh" in that home. So a test
// of "adding a host twice keeps one copy of the key" runs the real script, not
// a stand-in for it. It needs "sh" (Linux, macOS, WSL, or Git for Windows);
// Start skips the test when there is none.
package remotetest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Options configures a server. The zero value is a server on a free port with
// a new host key and the password "test-password".
type Options struct {
	Password string
	Port     int        // 0: any free port
	HostKey  ssh.Signer // nil: make one
	// Stubs are programs that stand in for the host's own: name → the whole
	// script, shebang included. They are put in <home>/bin, which comes first in
	// the PATH of every command. A stub replaces a default of the same name.
	Stubs map[string]string
}

// defaultStubs keep a test from touching the machine it runs on. A test host
// runs its commands for real, with the real sh, so "sudo -n systemctl reboot"
// would otherwise reboot the developer's computer.
//
//   - sudo does not ask for anything and does not become root: it only drops
//     its options and runs the command, under the same PATH, so the stubs below
//     still apply to it.
//   - reboot, shutdown, poweroff and halt refuse.
//   - systemctl refuses the verbs that stop or reboot the machine, and runs
//     (if there is one) the real program for the rest.
//   - apt-get finds nothing to upgrade.
var defaultStubs = map[string]string{
	"sudo": `#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -p) shift 2 ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
exec "$@"
`,
	"reboot":   refuse,
	"shutdown": refuse,
	"poweroff": refuse,
	"halt":     refuse,
	// No packages to upgrade, and quickly: the real "apt-get -s upgrade" takes a
	// second or two, and every host a test adds is asked.
	"apt-get": "#!/bin/sh\nexit 0\n",
	"systemctl": `#!/bin/sh
case "$1" in
  reboot|poweroff|halt|kexec|suspend|hibernate)
    echo "refused by the test server: systemctl $1" >&2
    exit 1 ;;
esac
PATH="${PATH#*:}"
exec systemctl "$@"
`,
}

const refuse = `#!/bin/sh
echo "refused by the test server: $0 $*" >&2
exit 1
`

type Server struct {
	Host     string // "127.0.0.1"
	Port     int
	Password string
	Home     string // the HOME of every command it runs
	bin      string // <home>/bin: the stubs

	config *ssh.ServerConfig
	ln     net.Listener
	mu     sync.Mutex
	conns  []net.Conn
}

// NewHostKey makes a host key. Giving two servers different ones is how a test
// plays "the machine was reinstalled".
func NewHostKey(t testing.TB) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// Start runs a server until the test ends.
func Start(t testing.TB, home string, o Options) *Server {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("this test runs real shell scripts and there is no sh here")
	}
	if o.Password == "" {
		o.Password = "test-password"
	}
	if o.HostKey == nil {
		o.HostKey = NewHostKey(t)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	stubs := map[string]string{}
	for name, script := range defaultStubs {
		stubs[name] = script
	}
	for name, script := range o.Stubs {
		stubs[name] = script
	}
	for name, script := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	s := &Server{Host: "127.0.0.1", Password: o.Password, Home: home, bin: bin}
	s.config = &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == s.Password {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.keyAuthorized(key) {
				return nil, nil
			}
			return nil, errors.New("key not in authorized_keys")
		},
	}
	s.config.AddHostKey(o.HostKey)

	ln, err := net.Listen("tcp", net.JoinHostPort(s.Host, strconv.Itoa(o.Port)))
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	s.Port = ln.Addr().(*net.TCPAddr).Port
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// AuthorizedKeys is the text of the fake home's ~/.ssh/authorized_keys.
func (s *Server) AuthorizedKeys() string {
	data, _ := os.ReadFile(filepath.Join(s.Home, ".ssh", "authorized_keys"))
	return string(data)
}

func (s *Server) keyAuthorized(key ssh.PublicKey) bool {
	rest := []byte(s.AuthorizedKeys())
	for len(rest) > 0 {
		authorized, _, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return false
		}
		if bytes.Equal(authorized.Marshal(), key.Marshal()) {
			return true
		}
		rest = next
	}
	return false
}

// Close stops the server and drops its connections.
func (s *Server) Close() {
	s.ln.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
}

func (s *Server) serve() {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, nc)
		s.mu.Unlock()
		go s.handle(nc)
	}
}

func (s *Server) handle(nc net.Conn) {
	defer nc.Close()
	sc, channels, requests, err := ssh.NewServerConn(nc, s.config)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		channel, reqs, err := newChannel.Accept()
		if err != nil {
			return
		}
		go s.session(channel, reqs)
	}
}

// session answers "exec" requests by running the command with sh.
func (s *Server) session(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for req := range requests {
		if req.Type != "exec" {
			req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			req.Reply(false, nil)
			return
		}
		req.Reply(true, nil)

		cmd := exec.Command("sh", "-c", payload.Command)
		// Later entries win, so these replace the ones from os.Environ.
		cmd.Env = append(os.Environ(), "HOME="+s.Home, "PATH="+s.bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		cmd.Dir = s.Home
		cmd.Stdin = channel
		cmd.Stdout = channel
		cmd.Stderr = channel.Stderr()
		status := uint32(0)
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				status = uint32(exit.ExitCode())
			} else {
				status = 127
			}
		}
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}
