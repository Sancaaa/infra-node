package remote

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// KnownHosts is the dashboard's own list of host keys, in OpenSSH's known_hosts
// format, so Ansible can be given the same file (IM4) and nothing has to be
// translated. It is separate from any user's ~/.ssh/known_hosts on purpose: the
// dashboard trusts exactly the hosts that were added to it.
//
// The rule is trust on first use. The first time a host is added its key is
// saved. After that a different key is refused, always, until an admin says
// otherwise.
type KnownHosts struct {
	mu   sync.Mutex
	path string
}

func newKnownHosts(path string) (*KnownHosts, error) {
	// Created empty if missing: the library refuses a file that does not exist.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	f.Close()
	return &KnownHosts{path: path}, nil
}

// hostKeyMode says what to do with a host key that is not in the file.
type hostKeyMode int

const (
	strictKeys    hostKeyMode = iota // refuse an unknown key: every connection but adding a host
	trustFirstUse                    // save an unknown key: adding a host
	captureKey                       // accept any key and remember it, to show it to an admin
)

// dialState is what a connection learned about the host's key.
type dialState struct {
	key         ssh.PublicKey
	fingerprint string
	added       bool  // this connection saved the key (trust on first use)
	err         error // why the key was refused, if it was
}

// HostKeyChangedError: the host answered with a key that is not the saved one.
// Either it was reinstalled, or somebody is pretending to be it.
type HostKeyChangedError struct {
	Address   string
	Presented string   // fingerprint of the key it showed now
	Known     []string // fingerprints of the keys that were saved
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("the host key of %s is %s, but %s was saved", e.Address, e.Presented, strings.Join(e.Known, ", "))
}

// UnknownHostKeyError: a strict connection to a host whose key was never saved.
type UnknownHostKeyError struct {
	Address     string
	Fingerprint string
}

func (e *UnknownHostKeyError) Error() string {
	return fmt.Sprintf("the host key of %s (%s) is not saved", e.Address, e.Fingerprint)
}

// algorithms lists the key types saved for an address. The client must ask the
// host for exactly those: if the file has its ed25519 key and the host offers
// ecdsa first, the client would meet an ecdsa key it has never seen and report
// a "changed key" that is no such thing.
func (k *KnownHosts) algorithms(hostport string) ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := os.Open(k.path)
	if err != nil {
		return nil, fmt.Errorf("read the host keys: %w", err)
	}
	defer f.Close()

	want := knownhosts.Normalize(hostport)
	var algos []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], "@") {
			continue
		}
		if !slices.Contains(strings.Split(fields[0], ","), want) {
			continue
		}
		for _, a := range hostKeyAlgorithms(fields[1]) {
			if !slices.Contains(algos, a) {
				algos = append(algos, a)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read the host keys: %w", err)
	}
	return algos, nil
}

func hostKeyAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// callback is the check the SSH client runs on a host's key.
func (k *KnownHosts) callback(mode hostKeyMode, st *dialState) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		st.key = key
		st.fingerprint = ssh.FingerprintSHA256(key)
		if mode == captureKey {
			return nil
		}

		k.mu.Lock()
		defer k.mu.Unlock()
		cb, err := knownhosts.New(k.path)
		if err != nil {
			st.err = fmt.Errorf("read the host keys: %w", err)
			return st.err
		}
		err = cb(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			st.err = err
			return err
		}
		if len(keyErr.Want) > 0 {
			known := make([]string, len(keyErr.Want))
			for i, w := range keyErr.Want {
				known[i] = ssh.FingerprintSHA256(w.Key)
			}
			st.err = &HostKeyChangedError{Address: hostname, Presented: st.fingerprint, Known: known}
			return st.err
		}
		// Nothing saved for this address.
		if mode == trustFirstUse {
			if err := k.appendLocked(hostname, key); err != nil {
				st.err = err
				return err
			}
			st.added = true
			return nil
		}
		st.err = &UnknownHostKeyError{Address: hostname, Fingerprint: st.fingerprint}
		return st.err
	}
}

func (k *KnownHosts) appendLocked(hostport string, key ssh.PublicKey) error {
	f, err := os.OpenFile(k.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("save the host key: %w", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, knownhosts.Line([]string{hostport}, key)); err != nil {
		return fmt.Errorf("save the host key: %w", err)
	}
	return nil
}

// forget removes every saved key of an address: when a host is removed, or its
// address changes, or its new key is trusted.
func (k *KnownHosts) forget(hostport string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.forgetLocked(hostport)
}

func (k *KnownHosts) forgetLocked(hostport string) error {
	f, err := os.Open(k.path)
	if err != nil {
		return fmt.Errorf("read the host keys: %w", err)
	}
	want := knownhosts.Normalize(hostport)
	var kept []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 && !strings.HasPrefix(fields[0], "#") && !strings.HasPrefix(fields[0], "@") {
			drop := false
			for _, pattern := range strings.Split(fields[0], ",") {
				if pattern == want {
					drop = true
				}
			}
			if drop {
				continue
			}
		}
		kept = append(kept, line)
	}
	err = scanner.Err()
	f.Close()
	if err != nil {
		return fmt.Errorf("read the host keys: %w", err)
	}

	// Rewritten as a new file and renamed, so a crash never leaves half a list.
	tmp, err := os.CreateTemp(filepath.Dir(k.path), ".known_hosts-*")
	if err != nil {
		return fmt.Errorf("write the host keys: %w", err)
	}
	defer os.Remove(tmp.Name())
	for _, line := range kept {
		fmt.Fprintln(tmp, line)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write the host keys: %w", err)
	}
	if err := os.Rename(tmp.Name(), k.path); err != nil {
		return fmt.Errorf("put the host keys in place: %w", err)
	}
	return nil
}

// replace saves a new key for an address in place of whatever was saved.
func (k *KnownHosts) replace(hostport string, key ssh.PublicKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.forgetLocked(hostport); err != nil {
		return err
	}
	return k.appendLocked(hostport, key)
}
