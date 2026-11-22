// Package remote is everything the dashboard does over SSH: its own key, the
// list of host keys it trusts, adding a host, and checking one. It uses Go's
// SSH client (golang.org/x/crypto/ssh), not the ssh program, so a host name or a
// password is never part of a local command line.
package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// keyComment is written after the public key, so a person reading a host's
// authorized_keys can tell whose key it is. Nothing relies on it: a key is
// found by its text, and a comment can be edited by anyone.
const keyComment = "infra-manager"

// Remote holds the dashboard's identity: the key that logs in to every host,
// and the file of host keys it trusts.
type Remote struct {
	dataDir     string
	keyPath     string
	signer      ssh.Signer
	publicLine  string
	fingerprint string
	known       *KnownHosts
}

// Open prepares <data>/keys: the dashboard's SSH key (made on the first start),
// and known_hosts. The folder is private to the service's user: the private key
// opens every managed host.
func Open(dataDir string) (*Remote, error) {
	// Absolute: the paths of the key and of known_hosts go into ansible.cfg, and
	// Ansible runs in another folder than the one the dashboard was started in.
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}
	dir := filepath.Join(dataDir, "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}

	keyPath := filepath.Join(dir, "id_ed25519")
	signer, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	public := signer.PublicKey()
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))) + " " + keyComment

	// A copy next to the private key, for people who want to look at it or copy
	// it by hand. The dashboard itself always uses the key it has in memory.
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519.pub"), []byte(line+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("write the public key: %w", err)
	}

	known, err := newKnownHosts(filepath.Join(dir, "known_hosts"))
	if err != nil {
		return nil, err
	}
	return &Remote{dataDir: dataDir, keyPath: keyPath, signer: signer, publicLine: line, fingerprint: ssh.FingerprintSHA256(public), known: known}, nil
}

// DataDir is the folder the dashboard keeps everything in.
func (r *Remote) DataDir() string { return r.dataDir }

// PrivateKeyPath is where the dashboard's private key is, for Ansible's
// ansible.cfg: Ansible logs in with the same key, through the ssh program.
func (r *Remote) PrivateKeyPath() string { return r.keyPath }

// PublicKey is the line to put in a host's authorized_keys.
func (r *Remote) PublicKey() string { return r.publicLine }

// Fingerprint is the public key's SHA-256 fingerprint ("SHA256:...").
func (r *Remote) Fingerprint() string { return r.fingerprint }

// KnownHostsPath is the file Ansible will be given as its own known_hosts.
func (r *Remote) KnownHostsPath() string { return r.known.path }

// loadOrCreateKey reads the private key, or makes a new ed25519 one when there
// is none. It never overwrites a key that exists, even one it cannot read: that
// would lock the dashboard out of every host.
func loadOrCreateKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("read the SSH key %s: %w", path, err)
		}
		return signer, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read the SSH key %s: %w", path, err)
	}

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("make an SSH key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(private, keyComment)
	if err != nil {
		return nil, fmt.Errorf("encode the SSH key: %w", err)
	}

	// Written to a temporary file and renamed, so a crash half way never leaves
	// a broken key under the real name (the next start would refuse to run).
	// CreateTemp makes the file 0600.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".id_ed25519-*")
	if err != nil {
		return nil, fmt.Errorf("write the SSH key: %w", err)
	}
	defer os.Remove(tmp.Name()) // does nothing after a successful rename
	if _, err := tmp.Write(pem.EncodeToMemory(block)); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write the SSH key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("write the SSH key: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, fmt.Errorf("put the SSH key in place: %w", err)
	}
	return ssh.NewSignerFromKey(private)
}
