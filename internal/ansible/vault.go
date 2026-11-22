package ansible

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"infra-manager/internal/run"
)

// Secrets are encrypted with ansible-vault, as Ansible expects them. The
// dashboard keeps only the ciphertext (in its database), writes it into the
// generated variables as a !vault value, and gives Ansible the vault password
// file, so Ansible decrypts it while it runs. The plain value is never stored,
// never shown and never in a file: it goes to ansible-vault once, on its
// standard input, and is forgotten.

// secretRe: the name of a secret is also part of a variable name (secret_<name>).
var secretRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// secretRefRe is how a setting or a variable points at a secret: "secret:name".
var secretRefRe = regexp.MustCompile(`^secret:([a-z][a-z0-9_]{0,31})$`)

var ErrBadSecretName = errors.New("A secret's name is 1 to 32 characters: lowercase letters, digits and underscore, starting with a letter.")

func CheckSecretName(name string) error {
	if !secretRe.MatchString(name) {
		return ErrBadSecretName
	}
	return nil
}

// CheckSecretValue: one line, not empty, not longer than a token or a password
// needs to be. (A new line would be part of the value for some programs and not
// for others; refusing it avoids the doubt.)
func CheckSecretValue(value string) error {
	if value == "" {
		return errors.New("A secret needs a value.")
	}
	if len(value) > 3000 || strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("A secret is one line of at most 3000 characters.")
	}
	return nil
}

// SecretRef returns the name a value points at, if it is a reference.
func SecretRef(value string) (name string, ok bool) {
	m := secretRefRe.FindStringSubmatch(value)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// SecretVar is the variable a secret is available as in every play.
func SecretVar(name string) string { return "secret_" + name }

// EnsureVaultPassword makes the vault password file if there is none: 32 random
// bytes, in a private folder, mode 0600. It is made once and never replaced
// (replacing it would make every stored secret unreadable).
func EnsureVaultPassword(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("look at %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("make a vault password: %w", err)
	}
	// O_EXCL: if two starts race, one wins and the other keeps what it finds.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("write the vault password: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(hex.EncodeToString(raw) + "\n"); err != nil {
		return fmt.Errorf("write the vault password: %w", err)
	}
	return nil
}

// EncryptCmd is "ansible-vault encrypt_string --vault-password-file F
// --stdin-name secret_<name>", with the value on its standard input.
func (r Runner) EncryptCmd(passwordFile, name, value string) (run.Command, error) {
	if err := CheckSecretName(name); err != nil {
		return run.Command{}, err
	}
	c := run.New("", r.VaultBin, "encrypt_string", "--vault-password-file", passwordFile, "--stdin-name", SecretVar(name))
	c.Stdin = value
	return c, nil
}

// Encrypt encrypts a value and returns the ciphertext: the lines of the !vault
// block, "$ANSIBLE_VAULT;1.1;AES256" first, without the indentation. The error
// never contains the value.
func (r Runner) Encrypt(passwordFile, name, value string) (string, error) {
	cmd, err := r.EncryptCmd(passwordFile, name, value)
	if err != nil {
		return "", err
	}
	res, err := run.Output(cmd, time.Minute)
	if err != nil {
		return "", err
	}
	if res.Exit != 0 {
		return "", errors.New("ansible-vault failed: " + strings.TrimSpace(strings.ReplaceAll(res.Stderr, value, "…")))
	}
	return ParseVaultBlock(res.Stdout)
}

// ParseVaultBlock reads the output of encrypt_string:
//
//	secret_name: !vault |
//	          $ANSIBLE_VAULT;1.1;AES256
//	          6265...
//
// and returns the indented lines, trimmed, one per line.
func ParseVaultBlock(output string) (string, error) {
	var lines []string
	started := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case !started:
			started = strings.Contains(line, "!vault")
		case strings.TrimSpace(line) == "":
			// the block ends at the first blank line
			if len(lines) > 0 {
				return finishVault(lines)
			}
		default:
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	return finishVault(lines)
}

func finishVault(lines []string) (string, error) {
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "$ANSIBLE_VAULT;") {
		return "", errors.New("ansible-vault did not give an encrypted value")
	}
	for _, l := range lines {
		if strings.ContainsAny(l, " \t") {
			return "", errors.New("ansible-vault gave an encrypted value in an unexpected shape")
		}
	}
	return strings.Join(lines, "\n"), nil
}
