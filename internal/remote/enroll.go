package remote

import (
	"errors"
	"fmt"
	"strings"
)

// The scripts that run on a host. Each is a constant that reads its values as
// $1, $2 (see conn.run): none of them is built from input.

// installKeyScript adds the dashboard's key to ~/.ssh/authorized_keys, once.
// $1 is the key's line. "grep -qxF" asks for a whole line equal to it, so
// running this again (or adding the same host twice) never adds a second copy.
// A file whose last line has no newline would have the new key glued to it, so
// one is added first.
const installKeyScript = `set -e
umask 077
mkdir -p "$HOME/.ssh"
f="$HOME/.ssh/authorized_keys"
touch "$f"
if ! grep -qxF -- "$1" "$f"; then
  if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then echo >> "$f"; fi
  printf '%s\n' "$1" >> "$f"
fi
chmod 700 "$HOME/.ssh"
chmod 600 "$f"
`

// removeKeyScript takes the key's line out again. $1 is the key's line. The
// file is rewritten in place (cat into it), not replaced, so its owner and mode
// stay. A grep that fails (status 2) must not blank the file, so only 0 and 1
// ("nothing left to print") count as done.
const removeKeyScript = `f="$HOME/.ssh/authorized_keys"
[ -f "$f" ] || exit 0
tmp=$(mktemp) || exit 1
grep -vxF -- "$1" "$f" > "$tmp"
rc=$?
if [ "$rc" -le 1 ]; then cat "$tmp" > "$f"; rc=0; fi
rm -f "$tmp"
exit "$rc"
`

// sudoersScript writes a sudoers file. It runs as root. $1 is the file's text
// and $2 its path. The text goes to a temporary file first and is checked with
// "visudo -cf"; only a file that parses is installed. A broken file in
// /etc/sudoers.d would break sudo for everybody on the host.
const sudoersScript = `set -e
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf '%s\n' "$1" > "$tmp"
visudo -cf "$tmp" > /dev/null
install -m 0440 -o root -g root "$tmp" "$2"
`

// sudoersPath is where the dashboard's sudo rule for a user lives. sudo ignores
// any file in sudoers.d with a dot in its name, so the dots of a user name
// ("john.doe") become underscores, or the rule would be silently ignored.
func sudoersPath(user string) string {
	return "/etc/sudoers.d/infra-manager-" + strings.ReplaceAll(user, ".", "_")
}

func sudoersText(user string) string {
	return "# Written by infra-manager: lets the dashboard run commands as root on this host.\n" +
		user + " ALL=(ALL) NOPASSWD:ALL"
}

// EnrollRequest is "add this host".
type EnrollRequest struct {
	Target Target
	// Password is used once, to put the dashboard's key on the host, and is not
	// kept: it is not stored, not logged, and not returned. Empty means the key
	// was added by hand.
	Password string
	// SudoNoPassword lets the dashboard write a sudo rule when sudo asks for a
	// password. It needs Password, which is also the sudo password.
	SudoNoPassword bool
}

// EnrollResult is what adding (or re-checking) a host found out.
type EnrollResult struct {
	Facts            Facts
	Health           Health
	SudoOK           bool     // commands can be run as root without a password
	SudoersInstalled bool     // this call wrote the sudo rule
	HostKeyFP        string   // the host's key, as saved
	Warnings         []string // things that did not work and the host was added anyway
}

// Enroll makes a host manageable: it logs in with the password (when there is
// one) and installs the dashboard's key, checks that logging in with the key
// works, looks at sudo, and reads the first facts.
//
// tofu is trust on first use: true when adding a host, so its key is saved the
// first time it is seen; false when the host's key must already be saved.
//
// If it fails after saving a host key, that key is taken out again, so a failed
// attempt leaves no trace in known_hosts.
func (r *Remote) Enroll(req EnrollRequest, tofu bool) (res EnrollResult, err error) {
	t := req.Target
	mode := strictKeys
	if tofu {
		mode = trustFirstUse
	}
	added := false
	defer func() {
		if err != nil && added {
			_ = r.known.forget(t.hostport())
		}
	}()

	keyMode := mode
	if req.Password != "" {
		c, st, derr := r.dial(t, passwordAuth(req.Password), mode)
		// Before looking at the error: the key may have been saved and the login
		// refused after it, and that line must go again.
		added = st.added
		if derr != nil {
			return res, wrapAuth(derr, ErrPasswordRejected)
		}
		out, rerr := c.run(installKeyScript, []string{r.publicLine}, "")
		c.close()
		if rerr != nil {
			return res, fmt.Errorf("Installing the key on the host failed: %w", rerr)
		}
		if out.exit != 0 {
			return res, fmt.Errorf("Installing the key on the host failed: %s", firstLine(out.stderr))
		}
		keyMode = strictKeys // the key was saved by the connection above
	}

	// The check that matters: log in with the key alone. Everything after this
	// uses this connection.
	c, st, derr := r.dial(t, r.keyAuth(), keyMode)
	added = added || st.added
	if derr != nil {
		return res, wrapAuth(derr, ErrKeyRejected)
	}
	defer c.close()
	res.HostKeyFP = st.fingerprint

	res.SudoOK, err = r.sudoStatus(c, req, &res)
	if err != nil {
		return res, err
	}
	if res.Facts, err = c.facts(); err != nil {
		return res, err
	}
	res.Health, err = c.health(true)
	return res, err
}

// sudoStatus finds out whether the dashboard can run commands as root, and
// when it cannot but may be allowed to, sets that up.
func (r *Remote) sudoStatus(c *conn, req EnrollRequest, res *EnrollResult) (bool, error) {
	t := req.Target
	if t.User == "root" {
		return true, nil // root needs no sudo
	}
	ok, err := c.sudoWorks()
	if err != nil || ok {
		return ok, err
	}

	switch {
	case req.Password == "":
		res.Warnings = append(res.Warnings, "sudo asks for a password, and the dashboard cannot type one. Give this user passwordless sudo, or edit the host and enter its password.")
	case !req.SudoNoPassword:
		res.Warnings = append(res.Warnings, "sudo asks for a password, so the dashboard cannot configure this host. Edit the host and allow it to use sudo without a password.")
	default:
		out, err := c.runRaw("sudo -S -p '' "+shellCommand("", sudoersScript, []string{sudoersText(t.User), sudoersPath(t.User)}), req.Password+"\n")
		if err != nil {
			return false, err
		}
		if out.exit != 0 {
			res.Warnings = append(res.Warnings, "The sudo rule could not be written: "+firstLine(out.stderr)+". The user may not be allowed to use sudo, or the password is not the sudo password.")
			return false, nil
		}
		res.SudoersInstalled = true
		ok, err = c.sudoWorks()
		if err != nil {
			return false, err
		}
		if !ok {
			res.Warnings = append(res.Warnings, "The sudo rule was written, but sudo still asks for a password.")
		}
		return ok, nil
	}
	return false, nil
}

// sudoWorks: "sudo -n true" runs true as root without asking for a password,
// and fails at once (-n) if it would have to ask.
func (c *conn) sudoWorks() (bool, error) {
	out, err := c.runRaw("sudo -n true", "")
	if err != nil {
		return false, err
	}
	return out.exit == 0, nil
}

func (c *conn) facts() (Facts, error) {
	out, err := c.run(factsScript, nil, "")
	if err != nil {
		return Facts{}, err
	}
	return ParseFacts(out.stdout), nil
}

// CheckResult is what Check found.
type CheckResult struct {
	Facts     Facts
	Health    Health
	SudoOK    bool
	HostKeyFP string
}

// Check logs in with the dashboard's key (the host's key must already be
// saved) and reads the facts again.
func (r *Remote) Check(t Target) (CheckResult, error) {
	c, st, err := r.dial(t, r.keyAuth(), strictKeys)
	if err != nil {
		return CheckResult{}, wrapAuth(err, ErrKeyRejected)
	}
	defer c.close()

	res := CheckResult{HostKeyFP: st.fingerprint, SudoOK: t.User == "root"}
	if !res.SudoOK {
		if res.SudoOK, err = c.sudoWorks(); err != nil {
			return res, err
		}
	}
	if res.Facts, err = c.facts(); err != nil {
		return res, err
	}
	res.Health, err = c.health(true) // a person asked: take the slow count too
	return res, err
}

// ErrKeyChangedAgain: the key an admin was shown is no longer the one the host
// presents.
var ErrKeyChangedAgain = errors.New("The host showed a different key than the one you were shown. Look at it again before trusting it.")

// TrustNewKey saves the key a host presents now, in place of the old one, but
// only if its fingerprint is the one the admin was shown: that is what they
// agreed to trust. The connection may fail afterwards (a reinstalled host has
// lost the dashboard's key); the host's key is saved all the same.
func (r *Remote) TrustNewKey(t Target, fingerprint string) error {
	c, st, err := r.dial(t, r.keyAuth(), captureKey)
	if c != nil {
		c.close()
	}
	if st.key == nil {
		if err == nil {
			err = errors.New("the host showed no key")
		}
		return err // could not even get as far as the host's key
	}
	if st.fingerprint != fingerprint {
		return ErrKeyChangedAgain
	}
	return r.known.replace(t.hostport(), st.key)
}

// RemoveKey takes the dashboard's key out of the host's authorized_keys, and
// the sudo rule too when the dashboard wrote one.
func (r *Remote) RemoveKey(t Target, removeSudoers bool) error {
	c, _, err := r.dial(t, r.keyAuth(), strictKeys)
	if err != nil {
		return wrapAuth(err, ErrKeyRejected)
	}
	defer c.close()

	// The sudo rule first: removing it needs sudo, and the rule is what gives it.
	if removeSudoers && t.User != "root" {
		out, err := c.runRaw("sudo -n rm -f -- "+ShellQuote(sudoersPath(t.User)), "")
		if err != nil {
			return err
		}
		if out.exit != 0 {
			return fmt.Errorf("The sudo rule could not be removed: %s", firstLine(out.stderr))
		}
	}
	out, err := c.run(removeKeyScript, []string{r.publicLine}, "")
	if err != nil {
		return err
	}
	if out.exit != 0 {
		return fmt.Errorf("The key could not be removed: %s", firstLine(out.stderr))
	}
	return nil
}

// Forget drops the saved key of an address.
func (r *Remote) Forget(t Target) error {
	return r.known.forget(t.hostport())
}

// wrapAuth marks a refused login with which kind it was, so the page can give
// the right advice. Other errors pass through unchanged.
func wrapAuth(err, kind error) error {
	if isAuthError(err) {
		return fmt.Errorf("%w (%v)", kind, err)
	}
	return err
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if line, _, found := strings.Cut(s, "\n"); found {
		s = line
	}
	if s == "" {
		return "it gave no reason"
	}
	return s
}
