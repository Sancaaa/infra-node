package remote

import (
	"errors"
	"strings"
)

// The two kinds of "the host did not let me in": they need different advice.
var (
	ErrPasswordRejected = errors.New("the host did not accept the password")
	ErrKeyRejected      = errors.New("the host did not accept the dashboard's key")
)

// Host statuses, as the Hosts page shows them.
const (
	StatusOnline     = "online"
	StatusOffline    = "offline"     // cannot connect: off, wrong address, no route, sshd down
	StatusAuthFailed = "auth_failed" // answers, but does not accept the dashboard's key
	StatusKeyChanged = "key_changed" // answers with a host key that is not the saved one
)

// Problem is a failed connection, in the words of the page.
type Problem struct {
	Status      string // one of the Status constants
	Message     string // a sentence saying what happened and what to do
	PresentedFP string // for StatusKeyChanged: the fingerprint of the new key
}

// Classify turns what went wrong into a status and a sentence. The tool's own
// text is not thrown away: the caller keeps err.Error() for whoever wants it.
func Classify(err error) Problem {
	var changed *HostKeyChangedError
	var unknown *UnknownHostKeyError
	text := strings.ToLower(err.Error())
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(text, w) {
				return true
			}
		}
		return false
	}

	switch {
	case errors.As(err, &changed):
		return Problem{
			Status: StatusKeyChanged,
			Message: "The host's SSH key is not the one the dashboard saved. This is expected if the machine was reinstalled. " +
				"It is not if somebody is pretending to be it. Connections are refused until an admin chooses Trust the new key.",
			PresentedFP: changed.Presented,
		}
	case errors.As(err, &unknown):
		return Problem{Status: StatusKeyChanged, Message: "The dashboard has no saved SSH key for this host yet.", PresentedFP: unknown.Fingerprint}
	case errors.Is(err, ErrPasswordRejected):
		return Problem{Status: StatusAuthFailed, Message: "The host did not accept that user name and password. Check the user, and that password login is allowed for it (PasswordAuthentication in sshd_config)."}
	case errors.Is(err, ErrKeyRejected):
		return Problem{Status: StatusAuthFailed, Message: "The host did not accept the dashboard's key. Add the key from Settings to the user's ~/.ssh/authorized_keys, or edit the host and give its password so the dashboard installs the key again."}
	case has("connection refused"):
		return Problem{Status: StatusOffline, Message: "Nothing answers on that address and port. Is sshd running on the host, and is the port right?"}
	case has("i/o timeout", "timed out", "deadline exceeded"):
		return Problem{Status: StatusOffline, Message: "The host did not answer in time. Is it on, and is the address right? A firewall may be dropping the connection."}
	case has("no route to host", "network is unreachable"):
		return Problem{Status: StatusOffline, Message: "There is no route to that address from the dashboard's machine."}
	case has("no such host", "server misbehaving", "name resolution"):
		return Problem{Status: StatusOffline, Message: "The host name cannot be resolved. Use its IP address, or fix DNS."}
	case has("no common algorithm", "key exchange", "handshake failed"):
		return Problem{Status: StatusOffline, Message: "The SSH handshake failed: " + err.Error()}
	}
	return Problem{Status: StatusOffline, Message: err.Error()}
}

// isAuthError reports whether an SSH error is a refused login (the library has
// no type for it, only this text).
func isAuthError(err error) bool {
	text := err.Error()
	return strings.Contains(text, "unable to authenticate") || strings.Contains(text, "no supported methods remain")
}
