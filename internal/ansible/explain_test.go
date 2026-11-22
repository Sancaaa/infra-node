package ansible

import (
	"strings"
	"testing"
)

func TestExplain(t *testing.T) {
	cases := map[string]string{
		"Failed to connect to the host via ssh: root@192.168.5.133: Permission denied (publickey,password).":      "refused the SSH key",
		"Failed to connect to the host via ssh: ssh: connect to host 192.168.5.133 port 22: Connection timed out": "cannot be reached",
		"Missing sudo password":         "sudo password",
		"sudo: a password is required":  "sudo password",
		"Incorrect sudo password":       "sudo password",
		"Host key verification failed.": "trust this host's key",
		"ssh: Could not resolve hostname ct-web-01: Name or service not known": "cannot be resolved",
		"ssh: connect to host 10.0.0.9 port 22: Connection refused":            "Nothing answers",
	}
	for raw, want := range cases {
		if got := Explain(raw); !strings.Contains(got, want) {
			t.Errorf("Explain(%q) = %q, want something with %q", raw, got, want)
		}
	}
	if got := Explain("pong"); got != "" {
		t.Errorf("a normal answer got an explanation: %q", got)
	}
	if strings.Contains(Explain("Missing sudo password"), "-K") {
		t.Errorf("Explain still gives stale v1 -K advice: %q", Explain("Missing sudo password"))
	}
	if strings.Contains(Explain("Host key verification failed."), "host_key_checking = False") {
		t.Errorf("Explain still suggests insecure host_key_checking = False: %q", Explain("Host key verification failed."))
	}
}
