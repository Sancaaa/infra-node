package main

import (
	"strings"
	"testing"
)

func TestCheckListen(t *testing.T) {
	good := map[string]bool{ // address → is it this machine's own
		"127.0.0.1:8095": true,
		"localhost:8095": true,
		"[::1]:8095":     true,
		"0.0.0.0:8095":   false,
		"10.0.0.5:80":    false,
	}
	for addr, wantLoopback := range good {
		got, err := checkListen(addr)
		if err != nil || got != wantLoopback {
			t.Errorf("checkListen(%q) = %v, %v; want %v, nil", addr, got, err, wantLoopback)
		}
	}

	// The last two would otherwise end up inside the systemd unit.
	for _, bad := range []string{"", "8095", ":8095", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000",
		"127.0.0.1:http", "example.com:80", "127.0.0.1:80\nUser=root", "127.0.0.1 :80"} {
		if _, err := checkListen(bad); err == nil {
			t.Errorf("checkListen(%q) was accepted", bad)
		}
	}
}

// The unit is the part of the installer that decides who the service runs as.
func TestUnitFileRunsAsItsOwnUser(t *testing.T) {
	unit := unitFile("/usr/local/bin/infra-manager", "127.0.0.1:8095")

	for _, want := range []string{
		"\nUser=infra-manager\n",
		"\nGroup=infra-manager\n",
		"\nExecStart=/usr/local/bin/infra-manager serve -data /var/lib/infra-manager -listen 127.0.0.1:8095\n",
		"\nStateDirectory=infra-manager\n",
		"\nStateDirectoryMode=0700\n",
		"\nNoNewPrivileges=true\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit has no %q:\n%s", strings.TrimSpace(want), unit)
		}
	}
	if strings.Contains(unit, "User=root") {
		t.Error("the service would run as root")
	}
	// The data folder in ExecStart must be the one StateDirectory creates.
	if serviceData != "/var/lib/"+serviceName {
		t.Errorf("serviceData %q does not match StateDirectory=%s", serviceData, serviceName)
	}
}
