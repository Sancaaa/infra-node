package remote

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The quick actions: what an operator does to a host from the Hosts page. Each
// connects with the dashboard's key, strictly, and runs one command. The unit
// name is the only value that goes into one, and it is checked and quoted.

// unitRe is a systemd service name as the host's own list gives it. A unit that
// systemd escapes with a backslash (device paths, mostly) does not match: those
// are not what anybody restarts from a page.
var unitRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,100}\.service$`)

var ErrBadUnit = errors.New("That is not a service name. It looks like nginx.service.")

func CheckUnit(unit string) error {
	if !unitRe.MatchString(unit) {
		return ErrBadUnit
	}
	return nil
}

// asRoot puts "sudo -n" in front of a command, for a user that is not root. -n:
// never ask for a password (there is nobody to type it), fail instead.
func asRoot(user, command string) string {
	if user == "root" {
		return command
	}
	return "sudo -n " + command
}

// CommandResult is what a command printed and how it ended.
type CommandResult struct {
	Stdout string
	Stderr string
	Exit   int
}

// Service is one line of the host's own list of services.
type Service struct {
	Unit   string `json:"unit"`
	Active string `json:"active"` // active, inactive, failed, activating...
	Sub    string `json:"sub"`    // running, exited, dead, failed...
}

// Services lists the host's services: what the person picks from to restart one
// or to read its logs.
func (r *Remote) Services(t Target) ([]Service, error) {
	var services []Service
	err := r.withConn(t, func(c *conn) error {
		out, err := c.runRaw("systemctl list-units --type=service --all --no-legend --plain --no-pager", "")
		if err != nil {
			return err
		}
		if out.exit != 0 {
			return errors.New("The host did not list its services: " + firstLine(out.stderr))
		}
		services = ParseServices(out.stdout)
		return nil
	})
	return services, err
}

// ParseServices reads "systemctl list-units --plain --no-legend": UNIT LOAD
// ACTIVE SUB DESCRIPTION. A unit that is not loaded (referred to, but with no
// file) is not something to restart.
func ParseServices(output string) []Service {
	services := []Service{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "loaded" || CheckUnit(fields[0]) != nil {
			continue
		}
		services = append(services, Service{Unit: fields[0], Active: fields[2], Sub: fields[3]})
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Unit < services[j].Unit })
	return services
}

// RestartService restarts a service and says what state it is in afterwards.
// useSudo is for a user that is not root.
func (r *Remote) RestartService(t Target, unit string, useSudo bool) (CommandResult, string, error) {
	if err := CheckUnit(unit); err != nil {
		return CommandResult{}, "", err
	}
	var res CommandResult
	var state string
	err := r.withConn(t, func(c *conn) error {
		restart := "systemctl restart -- " + ShellQuote(unit)
		if useSudo {
			restart = asRoot(t.User, restart)
		}
		out, err := c.runRaw(restart, "")
		if err != nil {
			return err
		}
		res = CommandResult{Stdout: out.stdout, Stderr: out.stderr, Exit: out.exit}

		// What the service is doing now is the answer a person wants, more than
		// the exit status of restart.
		after, err := c.runRaw("systemctl is-active -- "+ShellQuote(unit), "")
		if err != nil {
			return err
		}
		state = strings.TrimSpace(after.stdout)
		return nil
	})
	return res, state, err
}

// ServiceLogs reads the last 200 lines of a service's journal.
func (r *Remote) ServiceLogs(t Target, unit string, useSudo bool) (string, error) {
	if err := CheckUnit(unit); err != nil {
		return "", err
	}
	var logs string
	err := r.withConn(t, func(c *conn) error {
		command := "journalctl -u " + ShellQuote(unit) + " -n 200 --no-pager"
		if useSudo {
			command = asRoot(t.User, command)
		}
		out, err := c.runRaw(command, "")
		if err != nil {
			return err
		}
		if out.exit != 0 {
			return errors.New("The host did not give the log: " + firstLine(out.stderr))
		}
		logs = out.stdout
		return nil
	})
	return logs, err
}

// Reboot tells the host to reboot. The connection usually drops while the
// command is being answered, which is the command working, so a lost
// connection is not an error; a refusal (sudo, permissions) is.
func (r *Remote) Reboot(t Target) error {
	return r.withConn(t, func(c *conn) error {
		out, err := c.runRaw(asRoot(t.User, "systemctl reboot"), "")
		if err != nil {
			return nil // the host went away under the command
		}
		if out.exit != 0 {
			return errors.New("The host refused to reboot: " + firstLine(out.stderr))
		}
		return nil
	})
}

// Run runs a command the person typed, word for word, in the host's shell:
// the one place where free text goes to a host. Only an admin may, and what was
// run is written to History. asRoot runs it through "sudo -n sh -c", quoted.
func (r *Remote) Run(t Target, command string, root bool, timeout time.Duration) (CommandResult, error) {
	if strings.ContainsRune(command, 0) {
		return CommandResult{}, errors.New("A command cannot contain a NUL byte.")
	}
	var res CommandResult
	err := r.withConn(t, func(c *conn) error {
		line := command
		if root && t.User != "root" {
			line = "sudo -n sh -c " + ShellQuote(command)
		}
		out, err := c.runTimeout(line, "", timeout)
		if err != nil {
			return err
		}
		res = CommandResult{Stdout: out.stdout, Stderr: out.stderr, Exit: out.exit}
		return nil
	})
	return res, err
}

// Port is a listening TCP socket.
type Port struct {
	Local   string `json:"local"`   // 0.0.0.0:22, [::]:80
	Process string `json:"process"` // sshd, nginx: empty when the host does not say
}

var processRe = regexp.MustCompile(`\("([^"]+)"`)

// ParsePorts reads "ss -H -tlnp": State Recv-Q Send-Q Local Peer [Process].
func ParsePorts(output string) []Port {
	ports := []Port{}
	seen := map[Port]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "LISTEN" {
			continue
		}
		var names []string
		for _, m := range processRe.FindAllStringSubmatch(strings.Join(fields[5:], " "), -1) {
			if !contains(names, m[1]) {
				names = append(names, m[1])
			}
		}
		p := Port{Local: fields[3], Process: strings.Join(names, ", ")}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return ports
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// Details is the live picture of one host, for the Details page: nothing in it
// is stored.
type Details struct {
	Facts  Facts
	Health Health
	Ports  []Port
}

// Details collects the facts, the health (updates included) and the listening
// ports. Ports are read with sudo when useSudo, which is the only way to see
// which program owns a socket that is not the user's own.
func (r *Remote) Details(t Target, useSudo bool) (Details, error) {
	var d Details
	err := r.withConn(t, func(c *conn) error {
		var err error
		if d.Facts, err = c.facts(); err != nil {
			return err
		}
		if d.Health, err = c.health(true); err != nil {
			return err
		}
		command := "ss -H -tlnp"
		if useSudo {
			command = asRoot(t.User, command)
		}
		out, err := c.runRaw(command, "")
		if err != nil {
			return err
		}
		d.Ports = ParsePorts(out.stdout) // empty when the host has no ss
		return nil
	})
	return d, err
}
