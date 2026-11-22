package remote

import (
	"strconv"
	"strings"
)

// Health is what the check every minute learns about a host: how loaded it is,
// and the things that need somebody's attention.
type Health struct {
	Load1      float64  `json:"load1"`
	Load5      float64  `json:"load5"`
	Load15     float64  `json:"load15"`
	MemTotalKB int64    `json:"mem_total_kb"`
	MemAvailKB int64    `json:"mem_avail_kb"`
	DiskSizeKB int64    `json:"disk_size_kb"` // the root filesystem
	DiskUsedKB int64    `json:"disk_used_kb"`
	UptimeS    int64    `json:"uptime_s"`
	Failed     []string `json:"failed"` // systemd units in the failed state
	Reboot     bool     `json:"reboot_required"`
	// Updates is the number of packages apt would upgrade, from its list as it
	// is (the dashboard does not run "apt update"). -1: not known, because the
	// host has no apt or the count has not been taken yet. It is slow to take, so
	// the check takes it every few minutes, not every minute (UpdatesAt is when).
	Updates   int   `json:"updates"`
	UpdatesAt int64 `json:"updates_at"`
}

// healthScript prints "key=value" lines. $1 is "updates" when the pending
// updates should be counted too. It is a constant: no value is put in it.
//
// A reboot is needed when Debian or Ubuntu says so (the reboot-required file),
// or when a newer kernel is installed than the one that runs: plain Debian
// does not write that file for a kernel update.
const healthScript = `awk '{ print "load1=" $1; print "load5=" $2; print "load15=" $3 }' /proc/loadavg 2>/dev/null
awk '/^MemTotal:/ { t = $2 } /^MemAvailable:/ { a = $2 } END { print "mem_total_kb=" t; print "mem_avail_kb=" a }' /proc/meminfo 2>/dev/null
df -P -k / 2>/dev/null | awk 'NR == 2 { print "disk_size_kb=" $2; print "disk_used_kb=" $3 }'
echo "uptime_s=$(cut -d. -f1 /proc/uptime 2>/dev/null)"
systemctl --failed --no-legend --plain --no-pager 2>/dev/null | awk '{ print "failed=" $1 }'
reboot=0
[ -f /var/run/reboot-required ] && reboot=1
latest=$(ls /boot/vmlinuz-* 2>/dev/null | sed 's|/boot/vmlinuz-||' | sort -V | tail -n 1)
if [ -n "$latest" ] && [ "$latest" != "$(uname -r)" ]; then reboot=1; fi
echo "reboot=$reboot"
if [ "$1" = updates ] && command -v apt-get > /dev/null 2>&1; then
  echo "updates=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ')"
fi
`

// ParseHealth reads the output of healthScript. What it does not understand is
// skipped, and what is missing stays zero (Updates stays -1).
func ParseHealth(output string) Health {
	h := Health{Failed: []string{}, Updates: -1}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "load1":
			h.Load1, _ = strconv.ParseFloat(value, 64)
		case "load5":
			h.Load5, _ = strconv.ParseFloat(value, 64)
		case "load15":
			h.Load15, _ = strconv.ParseFloat(value, 64)
		case "mem_total_kb":
			h.MemTotalKB, _ = strconv.ParseInt(value, 10, 64)
		case "mem_avail_kb":
			h.MemAvailKB, _ = strconv.ParseInt(value, 10, 64)
		case "disk_size_kb":
			h.DiskSizeKB, _ = strconv.ParseInt(value, 10, 64)
		case "disk_used_kb":
			h.DiskUsedKB, _ = strconv.ParseInt(value, 10, 64)
		case "uptime_s":
			h.UptimeS, _ = strconv.ParseInt(value, 10, 64)
		case "failed":
			// A unit name, as systemctl prints it. It is shown on a page, so keep
			// only what a unit name can contain.
			if value != "" && len(value) <= 256 && !strings.ContainsAny(value, " \t\x00") {
				h.Failed = append(h.Failed, value)
			}
		case "reboot":
			h.Reboot = value == "1"
		case "updates":
			if n, err := strconv.Atoi(value); err == nil && n >= 0 {
				h.Updates = n
			}
		}
	}
	return h
}

// health runs the check on an open connection.
func (c *conn) health(withUpdates bool) (Health, error) {
	args := []string{"-"}
	if withUpdates {
		args = []string{"updates"}
	}
	out, err := c.run(healthScript, args, "")
	if err != nil {
		return Health{}, err
	}
	return ParseHealth(out.stdout), nil
}

// Probe is the check every minute: log in with the dashboard's key (the host's
// key must be the saved one) and read the health. Nothing is changed on the
// host.
func (r *Remote) Probe(t Target, withUpdates bool) (Health, error) {
	var h Health
	err := r.withConn(t, func(c *conn) error {
		var err error
		h, err = c.health(withUpdates)
		return err
	})
	return h, err
}

// withConn logs in with the key, strictly, runs f, and closes the connection.
func (r *Remote) withConn(t Target, f func(c *conn) error) error {
	c, _, err := r.dial(t, r.keyAuth(), strictKeys)
	if err != nil {
		return wrapAuth(err, ErrKeyRejected)
	}
	defer c.close()
	return f(c)
}
