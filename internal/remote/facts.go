package remote

import (
	"strconv"
	"strings"
)

// Facts is what the dashboard learns about a host when it connects: enough for
// the Hosts table and the Details page.
type Facts struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Kernel   string `json:"kernel"`
	Arch     string `json:"arch"`
	CPUs     int    `json:"cpus"`
	MemKB    int64  `json:"mem_kb"`
	UptimeS  int64  `json:"uptime_s"`
	Disks    []Disk `json:"disks"`
	IPs      []IP   `json:"ips"`
}

type Disk struct {
	Mount string `json:"mount"`
	Size  int64  `json:"size"` // bytes
	Used  int64  `json:"used"` // bytes
}

type IP struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
}

// factsScript prints one "key=value" line per fact. It is a constant: nothing
// is put in it, so it needs no quoting of values. It uses only what a plain
// Debian or Ubuntu has, and prints nothing for what a host does not have.
const factsScript = `echo "hostname=$(hostname)"
echo "os=$( . /etc/os-release 2>/dev/null; echo "$PRETTY_NAME" )"
echo "kernel=$(uname -sr)"
echo "arch=$(uname -m)"
echo "cpus=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)"
echo "mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)"
echo "uptime_s=$(cut -d. -f1 /proc/uptime 2>/dev/null)"
( df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -P -k 2>/dev/null ) |
  awk 'NR > 1 { m = $6; for (i = 7; i <= NF; i++) m = m " " $i; print "disk=" $2 " " $3 " " m }'
ip -o addr show scope global 2>/dev/null | awk '{ print "ip=" $2 " " $4 }'
`

// ParseFacts reads the output of factsScript. A line it does not understand is
// skipped, and a missing fact stays empty: a host that has no /proc is still a
// host.
func ParseFacts(output string) Facts {
	f := Facts{Disks: []Disk{}, IPs: []IP{}}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "hostname":
			f.Hostname = value
		case "os":
			f.OS = value
		case "kernel":
			f.Kernel = value
		case "arch":
			f.Arch = value
		case "cpus":
			f.CPUs, _ = strconv.Atoi(value)
		case "mem_kb":
			f.MemKB, _ = strconv.ParseInt(value, 10, 64)
		case "uptime_s":
			f.UptimeS, _ = strconv.ParseInt(value, 10, 64)
		case "disk": // "<size KB> <used KB> <mount point, which may have spaces>"
			parts := strings.SplitN(value, " ", 3)
			if len(parts) != 3 {
				continue
			}
			size, err1 := strconv.ParseInt(parts[0], 10, 64)
			used, err2 := strconv.ParseInt(parts[1], 10, 64)
			if err1 != nil || err2 != nil {
				continue
			}
			f.Disks = append(f.Disks, Disk{Mount: parts[2], Size: size * 1024, Used: used * 1024})
		case "ip": // "<interface> <address/prefix>"
			iface, cidr, ok := strings.Cut(value, " ")
			if ok {
				f.IPs = append(f.IPs, IP{Interface: iface, CIDR: cidr})
			}
		}
	}
	return f
}
