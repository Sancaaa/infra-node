package main

import (
	"fmt"
	"net"
	"strconv"
)

// checkListen validates a listen address and says whether it is this machine's
// own (127.0.0.1, ::1, localhost). Only an IP address or "localhost" is
// accepted, with a port: an empty host would mean "every interface", which must
// be asked for in words (0.0.0.0), and strict input also keeps odd characters
// out of the systemd unit this address is written into.
func checkListen(addr string) (loopback bool, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("-listen %q must look like 127.0.0.1:8095", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return false, fmt.Errorf("-listen %q: the port must be a number from 1 to 65535", addr)
	}
	if host == "localhost" {
		return true, nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false, fmt.Errorf("-listen %q: the address must be an IP such as 127.0.0.1 (or 0.0.0.0 for every interface)", addr)
	}
	return ip.IsLoopback(), nil
}
