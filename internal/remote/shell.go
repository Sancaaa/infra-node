package remote

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

// ShellQuote makes a value safe to put in a command that the remote shell will
// read. SSH "exec" hands ONE string to the host's shell, so "arguments passed
// separately" cannot be enforced there the way it is for local programs
// (roadmap, "Rules for every agent"). Two things keep it safe, in this order:
//
//  1. the value is checked against a strict pattern first (the Check functions
//     below), so it is what it should be;
//  2. it is quoted here, so even a value that slipped through is one word.
//
// Inside single quotes a shell reads every character as itself, except the
// single quote. That one is written as: end the quote, a quoted ', start
// again. The only value that cannot be sent is one with a NUL byte, and a NUL
// is a bug of ours (a value must have been checked), so it panics, like
// run.New does for a wrong argument.
func ShellQuote(s string) string {
	if strings.ContainsRune(s, 0) {
		panic("remote.ShellQuote: a NUL byte in a shell value")
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// The patterns for what a person types into Add host. They are strict on
// purpose: these values end up in remote commands, in a sudoers file name and
// line, and (from IM4) in an Ansible inventory.
var (
	nameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	userRe  = regexp.MustCompile(`^[a-z_][a-z0-9._-]{0,31}$`)
	labelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// These errors are sentences: the page shows them as they are.
var (
	ErrBadName    = errors.New("A host name is 1 to 63 characters: lowercase letters, digits, dot, dash or underscore, starting with a letter or digit.")
	ErrBadAddress = errors.New("The address must be an IP address or a host name such as web-1.lab.example.")
	ErrBadPort    = errors.New("The port must be a number from 1 to 65535.")
	ErrBadUser    = errors.New("The SSH user is 1 to 32 characters: lowercase letters, digits, dot, dash or underscore, starting with a letter or underscore.")
)

func CheckName(name string) error {
	if !nameRe.MatchString(name) {
		return ErrBadName
	}
	return nil
}

func CheckUser(user string) error {
	if !userRe.MatchString(user) {
		return ErrBadUser
	}
	return nil
}

func CheckPort(port int) error {
	if port < 1 || port > 65535 {
		return ErrBadPort
	}
	return nil
}

// CheckAddress accepts an IP address, or a host name made of dot-separated
// labels. A zone ("fe80::1%eth0") is refused: it has a % in it.
func CheckAddress(address string) error {
	if net.ParseIP(address) != nil {
		return nil
	}
	if len(address) > 253 {
		return ErrBadAddress
	}
	for _, label := range strings.Split(address, ".") {
		if !labelRe.MatchString(label) {
			return ErrBadAddress
		}
	}
	return nil
}
