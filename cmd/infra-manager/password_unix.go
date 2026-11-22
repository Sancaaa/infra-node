//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
)

// hideInput turns off the echo of the terminal on stdin, with stty, and returns
// the function that puts it back. Its arguments are fixed words, never
// anything typed. An error means "stdin is not a terminal" (stty cannot read
// its settings): there is nothing to hide then.
func hideInput() (restore func(), err error) {
	get := exec.Command("stty", "-g")
	get.Stdin = os.Stdin
	saved, err := get.Output()
	if err != nil {
		return nil, err
	}
	state := strings.TrimSpace(string(saved))
	if state == "" {
		return nil, errors.New("stty gave no settings")
	}

	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	if err := off.Run(); err != nil {
		return nil, err
	}
	return func() {
		back := exec.Command("stty", state)
		back.Stdin = os.Stdin
		_ = back.Run() // nothing more can be done if it fails
	}, nil
}
