package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
)

// One reader for the whole run: two reads from a pipe through two readers would
// lose what the first one had buffered.
var stdin = bufio.NewReader(os.Stdin)

// readPassword shows the prompt and reads one line. On a terminal the typing is
// not shown (interactive is true); when the input is a pipe there is nothing to
// hide and the line is read as it is.
//
// Hiding the typing uses only the standard library (hideInput in the
// password_*.go files) instead of golang.org/x/term: that would be a third
// dependency, and this is the one place that needs it (OD-08).
func readPassword(prompt string) (password string, interactive bool, err error) {
	fmt.Fprint(os.Stderr, prompt)

	restore, hideErr := hideInput()
	interactive = hideErr == nil
	if interactive {
		// Ctrl+C while the typing is hidden would leave the terminal silent.
		interrupted := make(chan os.Signal, 1)
		signal.Notify(interrupted, os.Interrupt)
		defer signal.Stop(interrupted)
		go func() {
			if _, ok := <-interrupted; ok {
				restore()
				fmt.Fprintln(os.Stderr)
				os.Exit(130)
			}
		}()
	}

	line, readErr := stdin.ReadString('\n')
	if interactive {
		restore()
		fmt.Fprintln(os.Stderr) // the Enter that was typed is not shown either
	}
	if readErr != nil && !(errors.Is(readErr, io.EOF) && line != "") {
		return "", interactive, fmt.Errorf("read the password: %w", readErr)
	}
	return strings.TrimRight(line, "\r\n"), interactive, nil
}
