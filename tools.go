//go:build tools

// Nothing builds this file. It only keeps golang.org/x/crypto/ssh in go.mod:
// no code imports it before IM2 (bcrypt, the other half of x/crypto, is used by
// internal/store since IM1), and `go mod tidy` removes what nothing imports.
// Delete this file as soon as the first real import of x/crypto/ssh exists.
package tools

import (
	_ "golang.org/x/crypto/ssh"
)
