package undo

import "errors"

// ErrNoRunAs: the Windows service runs as SYSTEM and has no safe way to act as a signed-in user
// here, so a restore from the console is not available. `manar-edge undo restore <id>` run by the
// user does the same thing.
// ErrNoUser is never returned on Windows.
var ErrNoUser = errors.New("unknown user")

var ErrNoRunAs = errors.New("restoring from the console is not available on Windows yet: run `manar-edge undo restore <id>` on the device")

func RunAs(uid int, exe string, args ...string) ([]byte, error) { return nil, ErrNoRunAs }
