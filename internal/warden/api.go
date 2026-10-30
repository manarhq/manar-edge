package warden

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"
	"time"
)

var current atomic.Pointer[Broker]

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// AskSecret is the call the secrets vault makes: "allow program X to use secret Y?". It shows a
// WARDEN prompt to the person at the screen and returns their decision (ApproveOnce, ApproveEight
// or Deny). Anything else is an error or Dismissed, and the vault must treat both as a refusal:
// ErrNoHelper (nobody can answer, or the Windows prompt is off), a timeout, or a closed prompt.
// The vault, not WARDEN, remembers an ApproveEight for 8 hours.
func AskSecret(ctx context.Context, program, secretName string) (Decision, error) {
	b := current.Load()
	if b == nil {
		return "", ErrNoHelper
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return b.Ask(ctx, Prompt{ID: newID(), Kind: KindSecret, Program: program, Resource: secretName})
}
