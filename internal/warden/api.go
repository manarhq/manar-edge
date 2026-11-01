package warden

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"
)

var vaultAPI atomic.Pointer[decider]

func setAPI(d decider) { vaultAPI.Store(&d) }

// AskSecret is the call the secrets vault makes: "allow program X to use secret Y?".
//
// The answer never comes from the device. A prompt on the desktop can be answered by any process
// running as the same user, including the program asking, so it is not consent. AskSecret opens an
// approval that only a signed-in person can decide in the console; WARDEN on the desktop only says
// "Open the console to decide". It waits for that decision and returns it (ApproveOnce,
// ApproveEight or Deny). Anything else is an error or Dismissed (expired, or the device is
// offline); the vault must treat both as a refusal. The vault remembers an ApproveEight itself.
func AskSecret(ctx context.Context, program, secretName string) (Decision, error) {
	p := vaultAPI.Load()
	if p == nil {
		return "", ErrNoHelper
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return askSecret(ctx, *p, program, secretName, 2*time.Second)
}

func askSecret(ctx context.Context, api decider, program, secret string, every time.Duration) (Decision, error) {
	var opened struct {
		ID string `json:"id"`
	}
	if err := api.Do(ctx, http.MethodPost, "/approvals/vault", map[string]string{"program": program, "secret": secret}, &opened); err != nil {
		return "", err
	}
	if opened.ID == "" {
		return "", errors.New("warden: the API did not open an approval")
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		var st struct {
			Status   string `json:"status"`
			Decision string `json:"decision"`
		}
		if err := api.Do(ctx, http.MethodGet, "/approvals/"+opened.ID, nil, &st); err != nil {
			return "", err
		}
		switch st.Status {
		case "APPROVED":
			d := Decision(st.Decision)
			if d == ApproveOnce || d == ApproveEight {
				return d, nil
			}
			return Dismissed, nil // an approval without a known decision is not consent
		case "DENIED":
			return Deny, nil
		case "EXPIRED":
			return Dismissed, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-t.C:
		}
	}
}
