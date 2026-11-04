package vault

import (
	"context"
	"sync"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

// Lease is how long the last server list of standing grants stays good without a new one (architect
// call EC-4): offline longer, every standing grant is asked again, which offline means denied.
const Lease = 24 * time.Hour

// The server's standing grants (GET /host/v1/config vaultGrants), shared by the broker and the
// secret-file gate. A local "8 hours" or "Always" grant counts only while this list names it, so a
// grant withdrawn in the console stops at the next config read (the vault polls every 20 seconds).
var server struct {
	mu    sync.Mutex
	until map[string]time.Time // zero: no end
	at    time.Time
}

// SetServerGrants replaces the list with the one the server just sent (at: when it was read). A nil
// list (an API that does not send one, or a device Manar refuses) means no standing grant counts.
func SetServerGrants(list []hostclient.VaultGrant, at time.Time) {
	server.mu.Lock()
	defer server.mu.Unlock()
	if list == nil {
		server.until, server.at = nil, time.Time{}
		return
	}
	m := make(map[string]time.Time, len(list))
	for _, g := range list {
		if g.ID == "" {
			continue
		}
		if g.Until != nil {
			m[g.ID] = *g.Until
		} else {
			m[g.ID] = time.Time{}
		}
	}
	server.until, server.at = m, at
}

// ServerAllows reports whether the server's list, read within the lease, names grant id and it has
// not ended. A grant with no id (kept by an older device) never counts.
func ServerAllows(id string, now time.Time) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if id == "" || server.until == nil || now.Sub(server.at) > Lease || now.Before(server.at.Add(-time.Minute)) {
		return false
	}
	end, ok := server.until[id]
	return ok && (end.IsZero() || now.Before(end))
}

// GrantAsker is an Approver that also names the console request its answer came from, so a
// standing grant can be matched with the server's list.
type GrantAsker interface {
	AskGrant(ctx context.Context, r Request) (Decision, string, error)
}

// AskGrant asks a, with the request id when a can give one ("" otherwise: no standing grant).
func AskGrant(ctx context.Context, a Approver, r Request) (Decision, string, error) {
	if g, ok := a.(GrantAsker); ok {
		return g.AskGrant(ctx, r)
	}
	d, err := a.Ask(ctx, r)
	return d, "", err
}

// Wipe deletes everything in the vault without putting it back: a revoked (lost or stolen) device
// (founder decision, 4 Nov 2026). It returns how many entries it deleted.
func (v *Vault) Wipe() (int, error) {
	names, err := v.Store.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range names {
		if err := v.Store.Delete(name); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
