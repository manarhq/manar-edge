package vault

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Decision is the person's answer to "may this program have this secret".
type Decision string

const (
	AllowOnce   Decision = "ALLOW_ONCE"
	Allow8h     Decision = "ALLOW_8H"
	AllowAlways Decision = "ALLOW_ALWAYS"
	Deny        Decision = "DENY"
)

// Request is a program asking for a vaulted secret.
type Request struct {
	Kind    string
	Ref     string
	Program string // path of the requesting executable; "" when it could not be found
}

// Approver asks the person. WARDEN's prompt replaces the console approval path by supplying
// another implementation to Broker.
type Approver interface {
	Ask(ctx context.Context, r Request) (Decision, error)
}

type grant struct {
	Until  time.Time `json:"until,omitempty"`
	Always bool      `json:"always,omitempty"`
}

// Broker releases vaulted secrets: a standing grant, or an answer from the Approver. It never
// releases on an error.
type Broker struct {
	V        *Vault
	A        Approver
	Now      func() time.Time
	OnDenied func(Request) // optional: reported to Manar

	mu sync.Mutex // one prompt at a time; parallel calls for the same program then use its grant
}

func (b *Broker) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func grantKey(r Request) string {
	return sum([]byte(r.Kind + "\x00" + r.Ref + "\x00" + r.Program))[:24]
}

func (b *Broker) grants() map[string]grant {
	m := map[string]grant{}
	if raw, err := b.V.Store.Get("grants"); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func (b *Broker) saveGrants(m map[string]grant) error {
	raw, _ := json.Marshal(m)
	return b.V.Store.Put("grants", raw)
}

// Credential returns the secret for a request, or an error.
func (b *Broker) Credential(ctx context.Context, r Request) ([]byte, error) {
	if r.Kind != "aws" {
		return nil, errors.New("unsupported secret kind")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := grantKey(r)
	g, ok := b.grants()[key]
	allowed := r.Program != "" && ok && (g.Always || b.now().Before(g.Until))
	if !allowed {
		d, err := b.A.Ask(ctx, r)
		if err != nil {
			d = Deny
		}
		switch {
		case d == Deny || (d != AllowOnce && d != Allow8h && d != AllowAlways):
			if b.OnDenied != nil {
				b.OnDenied(r)
			}
			return nil, errors.New("Manar: access to this secret was not allowed")
		case r.Program == "": // never keep a standing grant for a program we could not identify
		case d == Allow8h:
			m := b.grants()
			m[key] = grant{Until: b.now().Add(8 * time.Hour)}
			_ = b.saveGrants(m)
		case d == AllowAlways:
			m := b.grants()
			m[key] = grant{Always: true}
			_ = b.saveGrants(m)
		}
	}
	return b.V.AWSCredentialProcess(r.Ref)
}
