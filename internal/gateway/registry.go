package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer is one EdgePeer as the sync API returns it.
type Peer struct {
	ID         string   `json:"id"`
	PublicKey  string   `json:"publicKey"`
	Address    string   `json:"address"`
	State      string   `json:"state"`
	TenantSlug string   `json:"tenantSlug"`
	AgentSlug  string   `json:"agentSlug"`
	AllowHosts []string `json:"allowHosts"`
}

// PeerSet is a sync API response: a full replacement set or a delta of upserts.
type PeerSet struct {
	Version uint64 `json:"version"`
	Full    bool   `json:"full"`
	Peers   []Peer `json:"peers"`
}

// WGPeer is a peer to configure on wg0: AllowedIPs = Addr/32.
type WGPeer struct {
	PublicKey wgtypes.Key
	Addr      netip.Addr
}

type activePeer struct {
	Peer
	key  wgtypes.Key
	addr netip.Addr
}

// tracked is one open relay or proxy connection. host is set once the proxy allowed a CONNECT.
type tracked struct {
	c      io.Closer
	cancel context.CancelFunc
	host   string
}

// Close implements io.Closer for the connections Apply hands back.
func (t *tracked) Close() error { return t.c.Close() }

// Default connection caps; a single replica must survive one misbehaving peer.
const (
	DefaultMaxPerPeer = 64
	DefaultMaxTotal   = 2048
)

var (
	errNotPeer = errors.New("not an active peer")
	errTooMany = errors.New("too many connections")
)

// Registry holds the peer state and the open relay and proxy connections of each active peer, so
// that a cut closes them.
type Registry struct {
	overlay    netip.Prefix
	gateway    netip.Addr
	log        *slog.Logger
	MaxPerPeer int
	MaxTotal   int

	mu       sync.Mutex
	known    map[string]Peer
	byAddr   map[netip.Addr]*activePeer
	conns    map[string]map[*tracked]struct{}
	total    int
	rejected int
}

// NewRegistry returns an empty registry for the overlay whose first host is the gateway.
func NewRegistry(overlay netip.Prefix, log *slog.Logger) *Registry {
	return &Registry{
		overlay:    overlay.Masked(),
		gateway:    overlay.Masked().Addr().Next(),
		log:        log,
		MaxPerPeer: DefaultMaxPerPeer,
		MaxTotal:   DefaultMaxTotal,
		known:      map[string]Peer{},
		byAddr:     map[netip.Addr]*activePeer{},
		conns:      map[string]map[*tracked]struct{}{},
	}
}

func (r *Registry) parse(p Peer) (*activePeer, error) {
	key, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	pfx, err := netip.ParsePrefix(p.Address)
	if err != nil {
		return nil, fmt.Errorf("address: %w", err)
	}
	a := pfx.Addr()
	if !a.Is4() || pfx.Bits() != 32 || !r.overlay.Contains(a) || a == r.gateway ||
		a == r.overlay.Addr() {
		return nil, fmt.Errorf("address %s is not a host /32 in the overlay %s", p.Address, r.overlay)
	}
	return &activePeer{Peer: p, key: key, addr: a}, nil
}

// Apply merges a sync response and returns the WireGuard peers to configure, the open connections
// to close (the caller closes them; their contexts are already cancelled and the registry refuses
// them) and how many peers left the active set. An active peer with an invalid key or address, or
// sharing its address or key with another active peer, is not configured (fail closed). A peer
// whose allow-list shrank loses the proxy connections to hosts no longer allowed.
func (r *Registry) Apply(set PeerSet) (wg []WGPeer, closers []io.Closer, cuts int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if set.Full {
		r.known = make(map[string]Peer, len(set.Peers))
	}
	for _, p := range set.Peers {
		r.known[p.ID] = p
	}

	var valid []*activePeer
	addrs := map[netip.Addr]int{}
	keys := map[wgtypes.Key]int{}
	r.rejected = 0
	for _, p := range r.known {
		if p.State != "active" {
			continue
		}
		a, err := r.parse(p)
		if err != nil {
			r.rejected++
			r.log.Warn("peer not configured", "peerId", p.ID, "err", err)
			continue
		}
		valid = append(valid, a)
		addrs[a.addr]++
		keys[a.key]++
	}
	next := map[netip.Addr]*activePeer{}
	byID := map[string]*activePeer{}
	for _, a := range valid {
		if addrs[a.addr] > 1 || keys[a.key] > 1 {
			r.rejected++
			r.log.Warn("peer not configured: address or public key shared with another active peer",
				"peerId", a.ID, "address", a.addr)
			continue
		}
		next[a.addr] = a
		byID[a.ID] = a
		wg = append(wg, WGPeer{PublicKey: a.key, Addr: a.addr})
	}

	for _, old := range r.byAddr {
		n := byID[old.ID]
		if n != nil && n.key == old.key && n.addr == old.addr {
			if !slices.Equal(n.AllowHosts, old.AllowHosts) {
				for t := range r.conns[old.ID] {
					if _, ok := HostAllowed(n.AllowHosts, t.host); t.host != "" && !ok {
						closers = append(closers, r.drop(old.ID, t))
					}
				}
			}
			continue
		}
		cuts++
		for t := range r.conns[old.ID] {
			closers = append(closers, r.drop(old.ID, t))
		}
		delete(r.conns, old.ID)
	}
	r.byAddr = next
	return wg, closers, cuts
}

// drop unregisters t and cancels its context. Callers hold r.mu.
func (r *Registry) drop(id string, t *tracked) *tracked {
	if _, ok := r.conns[id][t]; ok {
		delete(r.conns[id], t)
		r.total--
	}
	t.cancel()
	return t
}

// Lease is one connection registered against an active peer.
type Lease struct {
	Peer Peer
	// Ctx is cancelled when the peer is cut or the connection is dropped for its allow-list.
	Ctx  context.Context
	r    *Registry
	t    *tracked
	addr netip.Addr
}

// Acquire looks up the active peer that owns src and registers c to be closed if the peer is
// cut. It fails with errNotPeer, or errTooMany (Peer set) when the per-peer or global cap is
// reached. Release must be called when c is done.
func (r *Registry) Acquire(src netip.Addr, c io.Closer) (*Lease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.byAddr[src.Unmap()]
	if a == nil {
		return nil, errNotPeer
	}
	if len(r.conns[a.ID]) >= r.MaxPerPeer || r.total >= r.MaxTotal {
		return &Lease{Peer: a.Peer}, errTooMany
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &tracked{c: c, cancel: cancel}
	if r.conns[a.ID] == nil {
		r.conns[a.ID] = map[*tracked]struct{}{}
	}
	r.conns[a.ID][t] = struct{}{}
	r.total++
	return &Lease{Peer: a.Peer, Ctx: ctx, r: r, t: t, addr: a.addr}, nil
}

// Allow checks host against the peer's current allow-list and, when allowed, records it on the
// connection so a later narrowing of the list closes it. It is false once the lease is cut.
func (l *Lease) Allow(host string) bool {
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	if l.Ctx.Err() != nil {
		return false
	}
	a := l.r.byAddr[l.addr]
	if a == nil || a.ID != l.Peer.ID {
		return false
	}
	if _, ok := HostAllowed(a.AllowHosts, host); !ok {
		return false
	}
	l.t.host = host
	return true
}

// Release unregisters the connection.
func (l *Lease) Release() {
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	l.r.drop(l.Peer.ID, l.t)
}

// Active returns the number of active peers and how many active peers were refused.
func (r *Registry) Active() (active, rejected int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byAddr), r.rejected
}
