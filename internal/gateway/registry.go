package gateway

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
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

type tracked struct{ c io.Closer }

// Registry holds the peer state and the open relay and proxy connections of each active peer, so
// that a cut closes them.
type Registry struct {
	overlay netip.Prefix
	gateway netip.Addr
	log     *slog.Logger

	mu     sync.Mutex
	known  map[string]Peer
	byAddr map[netip.Addr]*activePeer
	conns  map[string]map[*tracked]struct{}
}

// NewRegistry returns an empty registry for the overlay whose first host is the gateway.
func NewRegistry(overlay netip.Prefix, log *slog.Logger) *Registry {
	return &Registry{
		overlay: overlay.Masked(),
		gateway: overlay.Masked().Addr().Next(),
		log:     log,
		known:   map[string]Peer{},
		byAddr:  map[netip.Addr]*activePeer{},
		conns:   map[string]map[*tracked]struct{}{},
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
// of peers that left the active set (the caller closes them; the registry already refuses them)
// and how many peers left it. An active peer with an invalid key or address, or sharing its
// address with another active peer, is not configured (fail closed).
func (r *Registry) Apply(set PeerSet) (wg []WGPeer, closers []io.Closer, cuts int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if set.Full {
		r.known = make(map[string]Peer, len(set.Peers))
	}
	for _, p := range set.Peers {
		r.known[p.ID] = p
	}

	next := map[netip.Addr]*activePeer{}
	dup := map[netip.Addr]bool{}
	for _, p := range r.known {
		if p.State != "active" {
			continue
		}
		a, err := r.parse(p)
		if err != nil {
			r.log.Warn("peer not configured", "peerId", p.ID, "err", err)
			continue
		}
		if next[a.addr] != nil {
			dup[a.addr] = true
		}
		next[a.addr] = a
	}
	for addr := range dup {
		r.log.Warn("peer not configured: address shared by more than one active peer", "address", addr)
		delete(next, addr)
	}

	byID := make(map[string]*activePeer, len(next))
	for _, a := range next {
		byID[a.ID] = a
		wg = append(wg, WGPeer{PublicKey: a.key, Addr: a.addr})
	}
	for _, old := range r.byAddr {
		if n := byID[old.ID]; n != nil && n.key == old.key && n.addr == old.addr {
			continue
		}
		cuts++
		for t := range r.conns[old.ID] {
			closers = append(closers, t.c)
		}
		delete(r.conns, old.ID)
	}
	r.byAddr = next
	return wg, closers, cuts
}

// Acquire looks up the active peer that owns src and registers c to be closed if the peer is
// cut. ok is false when src is not an active peer. release must be called when c is done.
func (r *Registry) Acquire(src netip.Addr, c io.Closer) (p Peer, release func(), ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.byAddr[src.Unmap()]
	if a == nil {
		return Peer{}, nil, false
	}
	t := &tracked{c}
	if r.conns[a.ID] == nil {
		r.conns[a.ID] = map[*tracked]struct{}{}
	}
	r.conns[a.ID][t] = struct{}{}
	return a.Peer, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.conns[a.ID], t)
	}, true
}

// Active returns the number of active peers.
func (r *Registry) Active() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byAddr)
}
