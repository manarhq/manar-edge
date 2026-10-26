package gateway

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/jsimonetti/rtnetlink/v2"
	"github.com/jsimonetti/rtnetlink/v2/rtnl"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Kernel is the Linux Net: kernel WireGuard through wgctrl, the link through rtnetlink and the
// filter through nftables.
type Kernel struct {
	Iface string
	wg    *wgctrl.Client
}

// FirewallTable is the nftables table the gateway owns.
const FirewallTable = "manar_edge_gateway"

// SetupKernel creates (or reuses) the WireGuard interface, sets its key, port and address, removes
// any peer left from an earlier run, brings it up and installs the nftables filter. There is no
// userspace fallback: a pod with only NET_ADMIN has no /dev/net/tun.
func SetupKernel(iface string, addr netip.Prefix, port int, key wgtypes.Key, tcpPorts []int) (*Kernel, error) {
	nl, err := rtnl.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("rtnetlink: %w", err)
	}
	defer nl.Close()
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		err = nl.Conn.Link.New(&rtnetlink.LinkMessage{
			Family:     unix.AF_UNSPEC,
			Attributes: &rtnetlink.LinkAttributes{Name: iface, Info: &rtnetlink.LinkInfo{Kind: "wireguard"}},
		})
		if err != nil {
			return nil, fmt.Errorf("create WireGuard interface %s: %w (kernel WireGuard is required: "+
				"Linux 5.6+ or the wireguard module on the node)", iface, err)
		}
		if ifc, err = net.InterfaceByName(iface); err != nil {
			return nil, err
		}
	}
	wg, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	if err := wg.ConfigureDevice(iface, wgtypes.Config{PrivateKey: &key, ListenPort: &port, ReplacePeers: true}); err != nil {
		wg.Close()
		return nil, fmt.Errorf("configure %s: %w", iface, err)
	}
	ipnet := &net.IPNet{IP: addr.Addr().AsSlice(), Mask: net.CIDRMask(addr.Bits(), addr.Addr().BitLen())}
	if err := nl.AddrAdd(ifc, ipnet); err != nil && !errors.Is(err, os.ErrExist) && !errors.Is(err, unix.EEXIST) {
		wg.Close()
		return nil, fmt.Errorf("address %s on %s: %w", addr, iface, err)
	}
	if err := nl.LinkUp(ifc); err != nil {
		wg.Close()
		return nil, fmt.Errorf("link up %s: %w", iface, err)
	}
	if err := applyFirewall(iface, addr.Addr(), tcpPorts); err != nil {
		wg.Close()
		return nil, fmt.Errorf("nftables: %w", err)
	}
	return &Kernel{Iface: iface, wg: wg}, nil
}

// SetPeers makes wg0's peers exactly peers, touching only the ones that differ so established
// sessions of unchanged peers are kept.
func (k *Kernel) SetPeers(peers []WGPeer) error {
	dev, err := k.wg.Device(k.Iface)
	if err != nil {
		return err
	}
	want := make(map[wgtypes.Key]netip.Addr, len(peers))
	for _, p := range peers {
		want[p.PublicKey] = p.Addr
	}
	var cfg []wgtypes.PeerConfig
	have := map[wgtypes.Key]bool{}
	for _, p := range dev.Peers {
		a, ok := want[p.PublicKey]
		if ok && len(p.AllowedIPs) == 1 && p.AllowedIPs[0].String() == netip.PrefixFrom(a, 32).String() {
			have[p.PublicKey] = true
			continue
		}
		if !ok {
			cfg = append(cfg, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
		}
	}
	for key, a := range want {
		if have[key] {
			continue
		}
		cfg = append(cfg, wgtypes.PeerConfig{
			PublicKey:         key,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{{IP: a.AsSlice(), Mask: net.CIDRMask(32, 32)}},
		})
	}
	if len(cfg) == 0 {
		return nil
	}
	return k.wg.ConfigureDevice(k.Iface, wgtypes.Config{Peers: cfg})
}

// applyFirewall replaces the gateway's nftables table in one transaction:
//
//	input:   iifname wg0 ip daddr <gw> tcp dport { ports } accept
//	         iifname != wg0 ip daddr <gw> counter drop; iifname wg0 counter drop
//	forward: iifname wg0 counter drop; oifname wg0 counter drop
func applyFirewall(iface string, gw netip.Addr, ports []int) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: FirewallTable}
	c.AddTable(t)
	c.DelTable(t)
	c.AddTable(t)
	accept := nftables.ChainPolicyAccept
	input := c.AddChain(&nftables.Chain{Name: "input", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept})
	forward := c.AddChain(&nftables.Chain{Name: "forward", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept})
	for _, port := range ports {
		exprs := ifName(expr.MetaKeyIIFNAME, iface)
		exprs = append(exprs, ipv4Daddr(gw)...)
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, uint16(port))},
			&expr.Verdict{Kind: expr.VerdictAccept},
		)
		c.AddRule(&nftables.Rule{Table: t, Chain: input, Exprs: exprs})
	}
	drop := []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}
	// The gateway address answers only on wg0, whatever the weak host model would accept.
	notWG := ifName(expr.MetaKeyIIFNAME, iface)
	notWG[1].(*expr.Cmp).Op = expr.CmpOpNeq
	c.AddRule(&nftables.Rule{Table: t, Chain: input, Exprs: append(append(notWG, ipv4Daddr(gw)...), drop...)})
	c.AddRule(&nftables.Rule{Table: t, Chain: input, Exprs: append(ifName(expr.MetaKeyIIFNAME, iface), drop...)})
	c.AddRule(&nftables.Rule{Table: t, Chain: forward, Exprs: append(ifName(expr.MetaKeyIIFNAME, iface), drop...)})
	c.AddRule(&nftables.Rule{Table: t, Chain: forward, Exprs: append(ifName(expr.MetaKeyOIFNAME, iface), drop...)})
	return c.Flush()
}

func ipv4Daddr(a netip.Addr) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a.AsSlice()},
	}
}

func ifName(key expr.MetaKey, name string) []expr.Any {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b},
	}
}
