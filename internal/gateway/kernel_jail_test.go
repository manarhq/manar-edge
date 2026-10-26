//go:build jail && linux

package gateway

import (
	"net/netip"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestKernelJail needs root and the wireguard module: sudo -E go test -tags jail ./internal/gateway.
// It runs in a fresh network namespace on a locked thread, so the host's interfaces are untouched.
func TestKernelJail(t *testing.T) {
	runtime.LockOSThread() // never unlocked: the thread is discarded with its namespace
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Skipf("unshare netns (needs root): %v", err)
	}
	key, _ := wgtypes.GeneratePrivateKey()
	k, err := SetupKernel("wgtest0", netip.MustParsePrefix("100.88.0.1/16"), 51820, key, []int{443, 3128})
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := wgtypes.GeneratePrivateKey()
	p2, _ := wgtypes.GeneratePrivateKey()
	peers := []WGPeer{
		{PublicKey: p1.PublicKey(), Addr: netip.MustParseAddr("100.88.0.17")},
		{PublicKey: p2.PublicKey(), Addr: netip.MustParseAddr("100.88.0.18")},
	}
	if err := k.SetPeers(peers); err != nil {
		t.Fatal(err)
	}
	if err := k.SetPeers(peers[1:]); err != nil {
		t.Fatal(err)
	}
	wg, _ := wgctrl.New()
	defer wg.Close()
	dev, err := wg.Device("wgtest0")
	if err != nil {
		t.Fatal(err)
	}
	if len(dev.Peers) != 1 || dev.Peers[0].PublicKey != p2.PublicKey() ||
		dev.Peers[0].AllowedIPs[0].String() != "100.88.0.18/32" || dev.ListenPort != 51820 {
		t.Fatalf("device %+v", dev)
	}
	c, _ := nftables.New()
	rules, err := c.GetRules(&nftables.Table{Family: nftables.TableFamilyINet, Name: FirewallTable},
		&nftables.Chain{Name: "input"})
	if err != nil || len(rules) != 4 {
		t.Fatalf("input rules %d %v", len(rules), err)
	}
	// Idempotent: a restart reuses the interface and replaces the table.
	if _, err := SetupKernel("wgtest0", netip.MustParsePrefix("100.88.0.1/16"), 51820, key, []int{443, 3128}); err != nil {
		t.Fatal(err)
	}
}
