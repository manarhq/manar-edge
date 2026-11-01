package jail

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// Windows Filtering Platform. All of JAIL's filters live under one provider and one sublayer, so
// removing them is "delete the filters of the sublayer, then the sublayer, then the provider" and
// nothing else on the machine is touched. They are not persistent across a reboot: the service
// starts at boot and puts them back, and a machine whose service is gone has no leftover block.
//
// For each protected executable (matched by WFP's application id, i.e. the file's resolved path)
// at the ALE connect layers (IPv4 and IPv6):
//
//	permit  remote address is loopback   (the proxy, DOOR, local MCP servers)
//	permit  remote port 53 of a DNS server the machine is configured with (not any address)
//	block   everything else
const (
	wfpProviderName = "Manar JAIL"
	wfpSublayerName = "Manar JAIL egress"
	weightPermit    = 1000
	weightBlock     = 10
)

var (
	wfpProvider = wf.ProviderID(windows.GUID{Data1: 0xac8b1dc8, Data2: 0x5d12, Data3: 0x44c6, Data4: [8]byte{0xa4, 0xc3, 0xc2, 0x27, 0x21, 0xa8, 0xde, 0x94}})
	wfpSublayer = wf.SublayerID(windows.GUID{Data1: 0x87ca3dd4, Data2: 0x0660, Data3: 0x43d8, Data4: [8]byte{0xa4, 0x1c, 0x80, 0x8f, 0x67, 0x40, 0x26, 0x47}})
)

// wfpInstall replaces JAIL's filters with the set for exes. Executables that do not exist are
// skipped (WFP cannot name them) and reported in the error only if none could be used.
func wfpInstall(exes []string, resolvers []netip.Addr) error {
	s, err := wf.New(&wf.Options{Name: wfpProviderName, Description: "Manar JAIL session"})
	if err != nil {
		return fmt.Errorf("opening the filtering engine: %w", err)
	}
	defer s.Close()
	if err := removeAll(s); err != nil {
		return err
	}
	if err := s.AddProvider(&wf.Provider{ID: wfpProvider, Name: wfpProviderName, Description: "Egress filter for protected AI tools"}); err != nil {
		return fmt.Errorf("adding the provider: %w", err)
	}
	if err := s.AddSublayer(&wf.Sublayer{ID: wfpSublayer, Name: wfpSublayerName, Provider: wfpProvider, Weight: 0x7000}); err != nil {
		removeAll(s)
		return fmt.Errorf("adding the sublayer: %w", err)
	}
	used := 0
	var skipped []string
	for _, exe := range exes {
		app, err := wf.AppID(exe)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", exe, err))
			continue
		}
		if err := addExe(s, exe, app, resolvers); err != nil {
			removeAll(s)
			return err
		}
		used++
	}
	if used == 0 {
		removeAll(s)
		return fmt.Errorf("no executable could be filtered (%s)", strings.Join(skipped, "; "))
	}
	return nil
}

func addExe(s *wf.Session, exe, app string, resolvers []netip.Addr) error {
	name := filepath.Base(exe)
	appCond := &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: app}
	for _, v6 := range []bool{false, true} {
		layer, loop := wf.LayerALEAuthConnectV4, netip.MustParsePrefix("127.0.0.0/8")
		if v6 {
			layer, loop = wf.LayerALEAuthConnectV6, netip.MustParsePrefix("::1/128")
		}
		rules := []struct {
			what   string
			act    wf.Action
			weight uint64
			conds  []*wf.Match
		}{
			{"permit loopback", wf.ActionPermit, weightPermit, []*wf.Match{appCond, {Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: loop}}},
			{"block", wf.ActionBlock, weightBlock, []*wf.Match{appCond}},
		}
		for _, ns := range resolvers {
			if ns.Is6() != v6 {
				continue
			}
			rules = append(rules, struct {
				what   string
				act    wf.Action
				weight uint64
				conds  []*wf.Match
			}{"permit DNS " + ns.String(), wf.ActionPermit, weightPermit, []*wf.Match{appCond,
				{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(53)},
				{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: ns}}})
		}
		for _, r := range rules {
			id, err := windows.GenerateGUID()
			if err != nil {
				return err
			}
			if err := s.AddRule(&wf.Rule{
				ID: wf.RuleID(id), Name: "Manar JAIL " + r.what + " " + name, Layer: layer, Sublayer: wfpSublayer,
				Weight: r.weight, Conditions: r.conds, Action: r.act, Provider: wfpProvider,
			}); err != nil {
				return fmt.Errorf("adding a filter (%s %s): %w", r.what, name, err)
			}
		}
	}
	return nil
}

// wfpRemove deletes every JAIL filter, the sublayer and the provider. Nothing to remove is not an
// error.
func wfpRemove() error {
	s, err := wf.New(&wf.Options{Name: wfpProviderName, Description: "Manar JAIL cleanup"})
	if err != nil {
		return fmt.Errorf("opening the filtering engine: %w", err)
	}
	defer s.Close()
	return removeAll(s)
}

func removeAll(s *wf.Session) error {
	var errs []error
	rules, err := s.Rules()
	if err != nil {
		return fmt.Errorf("listing filters: %w", err)
	}
	for _, r := range rules {
		if r.Sublayer == wfpSublayer || r.Provider == wfpProvider {
			if err := s.DeleteRule(r.ID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) == 0 {
		if err := s.DeleteSublayer(wfpSublayer); err != nil && !notFound(err) {
			errs = append(errs, fmt.Errorf("sublayer: %w", err))
		}
		if err := s.DeleteProvider(wfpProvider); err != nil && !notFound(err) {
			errs = append(errs, fmt.Errorf("provider: %w", err))
		}
	}
	return errors.Join(errs...)
}

// FWP_E_*_NOT_FOUND
func notFound(err error) bool {
	var en windows.Errno
	if errors.As(err, &en) {
		switch uint32(en) {
		case 0x80320003, 0x80320005, 0x80320007, 0x80320008: // FWP_E_FILTER/PROVIDER/SUBLAYER/..._NOT_FOUND
			return true
		}
	}
	return false
}

// wfpFilterCount is the number of JAIL filters installed (0 when none).
func wfpFilterCount() (int, error) {
	s, err := wf.New(&wf.Options{Name: wfpProviderName, Description: "Manar JAIL check"})
	if err != nil {
		return 0, err
	}
	defer s.Close()
	rules, err := s.Rules()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rules {
		if r.Sublayer == wfpSublayer {
			n++
		}
	}
	return n, nil
}
