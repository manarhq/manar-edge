package jail

import (
	"fmt"
	"log"
	"net"
)

func newPlatform() (platform, error) {
	if err := Supported(); err != nil {
		return nil, err
	}
	return newEnforcer(), nil
}

func platformCleanupErrs() []error { return Teardown() }

// startProxy listens on 127.0.0.1 and ::1 (the nat rule redirects to whichever matches the
// destination's family) on one port, and serves the tool's transparent proxy there.
func (r *runner) startProxy(tool string) (*toolProxy, error) {
	var l4, l6 net.Listener
	var port int
	for range 5 {
		var err error
		if l4, err = net.Listen("tcp4", "127.0.0.1:0"); err != nil {
			return nil, err
		}
		port = l4.Addr().(*net.TCPAddr).Port
		if l6, err = net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port)); err == nil {
			break
		}
		l4.Close() // the port is taken on ::1: try another
		l4, l6 = nil, nil
	}
	if l4 == nil {
		l4, port = nil, 0
		var err error
		if l4, err = net.Listen("tcp4", "127.0.0.1:0"); err != nil {
			return nil, err
		}
		port = l4.Addr().(*net.TCPAddr).Port
		log.Printf("jail: no IPv6 loopback for %s: IPv6 connections are rejected", tool)
	}
	p := &Proxy{Tool: tool, Policy: r.policy, Asker: r.asker, OrigDst: OrigDst, Resolve: r.resolve, Log: log.Printf}
	tp := &toolProxy{port: port, lns: []net.Listener{l4}}
	go p.Serve(l4)
	if l6 != nil {
		tp.lns = append(tp.lns, l6)
		go p.Serve(l6)
	}
	return tp, nil
}
