package jail

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	netlinkNetfilter = 12 // NETLINK_NETFILTER
	nfnlgrpNftables  = 7  // NFNLGRP_NFTABLES
)

// watchNFT calls fn when anything changes nftables rules (a `nft flush ruleset`, a firewall
// reload), so a flushed table is put back within about two seconds instead of at the next config
// poll. Events are collapsed: fn runs at most once per 500 ms. It returns an error if the
// notifications are not available; the periodic check still covers that case.
func watchNFT(ctx context.Context, fn func()) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 << (nfnlgrpNftables - 1), Pid: uint32(os.Getpid()) + 1<<20}); err != nil {
		return err
	}
	tv := unix.NsecToTimeval(500e6)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	buf := make([]byte, 1<<16)
	var pending bool
	var last time.Time
	for ctx.Err() == nil {
		_, _, err := unix.Recvfrom(fd, buf, 0)
		switch {
		case err == nil || errors.Is(err, unix.ENOBUFS):
			pending = true
		case errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR):
		default:
			return err
		}
		if pending && time.Since(last) >= 500*time.Millisecond {
			pending, last = false, time.Now()
			fn()
		}
	}
	return nil
}

// reapply puts the ruleset back if our table was removed behind our back.
func (e *enforcer) reapply() {
	// Apply and Teardown hold the lock while they wait for this watcher to stop: never wait for them.
	if !e.mu.TryLock() {
		return
	}
	defer e.mu.Unlock()
	if e.rules == "" || tableExists() {
		return
	}
	if err := nft(e.rules); err != nil {
		log.Printf("jail: putting the rules back: %v", err)
		return
	}
	log.Printf("jail: the nftables table was removed; it is back")
}
