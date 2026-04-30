//go:build !android

package cfg

import (
	"errors"
	"fmt"
	"time"

	"ewp-core/engine"
	"ewp-core/tun"
)

// buildTUNInbound builds a TUN inbound from yaml. Only available on
// non-android builds; mobile bindings construct their own TUN via
// the OS-supplied file descriptor in package ewpmobile.
//
// No external bypass-dialer plumbing is needed: sing-tun's
// DefaultInterfaceMonitor watches kernel routing in real time and
// dialer Control funcs always bind to the current physical egress
// NIC.  See package tun's InterfaceMonitor() for the modern way to
// bind out-of-TUN sockets.
func buildTUNInbound(c InboundCfg) (engine.Inbound, error) {
	if c.TUN.Address == "" {
		return nil, errors.New("tun inbound: tun.address (e.g. 198.18.0.1/24) is required")
	}
	dnsv4 := ""
	dnsv6 := ""
	if len(c.TUN.DNS) > 0 {
		dnsv4 = c.TUN.DNS[0]
	}
	if len(c.TUN.DNS) > 1 {
		dnsv6 = c.TUN.DNS[1]
	}
	mtu := c.TUN.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	tcfg := &tun.Config{
		IP:       c.TUN.Address,
		IPv6:     c.TUN.AddressV6,
		Inet4DNS: dnsv4,
		Inet6DNS: dnsv6,
		MTU:      mtu,
		Stack:    "system",
	}
	if c.TUN.UDPTimeoutSec > 0 {
		tcfg.UDPTimeout = time.Duration(c.TUN.UDPTimeoutSec) * time.Second
	}
	t, err := tun.New(tcfg)
	if err != nil {
		return nil, fmt.Errorf("tun inbound: %w", err)
	}
	return t.AsInbound(c.Tag), nil
}
