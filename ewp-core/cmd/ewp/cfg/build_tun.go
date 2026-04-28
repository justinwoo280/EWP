//go:build !android

package cfg

import (
	"errors"
	"fmt"

	"ewp-core/engine"
	"ewp-core/transport"
	"ewp-core/tun"
)

// BypassSink is invoked once, after Setup() detects the physical
// outbound interface and constructs a dialer bound to it. main wires
// this to broadcast the bypass dialer to every transport and to the
// client-side DoH resolver — without that broadcast the resolver and
// the ewpclient outbound dial through the OS routing table, get
// caught by the TUN's default route, and infinite-loop.
//
// Safe to leave nil for tests; production must always set it.
type BypassSink func(*transport.BypassConfig)

// buildTUNInbound builds a TUN inbound from yaml. Only available on
// non-android builds; mobile bindings construct their own TUN via
// the OS-supplied file descriptor in package ewpmobile.
func buildTUNInbound(c InboundCfg, onBypass BypassSink) (engine.Inbound, error) {
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
		IP:         c.TUN.Address,
		DNS:        dnsv4,
		IPv6DNS:    dnsv6,
		MTU:        mtu,
		Stack:      "gvisor",
		ServerAddr: c.TUN.BypassServer,
	}
	if onBypass != nil {
		// tun.Config.OnBypass is invoked synchronously inside Setup()
		// once the physical interface is detected. We hand the result
		// straight to main's BypassSink.
		tcfg.OnBypass = func(b *transport.BypassConfig) { onBypass(b) }
	}
	t, err := tun.New(tcfg)
	if err != nil {
		return nil, fmt.Errorf("tun inbound: %w", err)
	}
	if err := t.Setup(); err != nil {
		return nil, fmt.Errorf("tun setup: %w", err)
	}
	return t.AsInbound(c.Tag), nil
}
