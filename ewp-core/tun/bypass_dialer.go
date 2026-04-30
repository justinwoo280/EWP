package tun

import (
	"net"
	"time"

	"github.com/sagernet/sing/common/control"
)

// MakeBypassDialer returns a *net.Dialer whose Control function pins
// every outgoing socket to the current physical default interface as
// reported by sing-tun's DefaultInterfaceMonitor.
//
// This is the missing piece that lets traffic from non-TUN-routed
// callers (most importantly the client.doh resolver and the ECH
// HTTPS-RR fetcher) escape past the TUN device once it has stolen
// the system default route.  Without it those callers TCP-dial via
// the OS default, get captured by the TUN, and either loop forever
// (DoH trying to resolve doh.pub via DoH) or time out silently.
//
// The returned Dialer reads the current default interface on every
// dial via the supplied TUN's monitor — interface flap (Wi-Fi -> 4G)
// is handled automatically by sing-tun's underlying NetworkMonitor,
// no callback re-registration needed on our side.
//
// Returns nil if the TUN is nil OR has not started yet (the monitor
// would itself be nil), in which case the caller should fall back to
// the OS default dialer.
func MakeBypassDialer(t *TUN) *net.Dialer {
	if t == nil {
		return nil
	}
	mon := t.InterfaceMonitor()
	if mon == nil {
		return nil
	}
	finder := t.InterfaceFinder()
	if finder == nil {
		return nil
	}
	bind := control.BindToInterfaceFunc(finder, func(network, address string) (string, int, error) {
		def := mon.DefaultInterface()
		if def == nil {
			// Monitor not yet observed an interface — let the
			// kernel pick.  This is racy but only happens during
			// the very first ms after Start().
			return "", -1, nil
		}
		return def.Name, def.Index, nil
	})
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   bind,
	}
}
