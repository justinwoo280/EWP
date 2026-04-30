package tun

// Package tun is the v2 TUN inbound. As of P0/sing-tun migration this
// file is a thin wrapper around sing-tun:
//
//   - sing-tun creates the OS device (wintun on Windows, /dev/net/tun
//     on Linux, utun on Darwin) and installs the routing table entries.
//   - sing-tun's stack ("system" by default, "gvisor" optional) demuxes
//     IP packets into per-flow TCP/UDP and hands them to our
//     singHandler, which forwards into the existing v2 dispatcher
//     (handler.go + tun_socket.go).
//
// Everything we previously hand-rolled (wgtun device, custom gVisor
// glue, per-OS netsh / iproute2 setup, bypass dialer probe) is gone --
// sing-tun owns the OS layer and provides DefaultInterfaceMonitor for
// out-of-TUN bypass without us juggling control.Func chains.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"

	"ewp-core/dns"
	"ewp-core/log"
)

// Config holds parameters for constructing a v2 TUN inbound.  In v2
// the TUN owns no transport: outbounds are reached via the engine,
// which is bound after construction via Handler.BindEngine.
type Config struct {
	// IPv4 address in CIDR form, e.g. "10.233.0.2/24".
	IP string
	// IPv6 address in CIDR form, e.g. "fd00:5ca1:e::2/64".  Optional.
	IPv6 string
	// MTU in bytes; 0 falls back to 1500.
	MTU int
	// Stack is one of "system" (default) or "gvisor".
	Stack string

	// Inet4DNS / Inet6DNS are the in-TUN DNS server IPs reported to
	// the OS via the TUN interface options.  Apps inside the TUN
	// will see these as their resolvers.  When FakeIP is enabled
	// those queries get short-circuited inside Handler.HandleUDP.
	Inet4DNS string
	Inet6DNS string

	// FileDescriptor adopts an existing TUN device instead of
	// asking sing-tun to create one. Used by ewpmobile on Android
	// where Java's VpnService gives us the fd. When non-zero,
	// sing-tun skips device creation AND OS routing setup (the
	// Android system handles routing via VpnService.Builder).
	FileDescriptor int

	// UDPTimeout is the lifetime of an idle UDP NAT entry inside
	// the sing-tun stack.  Zero falls back to defaultUDPTimeout
	// (5 minutes) which matches sing-box's chosen default and is a
	// safe fit for typical conntrack configurations.  sing-tun's
	// udpnat2.New panics with "invalid timeout" if it ever receives
	// zero, so this field MUST end up non-zero by the time we hand
	// StackOptions to NewStack().
	UDPTimeout time.Duration
}

// defaultUDPTimeout deliberately undercuts sing-box's 5-minute
// default and instead pins the value to RFC 4787 §4.3's recommended
// minimum (30 seconds).  The longer a UDP NAT entry survives, the
// longer-lived the side-channels become:
//
//   * On a colocated host, an observer can count outstanding UDP
//     mappings (ss -uapn | wc -l) to recover a smoothed history of
//     the user's recent UDP destinations — five minutes of history
//     vs thirty seconds is a meaningful privacy delta.
//   * In a full-cone NAT deployment the source port stays "callable"
//     by any third party for the duration of the mapping.  Five
//     minutes is a 10x larger reverse-attack window than 30s.
//   * sing-tun (and most user-space TUN stacks) do not implement
//     the protocol-aware UDP state machine that the Linux kernel's
//     nf_conntrack provides — DNS, NTP, STUN one-shots all stay in
//     the table for the same duration as a video call's RTP flow.
//     Lacking that selectivity, the only safe default is the floor.
//
// Real long-lived UDP flows (DTLS-VPN, SIP, persistent QUIC) keep
// the entry alive simply by exchanging packets, so the lower default
// only affects strictly idle mappings.  Operators with workloads that
// genuinely need longer mappings can opt in via tun.udp_timeout_sec
// in yaml — the escape hatch is one line, the safe default is global.
const defaultUDPTimeout = 30 * time.Second

// TUN is the v2 inbound device.  Created by New(); started by Start().
type TUN struct {
	device  tun.Tun
	stack   tun.Stack
	handler *Handler

	monitor       tun.DefaultInterfaceMonitor
	networkMon    tun.NetworkUpdateMonitor
	interfaceFind control.InterfaceFinder

	fakePool  *dns.FakeIPPool
	config    *Config
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// FakeIPPool returns the FakeIP pool owned by this TUN.  Used by the
// inbound binder to inject the same pool into the engine's DNS path.
func (t *TUN) FakeIPPool() *dns.FakeIPPool { return t.fakePool }

// InterfaceMonitor returns sing-tun's monitor so the rest of v2 can
// register dialer Control funcs that bind sockets to the current
// physical default interface.  Returns nil before Start().
func (t *TUN) InterfaceMonitor() tun.DefaultInterfaceMonitor { return t.monitor }

// InterfaceFinder returns the same finder used by the monitor so that
// control.BindToInterface can resolve interface index -> name without
// re-walking the kernel table.
func (t *TUN) InterfaceFinder() control.InterfaceFinder { return t.interfaceFind }

// buildTunOptions translates a v2 Config into the sing-tun Options
// struct WITHOUT touching the OS (no /dev/net/tun, no netlink). It
// is split out from New so unit tests can verify field propagation
// (IPv4/IPv6 prefixes, DNS, MTU, AutoRoute) without root or a TUN
// device. The non-OS-touching pieces (NetworkUpdateMonitor /
// DefaultInterfaceMonitor / InterfaceFinder) are filled in by New.
func buildTunOptions(cfg *Config) (tun.Options, error) {
	mtu := uint32(cfg.MTU)
	if mtu == 0 {
		mtu = 1500
	}

	v4Prefix, err := parseCIDRWith(cfg.IP, "/24")
	if err != nil {
		return tun.Options{}, fmt.Errorf("parse IPv4 address: %w", err)
	}
	prefixes := []netip.Prefix{v4Prefix}

	var v6Prefixes []netip.Prefix
	if cfg.IPv6 != "" {
		v6Prefix, err := parseCIDRWith(cfg.IPv6, "/64")
		if err != nil {
			return tun.Options{}, fmt.Errorf("parse IPv6 address: %w", err)
		}
		v6Prefixes = []netip.Prefix{v6Prefix}
	}

	dnsAddrs := make([]netip.Addr, 0, 2)
	if cfg.Inet4DNS != "" {
		if a, err := netip.ParseAddr(cfg.Inet4DNS); err == nil {
			dnsAddrs = append(dnsAddrs, a)
		}
	}
	if cfg.Inet6DNS != "" {
		if a, err := netip.ParseAddr(cfg.Inet6DNS); err == nil {
			dnsAddrs = append(dnsAddrs, a)
		}
	}

	// AutoRoute is OFF when an external fd is supplied: in that
	// scenario the OS (Android VpnService) already installed the
	// routes, and asking sing-tun to do it again will fail with
	// "operation not permitted" because the unprivileged app
	// can't manipulate the kernel routing table directly.
	autoRoute := cfg.FileDescriptor == 0

	return tun.Options{
		Name:           "ewp-tun",
		Inet4Address:   prefixes,
		Inet6Address:   v6Prefixes,
		MTU:            mtu,
		AutoRoute:      autoRoute,
		StrictRoute:    false,
		DNSServers:     dnsAddrs,
		FileDescriptor: cfg.FileDescriptor,
		Logger:         stubLogger{},
	}, nil
}

// New constructs a TUN device + stack but does NOT install routes
// yet.  Call Start() to bring the device up and let sing-tun install
// the routing table entries.
func New(cfg *Config) (*TUN, error) {
	ctx, cancel := context.WithCancel(context.Background())

	tunOpts, err := buildTunOptions(cfg)
	if err != nil {
		cancel()
		return nil, err
	}

	// FakeIP pool is always installed in v2 (sub-ms DNS, no tunnel
	// for queries).  Apps that disable FakeIP route DNS through the
	// engine like any other UDP, where the server-side resolver
	// handles them.
	fakeIPPool := dns.NewFakeIPPool()
	handler := NewHandler(ctx)
	handler.SetFakeIPPool(fakeIPPool)
	log.Printf("[TUN] FakeIP pool initialised (IPv4 198.18/15, IPv6 fc00::/112)")

	// sing-tun NetworkUpdateMonitor watches the kernel for routing
	// changes; the DefaultInterfaceMonitor uses it to expose the
	// current physical default interface.  Once the TUN is up, the
	// monitor automatically excludes the TUN device itself, which
	// is exactly what we need to bind out-of-TUN sockets.
	netMon, err := tun.NewNetworkUpdateMonitor(stubLogger{})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create network monitor: %w", err)
	}
	finder := control.NewDefaultInterfaceFinder()
	// The InterfaceFinder MUST be supplied via options here — sing-tun's
	// monitor.Start() immediately calls interfaceFinder.Update() with no
	// nil guard.  Forgetting it crashes the process on TUN start with a
	// nil pointer deref deep inside monitor_shared.go.
	ifaceMon, err := tun.NewDefaultInterfaceMonitor(netMon, stubLogger{}, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: finder,
	})
	if err != nil {
		_ = netMon.Close()
		cancel()
		return nil, fmt.Errorf("create interface monitor: %w", err)
	}

	// Wire the OS-touching fields that buildTunOptions intentionally
	// left blank.
	tunOpts.InterfaceFinder = finder
	tunOpts.InterfaceMonitor = ifaceMon

	dev, err := tun.New(tunOpts)
	if err != nil {
		_ = ifaceMon.Close()
		_ = netMon.Close()
		cancel()
		return nil, fmt.Errorf("create TUN device: %w", err)
	}

	stackName := cfg.Stack
	if stackName == "" {
		stackName = "system"
	}
	udpTimeout := cfg.UDPTimeout
	if udpTimeout <= 0 {
		udpTimeout = defaultUDPTimeout
	}
	st, err := tun.NewStack(stackName, tun.StackOptions{
		Context:                ctx,
		Tun:                    dev,
		TunOptions:             tunOpts,
		Handler:                newSingHandler(handler),
		Logger:                 stubLogger{},
		ForwarderBindInterface: true,
		IncludeAllNetworks:     false,
		InterfaceFinder:        finder,
		// UDPTimeout MUST be non-zero — sing-tun's stack_system.go
		// passes it straight into udpnat2.New() which panics on 0.
		UDPTimeout: udpTimeout,
	})
	if err != nil {
		_ = dev.Close()
		_ = ifaceMon.Close()
		_ = netMon.Close()
		cancel()
		return nil, fmt.Errorf("create stack %q: %w", stackName, err)
	}

	return &TUN{
		device:        dev,
		stack:         st,
		handler:       handler,
		monitor:       ifaceMon,
		networkMon:    netMon,
		interfaceFind: finder,
		fakePool:      fakeIPPool,
		config:        cfg,
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// Start brings the TUN device online and installs OS routing rules.
// Blocks until ctx (passed at New) is cancelled.
func (t *TUN) Start() error {
	if err := t.networkMon.Start(); err != nil {
		return fmt.Errorf("start network monitor: %w", err)
	}
	if err := t.monitor.Start(); err != nil {
		return fmt.Errorf("start interface monitor: %w", err)
	}
	if err := t.stack.Start(); err != nil {
		return fmt.Errorf("start stack: %w", err)
	}
	log.Printf("[TUN] started: stack=%s ipv4=%s ipv6=%s mtu=%d",
		stackName(t.config.Stack), t.config.IP, t.config.IPv6, t.MTU())
	<-t.ctx.Done()
	return nil
}

// MTU returns the configured MTU (or 1500 default).
func (t *TUN) MTU() uint32 {
	if t.config.MTU > 0 {
		return uint32(t.config.MTU)
	}
	return 1500
}

// Close tears the device down and unwinds the OS routing changes.
// Idempotent.
func (t *TUN) Close() error {
	t.closeOnce.Do(func() {
		log.Printf("[TUN] stopping")
		t.cancel()
		if t.stack != nil {
			_ = t.stack.Close()
		}
		if t.device != nil {
			_ = t.device.Close()
		}
		if t.monitor != nil {
			_ = t.monitor.Close()
		}
		if t.networkMon != nil {
			_ = t.networkMon.Close()
		}
		t.handler.Close()
	})
	return nil
}

// parseCIDRWith parses raw as a CIDR; if no `/` is present, applyDefault
// is appended (e.g. "/24" or "/64").
func parseCIDRWith(raw, applyDefault string) (netip.Prefix, error) {
	if raw == "" {
		return netip.Prefix{}, fmt.Errorf("empty address")
	}
	if !strings.Contains(raw, "/") {
		raw += applyDefault
	}
	return netip.ParsePrefix(raw)
}

func stackName(s string) string {
	if s == "" {
		return "system"
	}
	return s
}

// stubLogger is a minimal logger.Logger that forwards everything to
// our package logger.  sing-tun's logging is verbose by design; we
// downgrade most of it to V (verbose) so production logs stay clean.
type stubLogger struct{}

func (stubLogger) Trace(args ...any)                                  { log.V("[sing-tun] %v", args) }
func (stubLogger) Debug(args ...any)                                  { log.V("[sing-tun] %v", args) }
func (stubLogger) Info(args ...any)                                   { log.Printf("[sing-tun] %v", args) }
func (stubLogger) Warn(args ...any)                                   { log.Printf("[sing-tun] WARN %v", args) }
func (stubLogger) Error(args ...any)                                  { log.Printf("[sing-tun] ERR %v", args) }
func (stubLogger) Fatal(args ...any)                                  { log.Printf("[sing-tun] FATAL %v", args) }
func (stubLogger) Panic(args ...any)                                  { log.Printf("[sing-tun] PANIC %v", args) }
func (stubLogger) TraceContext(_ context.Context, args ...any)        { log.V("[sing-tun] %v", args) }
func (stubLogger) DebugContext(_ context.Context, args ...any)        { log.V("[sing-tun] %v", args) }
func (stubLogger) InfoContext(_ context.Context, args ...any)         { log.Printf("[sing-tun] %v", args) }
func (stubLogger) WarnContext(_ context.Context, args ...any)         { log.Printf("[sing-tun] WARN %v", args) }
func (stubLogger) ErrorContext(_ context.Context, args ...any)        { log.Printf("[sing-tun] ERR %v", args) }
func (stubLogger) FatalContext(_ context.Context, args ...any)        { log.Printf("[sing-tun] FATAL %v", args) }
func (stubLogger) PanicContext(_ context.Context, args ...any)        { log.Printf("[sing-tun] PANIC %v", args) }

// compile-time check that stubLogger satisfies sing's logger.Logger.
var _ logger.ContextLogger = stubLogger{}
