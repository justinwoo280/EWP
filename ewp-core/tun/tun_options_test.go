package tun

import (
	"net/netip"
	"testing"
)

// TestBuildTunOptions_IPv4Only locks in the baseline: a config with
// only an IPv4 address yields an Options with one v4 prefix, no v6
// prefixes, no DNS servers, default MTU 1500, and AutoRoute=true.
func TestBuildTunOptions_IPv4Only(t *testing.T) {
	cfg := &Config{IP: "10.233.0.2/24"}
	opts, err := buildTunOptions(cfg)
	if err != nil {
		t.Fatalf("buildTunOptions: %v", err)
	}

	if got := len(opts.Inet4Address); got != 1 {
		t.Fatalf("Inet4Address len = %d, want 1", got)
	}
	want := netip.MustParsePrefix("10.233.0.2/24")
	if opts.Inet4Address[0] != want {
		t.Errorf("Inet4Address[0] = %v, want %v", opts.Inet4Address[0], want)
	}

	if got := len(opts.Inet6Address); got != 0 {
		t.Errorf("Inet6Address len = %d, want 0 (no v6 in cfg)", got)
	}
	if got := len(opts.DNSServers); got != 0 {
		t.Errorf("DNSServers len = %d, want 0", got)
	}
	if opts.MTU != 1500 {
		t.Errorf("MTU = %d, want default 1500", opts.MTU)
	}
	if !opts.AutoRoute {
		t.Errorf("AutoRoute = false, want true (no external fd)")
	}
	if opts.FileDescriptor != 0 {
		t.Errorf("FileDescriptor = %d, want 0", opts.FileDescriptor)
	}
}

// TestBuildTunOptions_IPv6Propagated is the P2 acceptance test: a
// config carrying an IPv6 prefix + IPv6 DNS server must reach
// sing-tun via Options.Inet6Address and Options.DNSServers.  This
// pins down the v6 path so a future refactor can't silently break
// dual-stack TUN clients.
func TestBuildTunOptions_IPv6Propagated(t *testing.T) {
	cfg := &Config{
		IP:       "10.233.0.2/24",
		IPv6:     "fd00:5ca1:e::2/64",
		Inet4DNS: "10.233.0.1",
		Inet6DNS: "fd00:5ca1:e::1",
		MTU:      1420,
	}
	opts, err := buildTunOptions(cfg)
	if err != nil {
		t.Fatalf("buildTunOptions: %v", err)
	}

	// IPv4 + IPv6 prefixes both present.
	if got := len(opts.Inet4Address); got != 1 {
		t.Errorf("Inet4Address len = %d, want 1", got)
	}
	if got := len(opts.Inet6Address); got != 1 {
		t.Fatalf("Inet6Address len = %d, want 1", got)
	}
	wantV6 := netip.MustParsePrefix("fd00:5ca1:e::2/64")
	if opts.Inet6Address[0] != wantV6 {
		t.Errorf("Inet6Address[0] = %v, want %v", opts.Inet6Address[0], wantV6)
	}

	// Both DNS servers present, in v4-then-v6 order.
	if got := len(opts.DNSServers); got != 2 {
		t.Fatalf("DNSServers len = %d, want 2", got)
	}
	if got, want := opts.DNSServers[0], netip.MustParseAddr("10.233.0.1"); got != want {
		t.Errorf("DNSServers[0] = %v, want %v", got, want)
	}
	if got, want := opts.DNSServers[1], netip.MustParseAddr("fd00:5ca1:e::1"); got != want {
		t.Errorf("DNSServers[1] = %v, want %v", got, want)
	}

	if opts.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", opts.MTU)
	}
	if !opts.AutoRoute {
		t.Errorf("AutoRoute = false, want true")
	}
}

// TestBuildTunOptions_FileDescriptor verifies that supplying a
// non-zero FileDescriptor disables AutoRoute.  Android's VpnService
// already installs routes via VpnService.Builder; if we let sing-tun
// also try, the kernel rejects the netlink request with EPERM and
// the whole stack fails to come up.
func TestBuildTunOptions_FileDescriptor(t *testing.T) {
	cfg := &Config{
		IP:             "10.233.0.2/24",
		FileDescriptor: 42, // pretend Android handed us this
	}
	opts, err := buildTunOptions(cfg)
	if err != nil {
		t.Fatalf("buildTunOptions: %v", err)
	}
	if opts.FileDescriptor != 42 {
		t.Errorf("FileDescriptor = %d, want 42", opts.FileDescriptor)
	}
	if opts.AutoRoute {
		t.Errorf("AutoRoute = true, want false (external fd path)")
	}
}

// TestBuildTunOptions_BadIPv4 ensures malformed IPv4 input is
// surfaced as an error, not silently swallowed.
func TestBuildTunOptions_BadIPv4(t *testing.T) {
	cfg := &Config{IP: "not-an-ip"}
	if _, err := buildTunOptions(cfg); err == nil {
		t.Error("expected error for bad IPv4, got nil")
	}
}

// TestBuildTunOptions_BadIPv6 ensures malformed IPv6 input is
// surfaced as an error.  A missing v6 (empty string) is fine; only
// junk that fails to parse is rejected.
func TestBuildTunOptions_BadIPv6(t *testing.T) {
	cfg := &Config{
		IP:   "10.233.0.2/24",
		IPv6: "::not-valid::",
	}
	if _, err := buildTunOptions(cfg); err == nil {
		t.Error("expected error for bad IPv6, got nil")
	}
}

// TestBuildTunOptions_BareIPv4Address tests the implicit-CIDR path:
// "10.233.0.2" without a /N suffix should default to /24.
func TestBuildTunOptions_BareIPv4Address(t *testing.T) {
	cfg := &Config{IP: "10.233.0.2"}
	opts, err := buildTunOptions(cfg)
	if err != nil {
		t.Fatalf("buildTunOptions: %v", err)
	}
	want := netip.MustParsePrefix("10.233.0.2/24")
	if opts.Inet4Address[0] != want {
		t.Errorf("Inet4Address[0] = %v, want %v (bare addr default)", opts.Inet4Address[0], want)
	}
}

// TestBuildTunOptions_BareIPv6Address tests the implicit-CIDR path
// for v6: "fd00:5ca1:e::2" without /N should default to /64.
func TestBuildTunOptions_BareIPv6Address(t *testing.T) {
	cfg := &Config{
		IP:   "10.233.0.2/24",
		IPv6: "fd00:5ca1:e::2",
	}
	opts, err := buildTunOptions(cfg)
	if err != nil {
		t.Fatalf("buildTunOptions: %v", err)
	}
	want := netip.MustParsePrefix("fd00:5ca1:e::2/64")
	if opts.Inet6Address[0] != want {
		t.Errorf("Inet6Address[0] = %v, want %v (bare addr default)", opts.Inet6Address[0], want)
	}
}
