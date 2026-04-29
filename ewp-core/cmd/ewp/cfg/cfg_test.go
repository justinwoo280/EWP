package cfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoad_FullExample exercises the full v2 schema.  Since the DNS
// surface area was deliberately simplified — there is no longer an
// `ech.bootstrap_doh`, `server_name_dns`, or `dns.client` block —
// only `client.doh.servers` covers all client-side bootstrap DNS.
func TestLoad_FullExample(t *testing.T) {
	yaml := `
inbounds:
  - tag: tun
    type: tun
    tun:
      address: 198.18.0.1/24
      address_v6: "fc00::1/64"
      mtu: 1500
      dns: ["198.18.0.2", "fc00::2"]
      fake_ip: true
  - tag: socks
    type: socks5
    listen: "127.0.0.1:1080"
    users:
      alice: "s3cret"

outbounds:
  - tag: my-vps
    type: ewpclient
    uuid: "01020304-0506-0708-090a-0b0c0d0e0f10"
    transport:
      kind: websocket
      url: "wss://vps.example.com/ewp"
      sni: "vps.example.com"
      ech: true
  - tag: out
    type: direct

router:
  default: my-vps

dns:
  server:
    upstream:
      servers: ["https://1.1.1.1/dns-query"]
      cache_size: 4096
      worker_pool: 4
      min_ttl_sec: 30
      max_ttl_sec: 1800

client:
  doh:
    servers: ["https://1.1.1.1/dns-query"]

stun:
  servers: ["stun.cloudflare.com:3478"]
`
	path := writeTemp(t, "cfg.yaml", yaml)
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(f.Inbounds); got != 2 {
		t.Errorf("inbounds = %d, want 2", got)
	}
	if got := len(f.Outbounds); got != 2 {
		t.Errorf("outbounds = %d, want 2", got)
	}
	if got := f.Router.Default; got != "my-vps" {
		t.Errorf("router.default = %q, want my-vps", got)
	}
	if got := len(f.DNS.Server.Upstream.Servers); got != 1 {
		t.Errorf("dns.server.upstream.servers = %d", got)
	}
	if got := len(f.Client.DoH.Servers); got != 1 {
		t.Errorf("client.doh.servers = %d", got)
	}
	if got := len(f.STUN.Servers); got != 1 {
		t.Errorf("stun.servers = %d", got)
	}
	if got := f.Inbounds[0].TUN.AddressV6; got != "fc00::1/64" {
		t.Errorf("tun.address_v6 = %q", got)
	}
	if got := f.Inbounds[1].Users["alice"]; got != "s3cret" {
		t.Errorf("socks5 user not parsed: %q", got)
	}
}

// TestLoad_DefaultsToFirstOutbound ensures that an unspecified router
// default falls back to the first outbound's tag.
func TestLoad_DefaultsToFirstOutbound(t *testing.T) {
	yaml := `
inbounds:
  - tag: a
    type: socks5
    listen: 127.0.0.1:1
outbounds:
  - tag: foo
    type: direct
`
	path := writeTemp(t, "default.yaml", yaml)
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := f.Router.Default; got != "foo" {
		t.Errorf("router.default = %q, want foo", got)
	}
}

// TestLoad_RequiresInbound asserts that an inbound-less config is rejected.
func TestLoad_RequiresInbound(t *testing.T) {
	yaml := `
outbounds:
  - tag: foo
    type: direct
`
	path := writeTemp(t, "no-inbound.yaml", yaml)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "inbound") {
		t.Errorf("got %v, want error mentioning inbound", err)
	}
}

// TestLoad_RequiresOutbound asserts that an outbound-less config is rejected.
func TestLoad_RequiresOutbound(t *testing.T) {
	yaml := `
inbounds:
  - tag: a
    type: socks5
    listen: 127.0.0.1:1
`
	path := writeTemp(t, "no-out.yaml", yaml)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "outbound") {
		t.Errorf("got %v, want error mentioning outbound", err)
	}
}

// TestParseUUID covers the two accepted forms (with and without
// dashes) plus the common error path.
func TestParseUUID(t *testing.T) {
	canonical := "01020304-0506-0708-090a-0b0c0d0e0f10"
	bare := "0102030405060708090a0b0c0d0e0f10"
	cases := []struct {
		in   string
		want byte // first byte
		err  bool
	}{
		{canonical, 0x01, false},
		{bare, 0x01, false},
		{"too-short", 0, true},
		{"01020304-XX06-0708-090a-0b0c0d0e0f10", 0, true},
	}
	for _, c := range cases {
		got, err := parseUUID(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseUUID(%q): want error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUUID(%q): %v", c.in, err)
			continue
		}
		if got[0] != c.want {
			t.Errorf("parseUUID(%q): first byte = 0x%02x, want 0x%02x", c.in, got[0], c.want)
		}
	}
}

// TestBuildAsyncResolver returns nil for empty servers and a real
// resolver otherwise.
func TestBuildAsyncResolver(t *testing.T) {
	if BuildAsyncResolver(UpstreamDoHCfg{}) != nil {
		t.Error("expected nil for empty servers")
	}
	r := BuildAsyncResolver(UpstreamDoHCfg{
		Servers:    []string{"https://1.1.1.1/dns-query"},
		CacheSize:  16,
		WorkerPool: 1,
	})
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
	_ = r.Close()
}

// TestApplyClientDoHDefaults_Empty: a config that omits client.doh
// gets DefaultClientDoH applied automatically. Callers don't need to
// special-case "user didn't configure DoH".
func TestApplyClientDoHDefaults_Empty(t *testing.T) {
	cfg := writeTemp(t, "minimal.yaml", `
inbounds:
  - tag: socks
    type: socks5
    listen: "127.0.0.1:1080"
outbounds:
  - tag: out
    type: direct
`)
	f, err := Load(cfg)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !sameStrSlice(f.Client.DoH.Servers, DefaultClientDoH) {
		t.Errorf("client.doh.servers not defaulted: %v", f.Client.DoH.Servers)
	}
}

// TestApplyClientDoHDefaults_Explicit: an explicit list is preserved
// and not overwritten by the default.
func TestApplyClientDoHDefaults_Explicit(t *testing.T) {
	cfg := writeTemp(t, "explicit.yaml", `
inbounds:
  - tag: socks
    type: socks5
    listen: "127.0.0.1:1080"
outbounds:
  - tag: out
    type: direct
client:
  doh:
    servers:
      - "https://my-private-doh/dns-query"
`)
	f, err := Load(cfg)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"https://my-private-doh/dns-query"}
	if !sameStrSlice(f.Client.DoH.Servers, want) {
		t.Errorf("client.doh.servers = %v, want %v", f.Client.DoH.Servers, want)
	}
}

// TestLoad_IgnoresLegacyFields: stale configs that still carry the
// removed `ech.bootstrap_doh` / `server_name_dns` / `dns.client`
// blocks must load without error — yaml unknown-key tolerance keeps
// users' existing files working until they migrate.
func TestLoad_IgnoresLegacyFields(t *testing.T) {
	yaml := `
inbounds:
  - tag: socks
    type: socks5
    listen: "127.0.0.1:1080"
outbounds:
  - tag: out
    type: direct
ech:
  bootstrap_doh:
    servers: ["https://legacy/dns-query"]
server_name_dns:
  doh:
    servers: ["https://legacy2/dns-query"]
dns:
  client:
    mode: fake-ip
`
	path := writeTemp(t, "legacy.yaml", yaml)
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v (legacy fields should be silently ignored)", err)
	}
}

func sameStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}
