// Package cfg loads and validates the unified engine configuration
// and turns it into concrete inbound/outbound/router instances.
package cfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"ewp-core/engine"
	v2 "ewp-core/protocol/ewp/v2"
)

// File is the top-level config struct mapped from YAML/JSON.
// File is the unified ech-workers engine config.
//
// The DNS surface area is intentionally minimal in v2:
//
//   - Client.DoH.Servers — the ONLY client-side DoH knob.  Used at
//     startup to (a) resolve the upstream EWP server's domain to an
//     IP and (b) fetch the ECH HTTPS RR.  After bootstrap completes
//     the client never touches DoH again; everything else is data
//     plane (apps' DNS queries either get FakeIP'd locally or are
//     forwarded over the tunnel for the server to handle).
//
//   - DNS.Server.Upstream.Servers — the server-side DoH list used
//     by the direct outbound to resolve DOMAIN targets the tunnel
//     delivered.  Has nothing to do with the client.
//
// Older fields (ECH.BootstrapDoH, ServerNameDNS, DNS.Client) are no
// longer recognised; their yaml/json keys are silently ignored to
// keep stale configs from crashing.
type File struct {
	Inbounds  []InboundCfg  `yaml:"inbounds" json:"inbounds"`
	Outbounds []OutboundCfg `yaml:"outbounds" json:"outbounds"`
	Router    RouterCfg     `yaml:"router" json:"router"`
	DNS       DNSCfg        `yaml:"dns" json:"dns"`
	STUN      STUNCfg       `yaml:"stun" json:"stun"`

	// Client.DoH.Servers is the single client-side DoH list. See
	// File doc-comment for semantics.
	Client ClientCfg `yaml:"client" json:"client"`
}

// ClientCfg holds client-side bootstrap settings.
type ClientCfg struct {
	DoH UpstreamDoHCfg `yaml:"doh" json:"doh"`
}

// DefaultClientDoH is the fallback DoH list applied when
// client.doh.servers is not configured. Picked for accessibility from
// networks that block 1.1.1.1 / 8.8.8.8 (notably mainland China):
// AliDNS + Tencent DNSPod, both of which have first-class DoH
// endpoints and are reachable without prior tunneling.
var DefaultClientDoH = []string{
	"https://223.5.5.5/dns-query",
	"https://223.6.6.6/dns-query",
	"https://doh.pub/dns-query",
}

// DNSCfg holds server-side DNS configuration.  In v2 there is no
// "client DNS policy" knob — application DNS traffic is just regular
// UDP and gets handled the same way every other UDP flow does (TUN
// FakeIP fast-path or forward to server).
type DNSCfg struct {
	Server ServerDNSCfg `yaml:"server" json:"server"`
}

// ServerDNSCfg controls how the server-side direct outbound resolves
// DOMAIN targets passed in by remote clients.
type ServerDNSCfg struct {
	Upstream UpstreamDoHCfg `yaml:"upstream" json:"upstream"`
}

// UpstreamDoHCfg configures an AsyncResolver instance.
type UpstreamDoHCfg struct {
	Servers    []string `yaml:"servers" json:"servers"`
	CacheSize  int      `yaml:"cache_size" json:"cache_size"`
	WorkerPool int      `yaml:"worker_pool" json:"worker_pool"`
	MinTTLSec  int      `yaml:"min_ttl_sec" json:"min_ttl_sec"`
	MaxTTLSec  int      `yaml:"max_ttl_sec" json:"max_ttl_sec"`
}

// STUNCfg configures the optional reflexive-address discovery the
// server performs at startup. The result is reported in
// UDP_PROBE_RESP frames so clients can do NAT-type inference over
// the v2 tunnel without leaking STUN traffic outside it.
type STUNCfg struct {
	Servers []string `yaml:"servers" json:"servers"`
}

// RouterCfg is intentionally minimal in commit 7: a single default
// outbound tag. Rule-based routing is a follow-up.
type RouterCfg struct {
	Default string `yaml:"default" json:"default"`
}

type InboundCfg struct {
	Tag    string         `yaml:"tag" json:"tag"`
	Type   string         `yaml:"type" json:"type"`
	Listen string         `yaml:"listen" json:"listen"` // for socks5/http/ewpserver
	Users  map[string]string `yaml:"users" json:"users"` // socks5 only

	// EWP server inbound:
	UUIDs     []string  `yaml:"uuids" json:"uuids"`
	Transport TransportCfg `yaml:"transport" json:"transport"`

	// TUN inbound:
	TUN TUNCfg `yaml:"tun" json:"tun"`
}

type OutboundCfg struct {
	Tag       string       `yaml:"tag" json:"tag"`
	Type      string       `yaml:"type" json:"type"`
	UUID      string       `yaml:"uuid" json:"uuid"`         // ewpclient
	Server    string       `yaml:"server" json:"server"`     // ewpclient
	Transport TransportCfg `yaml:"transport" json:"transport"`
}

type TransportCfg struct {
	Kind string `yaml:"kind" json:"kind"` // "websocket" | "grpc" | "h3grpc" | "xhttp"
	URL  string `yaml:"url" json:"url"`
	SNI  string `yaml:"sni" json:"sni"`
	Host string `yaml:"host" json:"host"`
	Path string `yaml:"path" json:"path"`
	ECH  bool   `yaml:"ech" json:"ech"`

	// ECHDomain is the host we query for the ECH HTTPS resource record.
	// Empty means "infer from sni / url" — fine for the common case
	// where the server hosts its own ECH config. Cloudflare-fronted
	// deployments must set this to "cloudflare-ech.com" because
	// Cloudflare manages ECH keys centrally on a public domain that
	// has no relation to your backend's URL.
	ECHDomain string `yaml:"ech_domain" json:"ech_domain"`

	// Server side TLS:
	CertFile string `yaml:"cert" json:"cert"`
	KeyFile  string `yaml:"key" json:"key"`
}

// TUNCfg configures a TUN inbound.  bypass_server is a removed v1
// field — sing-tun's DefaultInterfaceMonitor learns the physical
// egress NIC continuously and dialer Control funcs always bind to
// the current default interface, so no startup-time hint is needed.
// yaml.v3 silently ignores unknown keys, so stale configs still load.
type TUNCfg struct {
	Name      string   `yaml:"name" json:"name"`
	Address   string   `yaml:"address" json:"address"`       // IPv4 in CIDR, e.g. "10.233.0.2/24"
	AddressV6 string   `yaml:"address_v6" json:"address_v6"` // IPv6 in CIDR, e.g. "fd00:5ca1:e::2/64"; optional
	MTU       int      `yaml:"mtu" json:"mtu"`
	DNS       []string `yaml:"dns" json:"dns"`               // [v4-dns, v6-dns]; both optional
	FakeIP    bool     `yaml:"fake_ip" json:"fake_ip"`       // FakeIP DNS short-circuit (sub-ms reply)
}

// Load parses the file at path. Format is detected by extension.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f File
	switch {
	case strings.HasSuffix(path, ".json"):
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse json: %w", err)
		}
	default:
		if err := yaml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse yaml: %w", err)
		}
	}
	if err := validate(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

func validate(f *File) error {
	if len(f.Inbounds) == 0 {
		return errors.New("at least one inbound is required")
	}
	if len(f.Outbounds) == 0 {
		return errors.New("at least one outbound is required")
	}
	if f.Router.Default == "" {
		// Default to the first outbound's tag.
		f.Router.Default = f.Outbounds[0].Tag
	}
	applyClientDoHDefaults(f)
	return nil
}

// applyClientDoHDefaults fills f.Client.DoH.Servers from the built-in
// fallback list when the user did not set it. After this call the
// rest of the codebase always reads f.Client.DoH.Servers and never
// has to think about defaulting.
func applyClientDoHDefaults(f *File) {
	if len(f.Client.DoH.Servers) == 0 {
		f.Client.DoH.Servers = DefaultClientDoH
	}
}

// BuildRouter returns the engine.Router instance.
func BuildRouter(rc RouterCfg) (engine.Router, error) {
	if rc.Default == "" {
		return nil, errors.New("router.default is required")
	}
	return &engine.StaticRouter{Tag: rc.Default}, nil
}

// parseUUID parses a hex-form UUID like "01020304-0506-0708-090a-0b0c0d0e0f10".
// It accepts both with and without hyphens.
func parseUUID(s string) ([16]byte, error) {
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return [16]byte{}, fmt.Errorf("uuid: want 32 hex chars, got %d", len(clean))
	}
	var out [16]byte
	for i := 0; i < 16; i++ {
		v, err := hexByte(clean[i*2 : i*2+2])
		if err != nil {
			return [16]byte{}, err
		}
		out[i] = v
	}
	return out, nil
}

func hexByte(s string) (byte, error) {
	if len(s) != 2 {
		return 0, fmt.Errorf("hex: bad len")
	}
	hi, err := hexNib(s[0])
	if err != nil {
		return 0, err
	}
	lo, err := hexNib(s[1])
	if err != nil {
		return 0, err
	}
	return hi<<4 | lo, nil
}

func hexNib(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("hex: bad char %q", c)
}

// parseUUIDs is a small helper used by ewpserver inbound.
func parseUUIDs(in []string) ([][v2.UUIDLen]byte, error) {
	if len(in) == 0 {
		return nil, errors.New("at least one UUID is required")
	}
	out := make([][v2.UUIDLen]byte, 0, len(in))
	for _, s := range in {
		u, err := parseUUID(s)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// silence unused-import for time when builds drop the helper.
var _ = time.Second
