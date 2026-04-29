package cfg

import (
	"errors"
	"fmt"
	"net"
	neturl "net/url"
	"os"

	"ewp-core/common/clientdns"
	commontls "ewp-core/common/tls"
	"ewp-core/engine"
	httpinb "ewp-core/inbound/http"
	"ewp-core/inbound/socks5"
	"ewp-core/outbound/direct"
	"ewp-core/outbound/ewpclient"
	"ewp-core/transport"
	"ewp-core/transport/grpc"
	"ewp-core/transport/h3grpc"
	"ewp-core/transport/websocket"
	"ewp-core/transport/xhttp"
)

// BuildInbound returns the engine.Inbound for the given config block.
//
// Supported types: "tun", "socks5", "http", "ewpserver".
func BuildInbound(c InboundCfg) (engine.Inbound, error) {
	switch c.Type {
	case "socks5":
		if c.Listen == "" {
			return nil, errors.New("socks5 inbound: listen is required")
		}
		return socks5.New(c.Tag, c.Listen, c.Users), nil

	case "http":
		if c.Listen == "" {
			return nil, errors.New("http inbound: listen is required")
		}
		return httpinb.New(c.Tag, c.Listen), nil

	case "ewpserver":
		return buildEWPServerInbound(c)

	case "tun":
		return buildTUNInbound(c)

	default:
		return nil, fmt.Errorf("unknown inbound type %q", c.Type)
	}
}

// BuildServerNameResolver constructs a *clientdns.Resolver from the
// client.doh block. The returned resolver is shared by every
// ewpclient outbound to translate the upstream EWP server's domain
// to an IP at Dial time, AND by buildClientTransport's ECHManager
// for HTTPS-RR fetch.  A single client-side DoH list does both jobs.
func BuildServerNameResolver(c ClientCfg) (*clientdns.Resolver, error) {
	return clientdns.New(clientdns.Config{
		Servers: c.DoH.Servers,
	})
}

// BuildOutbound returns the engine.Outbound for the given config
// block. Supported types: "direct", "ewpclient".
//
// echBootstrap is the resolver list used by the ECH manager to fetch
// HTTPS resource records at startup. It is independent of any other
// DoH path so that ECH bootstrap cannot deadlock on a not-yet-built
// tunnel. Pass nil for "ECH disabled" outbounds.
func BuildOutbound(c OutboundCfg, echBootstrap []string, resolver *clientdns.Resolver) (engine.Outbound, error) {
	switch c.Type {
	case "direct":
		return direct.New(c.Tag, 0), nil // 0 = use direct's default dial timeout

	case "ewpclient":
		uuid, err := parseUUID(c.UUID)
		if err != nil {
			return nil, fmt.Errorf("ewpclient %q: uuid: %w", c.Tag, err)
		}
		t, err := buildClientTransport(c.Transport, echBootstrap, resolver)
		if err != nil {
			return nil, fmt.Errorf("ewpclient %q: %w", c.Tag, err)
		}
		return ewpclient.New(c.Tag, t, uuid), nil

	default:
		return nil, fmt.Errorf("unknown outbound type %q", c.Type)
	}
}

// buildClientTransport translates a YAML transport block into a
// concrete transport.Transport instance. URL is the upstream server
// (e.g. "wss://vps.example/path"); SNI/Host overrides apply when set.
//
// ECH is configured per-transport via a managed ECH config list
// retrieved from DNS at construction time. Empty ECH config means
// no ECH (plain TLS). MozillaCA toggles the embedded CA bundle.
//
// PQC is always on for v2: the inner SecureStream uses
// X25519+ML-KEM-768 hybrid; the outer TLS layer here mirrors that
// posture by including X25519MLKEM768 in CurvePreferences.
func buildClientTransport(c TransportCfg, echBootstrap []string, resolver *clientdns.Resolver) (transport.Transport, error) {
	if c.URL == "" {
		return nil, errors.New("transport.url is required")
	}
	addr, path, isTLS, err := splitURL(c.URL)
	if err != nil {
		return nil, fmt.Errorf("url: %w", err)
	}
	if c.Path != "" {
		path = c.Path
	}

	const (
		useMozillaCA = true // safer default than relying on system CA
		enablePQC    = true // v2 mandates PQ in the outer TLS too
	)

	var echMgr *commontls.ECHManager
	if c.ECH {
		// echBootstrap explicitly takes precedence over the
		// manager's built-in default DoH list — that's the whole
		// point of having a dedicated ech.bootstrap_doh block in
		// the YAML.
		// Resolve which domain holds the ECH HTTPS RR.
		// Priority: explicit ech_domain > sni > url-host. Centralised
		// ECH (Cloudflare-style) lives on a totally unrelated public
		// domain (cloudflare-ech.com), so the URL host is the wrong
		// default in that case — users opt-in by setting ech_domain.
		echDomain := c.ECHDomain
		if echDomain == "" {
			echDomain = c.SNI
		}
		if echDomain == "" {
			echDomain = addrHost(addr)
		}
		if len(echBootstrap) > 0 {
			echMgr = commontls.NewECHManager(echDomain, echBootstrap...)
		} else {
			echMgr = commontls.NewECHManager(echDomain)
		}
		// Synchronously prefetch the HTTPS RR NOW, before any inbound
		// (notably TUN) gets a chance to take over the routing table.
		// V1 did this and never had the "wireshark sees zero TLS
		// ClientHellos" problem -- v2's lazy Get() in transport.Dial()
		// races the TUN setup and triggers the loop. Refresh() failure
		// is non-fatal: the manager will retry on first use, but the
		// user is informed via stderr immediately rather than getting
		// silent EOFs minutes later.
		if err := echMgr.Refresh(); err != nil {
			fmt.Fprintf(os.Stderr, "ECH bootstrap warning: %v "+
				"(will retry lazily; if TUN is enabled this is likely to deadlock)\n", err)
		}
	}

	var (
		tr  transport.Transport
		buildErr error
	)

	effectiveSNI := c.SNI
	if effectiveSNI == "" {
		effectiveSNI = c.Host
	}

	switch c.Kind {
	case "ws", "websocket":
		// Plain WS only when scheme says ws:// AND ECH wasn't asked for.
		// (ECH on a non-TLS leg is a contradiction; refuse rather than
		//  silently downgrade.)
		var t *websocket.Transport
		if !isTLS {
			if c.ECH {
				return nil, errors.New("transport.ech requires wss:// or https:// — got plain scheme")
			}
			t = websocket.NewPlain(addr, path)
		} else {
			t = websocket.New(addr, path, c.ECH, useMozillaCA, enablePQC, echMgr)
		}
		if c.Host != "" {
			t.SetHost(c.Host)
		}
		if effectiveSNI != "" {
			t.SetSNI(effectiveSNI)
		}
		t.SetClientResolver(resolver)
		tr = t

	case "grpc":
		t := grpc.New(addr, path, c.ECH, useMozillaCA, enablePQC, echMgr)
		if c.Host != "" {
			t.SetHost(c.Host)
		}
		if effectiveSNI != "" {
			t.SetSNI(effectiveSNI)
		}
		t.SetClientResolver(resolver)
		tr = t

	case "xhttp":
		t := xhttp.New(addr, path, c.ECH, useMozillaCA, enablePQC, echMgr)
		if c.Host != "" {
			t.SetHost(c.Host)
		}
		if effectiveSNI != "" {
			t.SetSNI(effectiveSNI)
		}
		t.SetClientResolver(resolver)
		tr = t

	case "h3grpc", "h3":
		t := h3grpc.New(addr, path, c.ECH, useMozillaCA, enablePQC, echMgr)
		if c.Host != "" {
			t.SetHost(c.Host)
		}
		if effectiveSNI != "" {
			t.SetSNI(effectiveSNI)
		}
		t.SetClientResolver(resolver)
		tr = t

	default:
		return nil, fmt.Errorf("unknown transport kind %q", c.Kind)
	}

	if buildErr != nil {
		return nil, buildErr
	}
	return tr, nil
}

// splitURL turns "wss://host:443/some/path" into ("host:443",
// "/some/path", true). The bool reports whether the scheme implies
// TLS — currently only `ws://` and `http://` opt OUT (used for
// reverse-tunnel deployments where TLS is terminated by an outer
// hop like frp / cloudflared / ngrok).
func splitURL(raw string) (addr, path string, isTLS bool, err error) {
	u, err := neturl.Parse(raw)
	if err != nil {
		return "", "", false, err
	}
	if u.Host == "" {
		return "", "", false, errors.New("missing host")
	}
	addr = u.Host
	scheme := u.Scheme
	// Default port + tls determination per scheme.
	switch scheme {
	case "ws", "http":
		isTLS = false
		if _, _, e := net.SplitHostPort(addr); e != nil {
			addr = net.JoinHostPort(addr, "80")
		}
	case "wss", "https", "h3", "h3grpc", "":
		isTLS = true
		if _, _, e := net.SplitHostPort(addr); e != nil {
			addr = net.JoinHostPort(addr, "443")
		}
	default:
		isTLS = true
		if _, _, e := net.SplitHostPort(addr); e != nil {
			addr = net.JoinHostPort(addr, "443")
		}
	}
	path = u.Path
	if path == "" {
		path = "/"
	}
	return addr, path, isTLS, nil
}

// addrHost strips the port off "host:port" for SNI/ECH purposes.
func addrHost(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
