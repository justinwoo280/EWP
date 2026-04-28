// Package websocket is the WebSocket-over-TLS outer transport for
// EWP v2. It carries opaque message-bounded bytes; all v2 protocol
// semantics live in protocol/ewp/v2.
package websocket

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lxzan/gws"

	"ewp-core/common/clientdns"
	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"
)

// Transport implements transport.Transport for WebSocket-over-TLS.
type Transport struct {
	serverAddr string
	path       string

	useECH       bool
	useMozillaCA bool
	enablePQC    bool
	echManager   *commontls.ECHManager

	// Optional overrides:
	host string // HTTP Host header (for fronting)
	sni  string // TLS SNI (for fronting)

	mu        sync.Mutex
	bypassCfg *transport.BypassConfig
	resolver  *clientdns.Resolver

	useTLS bool // false = plaintext WS for reverse-tunnel deployments
}

// SetClientResolver wires the privacy-preserving DoH resolver used to
// translate the EWP server's domain name to an IP at Dial time. Pass
// nil to fall back to the OS resolver.
func (t *Transport) SetClientResolver(r *clientdns.Resolver) {
	t.mu.Lock()
	t.resolver = r
	t.mu.Unlock()
}

// New constructs a v2 WebSocket transport using TLS (the standard
// internet-facing case). For plaintext (reverse-tunnel) deployments
// use NewPlain.
//
// serverAddr: "host:port" for the upstream TLS listener.
// path: HTTP path on the listener (e.g. "/ewp").
// useECH: enable Encrypted ClientHello.
// useMozillaCA: trust the embedded Mozilla bundle (recommended).
// enablePQC: include X25519MLKEM768 in CurvePreferences (recommended).
// echManager: optional pre-configured ECHManager; if nil and useECH
// is true, the default manager is created at Dial-time.
func New(serverAddr, path string, useECH, useMozillaCA, enablePQC bool, echManager *commontls.ECHManager) *Transport {
	if path == "" {
		path = "/"
	}
	return &Transport{
		serverAddr:   serverAddr,
		path:         path,
		useECH:       useECH,
		useMozillaCA: useMozillaCA,
		enablePQC:    enablePQC,
		echManager:   echManager,
		useTLS:       true,
	}
}

// NewPlain constructs a plaintext WebSocket transport. Only valid
// when the EWP server runs behind a reverse-tunnel (frp / cloudflared
// / ngrok / tailscale-funnel) that already terminates TLS at its
// edge. The application-layer EWP AEAD still defends the data.
func NewPlain(serverAddr, path string) *Transport {
	if path == "" {
		path = "/"
	}
	return &Transport{
		serverAddr: serverAddr,
		path:       path,
		useTLS:     false,
	}
}

func (t *Transport) Name() string { return "websocket" }

func (t *Transport) SetSNI(sni string)   { t.sni = sni }
func (t *Transport) SetHost(host string) { t.host = host }

func (t *Transport) SetBypassConfig(cfg *transport.BypassConfig) {
	t.mu.Lock()
	t.bypassCfg = cfg
	t.mu.Unlock()
}

func (t *Transport) bypass() *transport.BypassConfig {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bypassCfg
}

// Dial opens a new WebSocket tunnel and returns a v2 TunnelConn.
//
// The dial path is:
//   1. Build TLS config (TLS 1.3, optional ECH + Mozilla CA + PQ).
//   2. TCP-dial via the bypass dialer (TUN mode) or net.Dialer.
//   3. TLS-handshake.
//   4. Issue WS upgrade to t.path with t.host as Host header.
//   5. Wrap the resulting *gws.Conn in our Conn.
func (t *Transport) Dial() (transport.TunnelConn, error) {
	host, port, err := net.SplitHostPort(t.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("ws: bad serverAddr %q: %w", t.serverAddr, err)
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if bp := t.bypass(); bp != nil && bp.TCPDialer != nil {
		dialer = bp.TCPDialer
	}
	dialAddr := net.JoinHostPort(host, port)
	t.mu.Lock()
	resolver := t.resolver
	t.mu.Unlock()
	if resolver != nil {
		resolved, rerr := resolver.ResolveHostPort(context.Background(), dialAddr)
		if rerr != nil {
			return nil, fmt.Errorf("ws: client dns: %w", rerr)
		}
		dialAddr = resolved
	}

	httpHost := t.host
	if httpHost == "" {
		httpHost = host
	}
	header := http.Header{}
	header.Set("Host", httpHost)

	// Two dial paths depending on useTLS:
	//   useTLS == true  : dial TCP, do TLS-1.3 handshake (with optional
	//                     ECH), then upgrade WS over the *tls.Conn
	//   useTLS == false : dial TCP, upgrade WS directly over the raw
	//                     conn — for reverse-tunnel deployments where
	//                     TLS is terminated by the outer hop. The EWP
	//                     application-layer AEAD still defends data.
	var (
		conn   = newConn()
		netCon net.Conn
	)
	if t.useTLS {
		sni := t.sni
		if sni == "" {
			sni = host
		}
		cfg, err := commontls.NewSTDConfig(sni, t.useMozillaCA, t.enablePQC)
		if err != nil {
			return nil, fmt.Errorf("ws: tls cfg: %w", err)
		}
		tlsCfg, err := cfg.TLSConfig()
		if err != nil {
			return nil, err
		}
		tlsCfg.NextProtos = []string{"http/1.1"}
		if t.useECH && t.echManager != nil {
			echList, err := t.echManager.Get()
			if err != nil {
				return nil, fmt.Errorf("ws: ech fetch: %w", err)
			}
			tlsCfg.EncryptedClientHelloConfigList = echList
			tlsCfg.EncryptedClientHelloRejectionVerify = func(cs tls.ConnectionState) error {
				return errors.New("server rejected ECH")
			}
		}
		raw, err := dialer.DialContext(context.Background(), "tcp", dialAddr)
		if err != nil {
			return nil, fmt.Errorf("ws: tcp dial: %w", err)
		}
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("ws: tls handshake: %w", err)
		}
		log.V("[ws] TLS established (%s)", commontls.GetConnectionInfo(tc.ConnectionState()))
		netCon = tc
	} else {
		raw, err := dialer.DialContext(context.Background(), "tcp", dialAddr)
		if err != nil {
			return nil, fmt.Errorf("ws: tcp dial: %w", err)
		}
		log.V("[ws] plaintext WS to %s (TLS terminated by outer tunnel)", dialAddr)
		netCon = raw
	}

	scheme := "wss"
	if !t.useTLS {
		scheme = "ws"
	}
	target := url.URL{Scheme: scheme, Host: net.JoinHostPort(httpHost, port), Path: t.path}
	socket, _, err := gws.NewClientFromConn(conn, &gws.ClientOption{
		Addr:          target.String(),
		RequestHeader: header,
	}, netCon)
	if err != nil {
		_ = netCon.Close()
		return nil, fmt.Errorf("ws: upgrade: %w", err)
	}
	conn.attach(socket)
	go socket.ReadLoop()

	return conn, nil
}

// Compile-time check.
var _ transport.Transport = (*Transport)(nil)

// silence unused import warnings
var _ = strings.HasPrefix
