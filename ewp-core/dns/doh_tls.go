package dns

import (
	"crypto/tls"

	"ewp-core/common/cabundle"
)

// dohTLSConfig returns the *tls.Config used by DoH HTTP clients.
//
// MinVersion is TLS 1.2 — TLS 1.3 was originally hard-required here,
// but several mainland-China-friendly DoH endpoints we ship by default
// (notably doh.pub / 120.53.53.53 / 1.12.12.12) only speak TLS 1.2,
// and Go's strict-version handshake rejects them with the symptom
// "[DoH Client] TLS handshake failed: EOF". 1.2 is still a sound
// privacy floor for DoH (forward-secret with ECDHE, AEAD-only ciphers
// after our cipher pruning at the std-lib defaults).
//
// AliDNS (223.5.5.5 / 223.6.6.6) and 1.1.1.1 / 8.8.8.8 already speak
// 1.3, so on those we still get 1.3 — this floor only matters for
// the laggard endpoints.
//
// CurvePreferences keeps PQ-hybrid first; servers that don't
// understand X25519MLKEM768 quietly fall back to X25519.
//
// Embedded Mozilla trust store (NOT system CAs) so an enterprise MITM
// proxy with a planted root cert can't silently intercept this layer.
//
// We do NOT depend on common/tls here because common/tls itself
// imports this package for its ECH bootstrap; both go through the
// leaf cabundle pkg instead.
func dohTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		RootCAs:    cabundle.MozillaPool(),
		MinVersion: tls.VersionTLS12,
		// ALPN MUST stay h2-only. Adding "http/1.1" as a fallback
		// causes 223.5.5.5 (AliDNS) to RST the connection — confirmed
		// from a wireshark capture diff: ALPN len=14 (h2+http/1.1)
		// gets RST/FIN, ALPN len=5 (h2-only) succeeds. Some hardened
		// CDN/DoH frontends key on the exact ALPN list shape; don't
		// touch this without retesting from a CN egress.
		NextProtos: []string{"h2"},
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
	}
}
