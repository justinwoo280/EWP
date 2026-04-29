# EWP v2 — example configurations

All configs in this directory drive the unified `cmd/ewp` binary:

```
ewp -config <file>.yaml
```

| File | Role |
|---|---|
| `client-socks5.yaml` | Local SOCKS5 proxy → ewpclient (WebSocket+ECH+ML-KEM) |
| `client-http.yaml` | Local HTTP CONNECT proxy → ewpclient |
| `client-tun.yaml` | OS-level TUN interface (TODO: still needs platform setup) |
| `server.yaml` | EWP-WebSocket listener + direct outbound (typical VPS deployment) |
| `relay.yaml` | EWP listener + ewpclient outbound (chain through another node) |

Replace placeholder values (`UUID`, `URL`, certificate paths) before running.

## UUID

Generate with `uuidgen` or any UUID v4 tool. The same UUID must be present on
both client (in `outbounds[].uuid`) and server (in `inbounds[].uuids`).

## TLS

Server-side TLS uses standard PEM cert/key. Get them from Let's Encrypt
(`certbot`) or any other CA. Client-side TLS uses the embedded Mozilla CA
bundle by default; no system trust store dependency.

## ECH

To enable ECH, set `ech: true` on the transport block and ensure your
server's domain has an HTTPS resource record advertising the ECH config.
The single `client.doh.servers` list is used at startup, exactly once,
to (a) resolve the upstream server's domain and (b) fetch the ECH HTTPS
RR. After bootstrap completes the client never touches DoH again.

For Cloudflare-fronted deployments add `ech_domain: cloudflare-ech.com`
on the transport block — Cloudflare publishes ECH keys on a public domain
that has no relation to your backend's URL.

## TUN routing

`client-tun.yaml` does not need any "bypass" hint. sing-tun's
`DefaultInterfaceMonitor` watches kernel routing in real time and dialer
Control funcs always bind to the current physical egress NIC, so the
ewpclient outbound's own packets can never loop back through the TUN.

## NAT diagnostics

The server side automatically discovers its public reflexive address at
startup if you set the `stun:` block (see `server.yaml`). Clients can ask
"what NAT am I behind?" with a one-shot probe:

```
ewp -config client-socks5.yaml \
    -probe-nat stun.cloudflare.com:3478
```

This sends one `UDP_PROBE_REQ` through the default ewpclient outbound and
prints the reflexive address the server saw, then exits.

## What's gone from v1

If you're migrating an existing config, drop these — they're either no-ops
in v2 or have been replaced:

- `appProtocol: trojan` / `protocol: trojan` — Trojan support removed.
- `flow: xtls-rprx-vision`, `enableFlow: true` — flow padding superseded
  by the v2 outer transport's framing.
- `xhttpMode: stream-down` — only `stream-one` is implemented (RPRX
  himself recommends against `stream-down`).
- `tunnel-doh-server` — DNS no longer rides the tunnel as its own flow.
- `ech.bootstrap_doh` / `server_name_dns` / `dns.client.mode` — collapsed
  into the single `client.doh.servers` list. Old keys still load (yaml
  unknown-key tolerance) but are ignored.
- `inbounds[].tun.bypass_server` — sing-tun's interface monitor
  obviates it; field removed from the schema. Old configs still load.
