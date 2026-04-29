package tun

// singHandler bridges sing-tun's Handler interface to the v2 ewp-core
// dispatcher in handler.go.  We implement the three callbacks
// sing-tun's stack invokes per accepted flow:
//
//   - PrepareConnection:     unused (no DirectRoute fast-path), return ErrNoRoute
//   - NewConnectionEx:       TCP — wrap conn, defer to Handler.HandleTCP
//   - NewPacketConnectionEx: UDP — pump packets, defer to Handler.HandleUDP
//
// The wrapper preserves the v2 invariants:
//   * one tunSocket per (src,dst) UDP flow, so multi-target NAT works
//   * FakeIP × Real-IP semantics are decided inside Handler / tunSocket,
//     not here — sing-tun gives us raw 4-tuples and we hand them through
//     unmodified.

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	singtun "github.com/sagernet/sing-tun"
)

// singHandler is the value passed to sing-tun's stack.Options.Handler.
// It owns a back-reference to our Handler and forwards events into it.
type singHandler struct {
	h *Handler
}

func newSingHandler(h *Handler) *singHandler { return &singHandler{h: h} }

// PrepareConnection is part of sing-tun's Handler interface; we don't
// use the DirectRoute fast-path, so always return ErrNoRoute (which
// makes sing-tun fall back to the regular TCP/UDP forwarders).
func (s *singHandler) PrepareConnection(
	network string,
	source M.Socksaddr,
	destination M.Socksaddr,
	routeContext singtun.DirectRouteContext,
	timeout time.Duration,
) (singtun.DirectRouteDestination, error) {
	return nil, singtun.ErrNoRoute
}

// NewConnectionEx is invoked once per accepted TCP flow on the TUN.
// We reuse the existing Handler.HandleTCP code path which expects a
// net.Conn whose Local/Remote addrs are AddrPort-style strings —
// sing's net.Conn already satisfies this.
func (s *singHandler) NewConnectionEx(
	ctx context.Context,
	conn net.Conn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	defer func() {
		if onClose != nil {
			onClose(nil)
		}
	}()
	s.h.handleTCPFromSing(conn, sockAddrAdapter{source}, sockAddrAdapter{destination})
}

// NewPacketConnectionEx is invoked once per UDP "flow"; sing-tun
// demuxes by source port internally and gives us a single PacketConn
// per (src,dst) tuple. We pump packets in a loop so the rest of v2
// (which is packet-oriented) sees the same shape it always has.
func (s *singHandler) NewPacketConnectionEx(
	ctx context.Context,
	conn N.PacketConn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	defer func() {
		if onClose != nil {
			onClose(nil)
		}
	}()
	s.h.handleUDPFromSing(ctx, packetConnAdapter{conn}, sockAddrAdapter{source}, sockAddrAdapter{destination})
}

// sockAddrAdapter satisfies the sockaddrLike interface used by Handler
// without leaking sing's M package outside this file.
type sockAddrAdapter struct{ s M.Socksaddr }

func (a sockAddrAdapter) AddrPort() netip.AddrPort { return netip.AddrPortFrom(a.s.Addr, a.s.Port) }
func (a sockAddrAdapter) Port() uint16             { return a.s.Port }

// packetConnAdapter satisfies the packetConnLike interface used by Handler.
type packetConnAdapter struct{ N.PacketConn }

func (p packetConnAdapter) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := buf.With(b)
	dest, err := p.PacketConn.ReadPacket(buf)
	if err != nil {
		return 0, nil, err
	}
	return buf.Len(), &net.UDPAddr{IP: dest.Addr.AsSlice(), Port: int(dest.Port)}, nil
}

func (p packetConnAdapter) WriteTo(b []byte, addr net.Addr) (int, error) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		udp = net.UDPAddrFromAddrPort(M.SocksaddrFromNet(addr).AddrPort())
	}
	dst := M.SocksaddrFromNetIP(udp.AddrPort())
	bb := buf.With(b)
	if err := p.PacketConn.WritePacket(bb, dst); err != nil {
		return 0, err
	}
	return len(b), nil
}

