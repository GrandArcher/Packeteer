// Package bmp is a BMP monitoring station (RFC 7854, Loc-RIB per RFC 9069).
// Edge routers connect to it and stream their Adj-RIB-In, so Packeteer sees
// every provider's paths, including ones the router did not select, without
// a full iBGP feed. It is learn-only: it never sends BGP, never announces,
// and only feeds the RIB view through the plugin.RIBSource sink.
//
// Only configured router addresses may connect. When a router's session
// ends (TCP close, termination, a read error, or Stop) every path from that
// router is dropped. A peer whose messages cannot be decoded, or that
// negotiated add-path (#26 follow-up), is treated as down and its paths are
// dropped until the router sends a new peer up.
package bmp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

// Defaults and bounds.
const (
	// DefaultPort is the IANA BMP port.
	DefaultPort = gobmp.BMP_DEFAULT_PORT
	// maxMessage bounds one BMP message: a 42-byte peer header plus a BGP
	// extended message (RFC 8654) with room for peer up's two OPENs.
	maxMessage = 1 << 18
	// keepAlive probes a silent router so a dead one is noticed.
	keepAlive = 30 * time.Second
)

// Config is the plugin config.
type Config struct {
	// Listen is host:port for the station (default ":11019").
	Listen string `yaml:"listen"`
	// Routers lists the router addresses allowed to connect. Required.
	Routers []string `yaml:"routers"`
	// Policy is which Adj-RIB-In to read: pre (default) or post.
	Policy string `yaml:"policy"`
	// LocRIB reads Loc-RIB (RFC 9069) messages as the router's selected
	// path (default true).
	LocRIB *bool `yaml:"loc_rib"`
}

// Station is the plugin.
type Station struct {
	listen  string
	routers map[netip.Addr]bool
	post    bool
	locRIB  bool
	log     *slog.Logger

	mu    sync.Mutex
	sink  func(plugin.RIBEvent)
	ln    net.Listener
	conns map[netip.Addr]*session
	wg    sync.WaitGroup
	done  bool
}

type session struct {
	conn net.Conn
	done chan struct{}
}

func init() {
	plugin.RIBSources.Register("bmp", New)
}

// New validates the config. It does not listen.
func New(c plugin.Config, env plugin.Env) (plugin.RIBSource, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	s := &Station{listen: cfg.Listen, routers: map[netip.Addr]bool{}, locRIB: true, log: env.Logger,
		conns: map[netip.Addr]*session{}}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.listen == "" {
		s.listen = ":" + strconv.Itoa(DefaultPort)
	}
	host, port, err := net.SplitHostPort(s.listen)
	if err != nil {
		return nil, fmt.Errorf("bmp: listen %q: %w", s.listen, err)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return nil, fmt.Errorf("bmp: listen %q: port must be 0-65535", s.listen)
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, fmt.Errorf("bmp: listen %q: host must be an IP address", s.listen)
		}
	}
	if len(cfg.Routers) == 0 {
		return nil, errors.New("bmp: routers is required (addresses allowed to connect)")
	}
	for i, r := range cfg.Routers {
		a, err := netip.ParseAddr(r)
		if err != nil {
			return nil, fmt.Errorf("bmp: routers[%d]: %q is not an IP address", i, r)
		}
		if s.routers[a.Unmap()] {
			return nil, fmt.Errorf("bmp: routers[%d]: duplicate %s", i, a)
		}
		s.routers[a.Unmap()] = true
	}
	switch cfg.Policy {
	case "", "pre":
	case "post":
		s.post = true
	default:
		return nil, fmt.Errorf("bmp: policy %q is invalid (want pre or post)", cfg.Policy)
	}
	if cfg.LocRIB != nil {
		s.locRIB = *cfg.LocRIB
	}
	return s, nil
}

// SetRIBSink implements plugin.RIBSource.
func (s *Station) SetRIBSink(fn func(plugin.RIBEvent)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sink = fn
}

// Addr is the bound listener address, once started.
func (s *Station) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Start listens and accepts router sessions in the background.
func (s *Station) Start(context.Context) error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("bmp: listen: %w", err)
	}
	s.mu.Lock()
	s.ln = ln
	s.done = false
	s.mu.Unlock()
	s.log.Info("bmp station listening", "addr", ln.Addr().String())
	s.wg.Add(1)
	go s.accept(ln)
	return nil
}

// Stop closes the listener and every session. Each session's paths are
// dropped (RIBRouterDown) before Stop returns.
func (s *Station) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.done = true
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for _, c := range s.conns {
		_ = c.conn.Close()
	}
	s.mu.Unlock()
	ch := make(chan struct{})
	go func() { s.wg.Wait(); close(ch) }()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Station) accept(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.log.Warn("bmp accept", "err", err)
			}
			return
		}
		ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
		router := ap.Addr().Unmap()
		if err != nil || !s.routers[router] {
			s.log.Warn("bmp: refusing session from an unlisted address", "remote", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(keepAlive)
		}
		s.mu.Lock()
		if s.done {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		old := s.conns[router]
		sess := &session{conn: conn, done: make(chan struct{})}
		s.conns[router] = sess
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			if old != nil {
				// A router reconnecting replaces its old session. The old
				// one drops its paths before the new one reports any.
				_ = old.conn.Close()
				<-old.done
			}
			s.serve(router, sess)
		}()
	}
}

func (s *Station) emit(ev plugin.RIBEvent) {
	s.mu.Lock()
	fn := s.sink
	s.mu.Unlock()
	if fn != nil {
		fn(ev)
	}
}

func (s *Station) serve(router netip.Addr, sess *session) {
	defer close(sess.done)
	defer func() {
		s.mu.Lock()
		if s.conns[router] == sess {
			delete(s.conns, router)
		}
		s.mu.Unlock()
	}()
	defer s.emit(plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: router})
	defer sess.conn.Close()
	s.log.Info("bmp session up", "router", router)
	d := newDecoder(router, s.post, s.locRIB, s.log)
	err := readMessages(sess.conn, func(msg []byte) error {
		evs, stop := d.message(msg)
		for _, ev := range evs {
			s.emit(ev)
		}
		if stop {
			return io.EOF
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		s.log.Warn("bmp session ended", "router", router, "err", err)
		return
	}
	s.log.Info("bmp session down", "router", router)
}

// readMessages reads whole BMP messages from r and hands each to fn. A bad
// version or length ends the stream: framing cannot be recovered.
func readMessages(r io.Reader, fn func([]byte) error) error {
	hdr := make([]byte, gobmp.BMP_HEADER_SIZE)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("bmp: truncated header: %w", err)
			}
			return err
		}
		if hdr[0] != gobmp.BMP_VERSION {
			return fmt.Errorf("bmp: unsupported version %d", hdr[0])
		}
		n := binary.BigEndian.Uint32(hdr[1:5])
		if n < gobmp.BMP_HEADER_SIZE || n > maxMessage {
			return fmt.Errorf("bmp: bad message length %d", n)
		}
		msg := make([]byte, n)
		copy(msg, hdr)
		if _, err := io.ReadFull(r, msg[gobmp.BMP_HEADER_SIZE:]); err != nil {
			return fmt.Errorf("bmp: truncated message: %w", err)
		}
		if err := fn(msg); err != nil {
			return err
		}
	}
}

// decoder turns one router's BMP messages into RIB events.
type decoder struct {
	router netip.Addr
	post   bool
	locRIB bool
	log    *slog.Logger
	// skip holds peers whose routes are ignored until the next peer up.
	skip map[plugin.RIBPeer]string
}

func newDecoder(router netip.Addr, post, locRIB bool, log *slog.Logger) *decoder {
	return &decoder{router: router, post: post, locRIB: locRIB, log: log, skip: map[plugin.RIBPeer]string{}}
}

// message decodes one BMP message. stop is true on a termination message.
func (d *decoder) message(raw []byte) (evs []plugin.RIBEvent, stop bool) {
	msg, err := gobmp.ParseBMPMessage(raw)
	if msg == nil {
		return d.undecodable(raw, err), false
	}
	switch msg.Header.Type {
	case gobmp.BMP_MSG_INITIATION:
		return nil, false
	case gobmp.BMP_MSG_TERMINATION:
		return nil, true
	case gobmp.BMP_MSG_STATISTICS_REPORT, gobmp.BMP_MSG_ROUTE_MIRRORING:
		return nil, false
	}
	peer, ok := d.peer(msg.PeerHeader)
	if !ok {
		return nil, false
	}
	ev := plugin.RIBEvent{Router: d.router, Peer: peer}
	switch body := msg.Body.(type) {
	case *gobmp.BMPPeerUpNotification:
		if why := addPath(body); why != "" {
			d.skip[peer] = why
			d.log.Warn("bmp: ignoring peer (add-path is not decoded yet)", "router", d.router, "peer", peer.Address, "detail", why)
			ev.Kind = plugin.RIBPeerDown
			return []plugin.RIBEvent{ev}, false
		}
		delete(d.skip, peer)
		ev.Kind = plugin.RIBPeerUp
		return []plugin.RIBEvent{ev}, false
	case *gobmp.BMPPeerDownNotification:
		delete(d.skip, peer)
		ev.Kind = plugin.RIBPeerDown
		return []plugin.RIBEvent{ev}, false
	case *gobmp.BMPRouteMonitoring:
		if _, skipped := d.skip[peer]; skipped {
			return nil, false
		}
		if err != nil || body.BGPUpdate == nil {
			// A path we cannot read could be a withdraw we would miss, so
			// the whole peer is dropped until it comes up again.
			d.skip[peer] = "decode error"
			d.log.Warn("bmp: undecodable route monitoring; dropping peer", "router", d.router, "peer", peer.Address, "err", err)
			ev.Kind = plugin.RIBPeerDown
			return []plugin.RIBEvent{ev}, false
		}
		upd, ok := body.BGPUpdate.Body.(*bgp.BGPUpdate)
		if !ok {
			return nil, false
		}
		ev.Kind = plugin.RIBPaths
		ev.Paths = paths(upd)
		if len(ev.Paths) == 0 {
			return nil, false
		}
		return []plugin.RIBEvent{ev}, false
	}
	return nil, false
}

// undecodable handles a message the parser rejected. A per-peer message
// that could be a peer down or carry a withdraw drops that peer until its
// next peer up. Other types (statistics variants, future messages) are
// skipped; the framing is already known to be intact.
func (d *decoder) undecodable(raw []byte, err error) []plugin.RIBEvent {
	switch raw[5] {
	case gobmp.BMP_MSG_ROUTE_MONITORING, gobmp.BMP_MSG_PEER_UP_NOTIFICATION, gobmp.BMP_MSG_PEER_DOWN_NOTIFICATION:
	default:
		d.log.Debug("bmp: skipping message", "router", d.router, "type", raw[5], "err", err)
		return nil
	}
	if len(raw) < gobmp.BMP_HEADER_SIZE+gobmp.BMP_PEER_HEADER_SIZE {
		d.log.Warn("bmp: short per-peer message", "router", d.router, "type", raw[5])
		return nil
	}
	var h gobmp.BMPPeerHeader
	if h.DecodeFromBytes(raw[gobmp.BMP_HEADER_SIZE:]) != nil {
		return nil
	}
	peer, ok := d.peer(h)
	if !ok {
		return nil
	}
	d.skip[peer] = "decode error"
	d.log.Warn("bmp: undecodable message; dropping peer", "router", d.router, "peer", peer.Address, "type", raw[5], "err", err)
	return []plugin.RIBEvent{{Kind: plugin.RIBPeerDown, Router: d.router, Peer: peer}}
}

// peer maps a per-peer header to a RIBPeer, or false when this station
// does not read that table (Adj-RIB-Out, the other policy side, L3VPN).
func (d *decoder) peer(h gobmp.BMPPeerHeader) (plugin.RIBPeer, bool) {
	switch h.PeerType {
	case gobmp.BMP_PEER_TYPE_GLOBAL:
		if h.IsAdjRIBOut() || h.IsPostPolicy() != d.post {
			return plugin.RIBPeer{}, false
		}
		a, ok := netip.AddrFromSlice(h.PeerAddress)
		if !ok {
			return plugin.RIBPeer{}, false
		}
		id, _ := netip.AddrFromSlice(h.PeerBGPID.To4())
		return plugin.RIBPeer{Address: a.Unmap(), ASN: h.PeerAS, BGPID: id}, true
	case gobmp.BMP_PEER_TYPE_LOCAL_RIB:
		if !d.locRIB {
			return plugin.RIBPeer{}, false
		}
		return plugin.RIBPeer{LocRIB: true}, true
	}
	return plugin.RIBPeer{}, false
}

// addPath reports an add-path capability in either OPEN of a peer up.
// Without it the NLRI would be misread.
func addPath(b *gobmp.BMPPeerUpNotification) string {
	for _, m := range []*bgp.BGPMessage{b.SentOpenMsg, b.ReceivedOpenMsg} {
		if m == nil {
			continue
		}
		open, ok := m.Body.(*bgp.BGPOpen)
		if !ok {
			continue
		}
		for _, p := range open.OptParams {
			cp, ok := p.(*bgp.OptionParameterCapability)
			if !ok {
				continue
			}
			for _, c := range cp.Capability {
				if c.Code() == bgp.BGP_CAP_ADD_PATH {
					return "add-path capability in OPEN"
				}
			}
		}
	}
	return ""
}

// paths flattens an UPDATE into announcements and withdrawals for IPv4 and
// IPv6 unicast. Other families are ignored.
func paths(u *bgp.BGPUpdate) []plugin.RIBPath {
	var out []plugin.RIBPath
	for _, w := range u.WithdrawnRoutes {
		if p, ok := prefixOf(w); ok {
			out = append(out, plugin.RIBPath{Prefix: p, Withdraw: true})
		}
	}
	var nh netip.Addr
	var asPath, comms []uint32
	var mpNLRI []bgp.AddrPrefixInterface
	var mpNH netip.Addr
	for _, a := range u.PathAttributes {
		switch attr := a.(type) {
		case *bgp.PathAttributeNextHop:
			if x, ok := netip.AddrFromSlice(attr.Value); ok {
				nh = x.Unmap()
			}
		case *bgp.PathAttributeAsPath:
			for _, seg := range attr.Value {
				asPath = append(asPath, seg.GetAS()...)
			}
		case *bgp.PathAttributeCommunities:
			comms = append(comms, attr.Value...)
		case *bgp.PathAttributeMpReachNLRI:
			if !unicast(attr.AFI, attr.SAFI) {
				continue
			}
			if x, ok := netip.AddrFromSlice(attr.Nexthop); ok {
				mpNH = x.Unmap()
			}
			mpNLRI = append(mpNLRI, attr.Value...)
		case *bgp.PathAttributeMpUnreachNLRI:
			if !unicast(attr.AFI, attr.SAFI) {
				continue
			}
			for _, w := range attr.Value {
				if p, ok := prefixOf(w); ok {
					out = append(out, plugin.RIBPath{Prefix: p, Withdraw: true})
				}
			}
		}
	}
	for _, n := range u.NLRI {
		if p, ok := prefixOf(n); ok && nh.IsValid() {
			out = append(out, plugin.RIBPath{Prefix: p, NextHop: nh, ASPath: asPath, Communities: comms})
		}
	}
	for _, n := range mpNLRI {
		if p, ok := prefixOf(n); ok && mpNH.IsValid() {
			out = append(out, plugin.RIBPath{Prefix: p, NextHop: mpNH, ASPath: asPath, Communities: comms})
		}
	}
	return out
}

func unicast(afi uint16, safi uint8) bool {
	return (afi == bgp.AFI_IP || afi == bgp.AFI_IP6) && safi == bgp.SAFI_UNICAST
}

func prefixOf(a bgp.AddrPrefixInterface) (netip.Prefix, bool) {
	var ip net.IP
	var bits uint8
	switch n := a.(type) {
	case *bgp.IPAddrPrefix:
		ip, bits = n.Prefix, n.Length
	case *bgp.IPv6AddrPrefix:
		ip, bits = n.Prefix, n.Length
	default:
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	p, err := addr.Prefix(int(bits))
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}
