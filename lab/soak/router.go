package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// Lab addresses. Router k listens on routerAddrs[k] and plays one edge
// router (AS 64512, iBGP); Packeteer connects to each from peerAddr.
// GoBGP keys a neighbor by its address, so every session needs its own.
const (
	labASN   = 64512
	peerAddr = "127.0.0.2"
	holdTime = 9
)

var (
	routerAddrs = [...]string{"127.0.0.1", "127.0.0.3", "127.0.0.4", "127.0.0.5"}
	routerIDs   = [...]string{"192.0.2.254", "192.0.2.253", "192.0.2.252", "192.0.2.251"}
)

// maxSessions is how many routers the harness can play.
const maxSessions = len(routerAddrs)

// packeteerComm is packeteer_community in the generated config (64512:666).
const packeteerComm = labASN<<16 | 666

// Provider next hops, one per family, by table.provider index.
var (
	nextHopsV4 = [2]string{"192.0.2.1", "192.0.2.2"}
	nextHopsV6 = [2]string{"2001:db8:ffff::1", "2001:db8:ffff::2"}
)

var errNoSession = errors.New("router: no session")

// router is a minimal BGP speaker playing one edge router. It keeps no
// table: it encodes UPDATEs straight from the generated one, so the harness
// stays small next to Packeteer and the measurement is Packeteer's. A real
// speaker (GoBGP) would hold its own copy of the full table.
type router struct {
	id   int
	tbl  table
	adv  *advertised
	ln   net.Listener
	slow int // bytes a second Packeteer's messages are read at; 0 reads at once
	cap  int // routes Packeteer may hold on this session (max_improvements)

	mu    sync.Mutex // serializes writes on c and guards c and ended
	c     net.Conn   // nil between sessions
	ended chan struct{}

	up       atomic.Bool
	flapping atomic.Bool  // the harness is closing the session on purpose
	recvd    atomic.Int64 // NLRI Packeteer announced; observe must send none
	drops    atomic.Int64 // sessions that ended without a flap
	silence  atomic.Int64 // longest gap between Packeteer's messages, ns

	out adjOut
}

func startRouter(ctx context.Context, id, port int, tbl table, adv *advertised) (*router, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(routerAddrs[id], strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("router %d: %w", id, err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	return &router{id: id, tbl: tbl, adv: adv, ln: ln, out: newAdjOut()}, nil
}

// accept waits for Packeteer and opens a session. Connections from any
// other address are refused.
func (r *router) accept() error {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return fmt.Errorf("router %d: accept: %w", r.id, err)
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		if host != peerAddr {
			_ = c.Close()
			continue
		}
		if tc, ok := c.(*net.TCPConn); ok && r.slow > 0 {
			// A small window, so Packeteer's sends back up behind the
			// slow reads instead of waiting in the kernel.
			_ = tc.SetReadBuffer(4096)
		}
		if err := r.open(c); err != nil {
			_ = c.Close()
			log.Printf("router %d: open: %v", r.id, err)
			continue
		}
		return nil
	}
}

func (r *router) open(c net.Conn) error {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	m, err := readMsg(c)
	if err != nil {
		return err
	}
	if m.Header.Type != bgp.BGP_MSG_OPEN {
		return fmt.Errorf("want OPEN, got type %d", m.Header.Type)
	}
	if got := m.Body.(*bgp.BGPOpen).MyAS; got != labASN && got != bgp.AS_TRANS {
		return fmt.Errorf("peer AS %d, want %d", got, labASN)
	}
	caps := []bgp.ParameterCapabilityInterface{
		bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC),
		bgp.NewCapMultiProtocol(bgp.RF_IPv6_UC),
		bgp.NewCapFourOctetASNumber(labASN),
		bgp.NewCapRouteRefresh(),
	}
	open := bgp.NewBGPOpenMessage(labASN, holdTime, routerIDs[r.id], []bgp.OptionParameterInterface{bgp.NewOptionParameterCapability(caps)})
	if err := writeMsg(c, open); err != nil {
		return err
	}
	if err := writeMsg(c, bgp.NewBGPKeepAliveMessage()); err != nil {
		return err
	}
	for {
		m, err := readMsg(c)
		if err != nil {
			return err
		}
		if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
			break
		}
		if m.Header.Type == bgp.BGP_MSG_NOTIFICATION {
			return errors.New("peer sent NOTIFICATION during OPEN")
		}
	}
	_ = c.SetDeadline(time.Time{})
	ended := make(chan struct{})
	r.mu.Lock()
	r.c, r.ended = c, ended
	r.mu.Unlock()
	r.up.Store(true)
	go r.readLoop(c, ended)
	go r.keepalives(c, ended)
	return nil
}

// serve sends the table and End-of-RIB on the session accept opened, and
// again each time Packeteer comes back after the session ends (a flap),
// until ctx ends. first is closed once the first table is written.
func (r *router) serve(ctx context.Context, first chan<- struct{}) {
	for {
		err := r.update(0, r.tbl.n, false)
		if err == nil {
			err = r.endOfRIB()
		}
		if first != nil {
			close(first)
			first = nil
		}
		if err != nil {
			log.Printf("router %d: table: %v", r.id, err)
		}
		r.mu.Lock()
		ended := r.ended
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ended:
		}
		if err := r.accept(); err != nil {
			return
		}
	}
}

func readMsg(c io.Reader) (*bgp.BGPMessage, error) {
	hdr := make([]byte, bgp.BGP_HEADER_LENGTH)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[16:18]))
	if n < bgp.BGP_HEADER_LENGTH || n > bgp.BGP_MAX_MESSAGE_LENGTH {
		return nil, fmt.Errorf("bad message length %d", n)
	}
	buf := make([]byte, n)
	copy(buf, hdr)
	if _, err := io.ReadFull(c, buf[bgp.BGP_HEADER_LENGTH:]); err != nil {
		return nil, err
	}
	return bgp.ParseBGPMessage(buf)
}

func writeMsg(c io.Writer, m *bgp.BGPMessage) error {
	b, err := m.Serialize()
	if err != nil {
		return err
	}
	_, err = c.Write(b)
	return err
}

// throttle reads at most bps bytes a second, so Packeteer's messages to
// this session wait on a slow reader.
type throttle struct {
	r    io.Reader
	bps  int
	next time.Time // when the next read may start
}

func (t *throttle) Read(p []byte) (int, error) {
	if d := time.Until(t.next); d > 0 {
		time.Sleep(d)
	}
	if chunk := max(1, t.bps/4); len(p) > chunk {
		p = p[:chunk]
	}
	n, err := t.r.Read(p)
	t.next = time.Now().Add(time.Duration(n) * time.Second / time.Duration(t.bps))
	return n, err
}

// readLoop checks and records what Packeteer announces and notices the
// session ending. The routes Packeteer held on the session leave with it.
func (r *router) readLoop(c net.Conn, ended chan struct{}) {
	defer func() {
		r.mu.Lock()
		if r.c == c {
			r.c = nil
		}
		r.mu.Unlock()
		r.up.Store(false)
		r.out.end()
		if !r.flapping.Load() {
			r.drops.Add(1)
		}
		close(ended)
	}()
	var src io.Reader = c
	if r.slow > 0 {
		src = &throttle{r: c, bps: r.slow}
	}
	last := time.Now()
	for {
		_ = c.SetReadDeadline(time.Now().Add(holdTime * time.Second))
		m, err := readMsg(src)
		if err != nil {
			return
		}
		now := time.Now()
		if gap := int64(now.Sub(last)); gap > r.silence.Load() {
			r.silence.Store(gap)
		}
		last = now
		switch m.Header.Type {
		case bgp.BGP_MSG_NOTIFICATION:
			return
		case bgp.BGP_MSG_UPDATE:
			u := m.Body.(*bgp.BGPUpdate)
			r.recvd.Add(int64(r.out.apply(u, now, r.tbl, r.cap)))
		}
	}
}

func (r *router) keepalives(c net.Conn, ended chan struct{}) {
	t := time.NewTicker(holdTime * time.Second / 3)
	defer t.Stop()
	for {
		select {
		case <-ended:
			return
		case <-t.C:
			r.mu.Lock()
			err := writeMsg(c, bgp.NewBGPKeepAliveMessage())
			r.mu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

// flap closes the session with a Cease, as an operator's clear would, and
// waits for it to end. serve then takes Packeteer's reconnect and sends
// the table again. It reports false when there was no session.
func (r *router) flap() bool {
	r.mu.Lock()
	c, ended := r.c, r.ended
	if c == nil {
		r.mu.Unlock()
		return false
	}
	r.flapping.Store(true)
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = writeMsg(c, bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, nil))
	_ = c.Close()
	r.mu.Unlock()
	<-ended
	r.flapping.Store(false)
	return true
}

// established reports whether Packeteer's session is up.
func (r *router) established() bool { return r.up.Load() }

func (r *router) stop() {
	_ = r.ln.Close()
	r.mu.Lock()
	if r.c != nil {
		_ = r.c.Close()
	}
	r.mu.Unlock()
}

// endOfRIB marks the table complete for both families.
func (r *router) endOfRIB() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.c == nil {
		return errNoSession
	}
	for _, m := range []*bgp.BGPMessage{bgp.NewEndOfRib(bgp.RF_IPv4_UC), bgp.NewEndOfRib(bgp.RF_IPv6_UC)} {
		if err := writeMsg(r.c, m); err != nil {
			return err
		}
	}
	return nil
}

// maxNLRI keeps an UPDATE well under 4096 bytes (a /32 IPv4 or a /64
// IPv6 NLRI is at most 9 bytes).
const maxNLRI = 256

// update announces or withdraws entries [from, to): one UPDATE per run of
// entries that share attributes (one family, one group). An announce
// leaves out the entries withdrawn on every session. Each batch is built
// and written under mu, so a withdraw the fleet sends after marking an
// entry can never be overtaken by an announce of it.
func (r *router) update(from, to int, withdraw bool) error {
	skip := func(i int) bool { return !withdraw && r.adv.withdrawn(i) }
	batch := make([]*bgp.BGPMessage, 0, 64)
	for i := from; i < to; {
		r.mu.Lock()
		if r.c == nil {
			r.mu.Unlock()
			return errNoSession
		}
		batch = batch[:0]
		for len(batch) < cap(batch) && i < to {
			if skip(i) {
				i++
				continue
			}
			j := i + 1
			for j < to && j-i < maxNLRI && r.tbl.group(j) == r.tbl.group(i) && (j < r.tbl.v4n()) == (i < r.tbl.v4n()) && !skip(j) {
				j++
			}
			batch = append(batch, r.message(i, j, withdraw))
			i = j
		}
		var err error
		for _, m := range batch {
			if err = writeMsg(r.c, m); err != nil {
				break
			}
		}
		r.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

// message is one UPDATE for entries [i, j), which share family and group.
func (r *router) message(i, j int, withdraw bool) *bgp.BGPMessage {
	if i < r.tbl.v4n() {
		nlri := make([]*bgp.IPAddrPrefix, 0, j-i)
		for k := i; k < j; k++ {
			p := r.tbl.prefix(k)
			nlri = append(nlri, bgp.NewIPAddrPrefix(uint8(p.Bits()), p.Addr().String()))
		}
		if withdraw {
			return bgp.NewBGPUpdateMessage(nlri, nil, nil)
		}
		return bgp.NewBGPUpdateMessage(nil, append(r.attrs(i), bgp.NewPathAttributeNextHop(nextHopsV4[r.tbl.provider(i)])), nlri)
	}
	nlri := make([]bgp.AddrPrefixInterface, 0, j-i)
	for k := i; k < j; k++ {
		p := r.tbl.prefix(k)
		nlri = append(nlri, bgp.NewIPv6AddrPrefix(uint8(p.Bits()), p.Addr().String()))
	}
	if withdraw {
		return bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{bgp.NewPathAttributeMpUnreachNLRI(nlri)}, nil)
	}
	return bgp.NewBGPUpdateMessage(nil, append(r.attrs(i), bgp.NewPathAttributeMpReachNLRI(nextHopsV6[r.tbl.provider(i)], nlri)), nil)
}

func (r *router) attrs(i int) []bgp.PathAttributeInterface {
	if r.tbl.real != nil {
		return r.tbl.real.attrs(i)
	}
	a := r.tbl.attrs(i)
	var path []bgp.AsPathParamInterface
	if len(a.path) > 0 {
		path = []bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, a.path)}
	}
	out := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(a.origin),
		bgp.NewPathAttributeAsPath(path),
		bgp.NewPathAttributeLocalPref(100),
	}
	if a.hasMED {
		out = append(out, bgp.NewPathAttributeMultiExitDisc(a.med))
	}
	if len(a.comms) > 0 {
		out = append(out, bgp.NewPathAttributeCommunities(a.comms))
	}
	if len(a.large) > 0 {
		lc := make([]*bgp.LargeCommunity, len(a.large))
		for k, v := range a.large {
			lc[k] = bgp.NewLargeCommunity(v[0], v[1], v[2])
		}
		out = append(out, bgp.NewPathAttributeLargeCommunities(lc))
	}
	return out
}

// advertised is the entries the harness has withdrawn on every session:
// the churn batch that is out and the prefix the withdraw-latency check
// holds out. A router that opens again leaves them out of its table, so
// every session carries the same routes.
type advertised struct {
	mu  sync.Mutex
	out map[int]bool
}

func newAdvertised() *advertised { return &advertised{out: map[int]bool{}} }

func (a *advertised) withdrawn(i int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.out[i]
}

func (a *advertised) mark(from, to int, out bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := from; i < to; i++ {
		if out {
			a.out[i] = true
		} else {
			delete(a.out, i)
		}
	}
}

// fleet is the routers Packeteer peers with. Every one carries the same
// table.
type fleet struct {
	routers []*router
	adv     *advertised
}

// withdraw takes entries [from, to) off every session. A router without a
// session gets the change with its next table. A failed write is not
// handled here: the session is counted as a drop once its read fails.
func (f *fleet) withdraw(from, to int) {
	f.adv.mark(from, to, true)
	for _, r := range f.routers {
		_ = r.update(from, to, true)
	}
}

// announce puts entries [from, to) back on every session.
func (f *fleet) announce(from, to int) {
	f.adv.mark(from, to, false)
	for _, r := range f.routers {
		_ = r.update(from, to, false)
	}
}

// anyUp reports whether some session is established.
func (f *fleet) anyUp() bool {
	for _, r := range f.routers {
		if r.established() {
			return true
		}
	}
	return false
}

// adjOut is the routes Packeteer has on one session, checked as they
// arrive: each must be a table prefix and carry packeteer_community and
// NO_EXPORT, and the session may hold no more than max_improvements of
// them. A table prefix the harness has withdrawn is not rejected here; the
// withdraw check's one-minute stale test covers the prefix it holds out.
type adjOut struct {
	mu      sync.Mutex
	held    map[netip.Prefix]time.Time // announced, by first announce
	gone    map[netip.Prefix]time.Time // last withdraw of each prefix
	peak    int
	atClose int // routes held when the last session ended
	bad     []string
	nbad    int
}

func newAdjOut() adjOut {
	return adjOut{held: map[netip.Prefix]time.Time{}, gone: map[netip.Prefix]time.Time{}}
}

// maxBad is how many broken-rule messages a session keeps; the rest are
// counted.
const maxBad = 5

// apply records one UPDATE and returns how many prefixes it announced.
func (a *adjOut) apply(u *bgp.BGPUpdate, now time.Time, tbl table, limit int) int {
	var adds, dels []netip.Prefix
	for _, n := range u.WithdrawnRoutes {
		dels = append(dels, nlriPrefix(n))
	}
	for _, n := range u.NLRI {
		adds = append(adds, nlriPrefix(n))
	}
	var comms []uint32
	for _, pa := range u.PathAttributes {
		switch v := pa.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			for _, n := range v.Value {
				adds = append(adds, nlriPrefix(n))
			}
		case *bgp.PathAttributeMpUnreachNLRI:
			for _, n := range v.Value {
				dels = append(dels, nlriPrefix(n))
			}
		case *bgp.PathAttributeCommunities:
			comms = v.Value
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range dels {
		delete(a.held, p)
		a.gone[p] = now
	}
	for _, p := range adds {
		if why := routeFault(p, comms, tbl); why != "" {
			a.fault(why)
		}
		if _, ok := a.held[p]; !ok {
			a.held[p] = now
		}
	}
	a.peak = max(a.peak, len(a.held))
	if limit > 0 && len(a.held) > limit {
		a.fault(fmt.Sprintf("%d routes held, more than max_improvements %d", len(a.held), limit))
	}
	return len(adds)
}

// routeFault says what is wrong with a route Packeteer announced, or "".
func routeFault(p netip.Prefix, comms []uint32, tbl table) string {
	if !p.IsValid() {
		return "unparsable prefix"
	}
	if tbl.real != nil {
		// A real-table run is observe-only, so any route is a fault. The
		// message names no prefix: logs and artifacts carry counts only.
		return "Packeteer announced a route during a real-table run"
	}
	if _, ok := tbl.index(p); !ok {
		return fmt.Sprintf("%s is not a prefix the routers advertised", p)
	}
	var own, noExport bool
	for _, c := range comms {
		own = own || c == packeteerComm
		noExport = noExport || c == uint32(bgp.COMMUNITY_NO_EXPORT)
	}
	if !own || !noExport {
		return fmt.Sprintf("%s without packeteer_community and NO_EXPORT (communities %v)", p, comms)
	}
	return ""
}

func (a *adjOut) fault(why string) {
	a.nbad++
	if len(a.bad) < maxBad {
		a.bad = append(a.bad, why)
	}
}

func nlriPrefix(n bgp.AddrPrefixInterface) netip.Prefix {
	p, err := netip.ParsePrefix(n.String())
	if err != nil {
		return netip.Prefix{}
	}
	return p
}

// end drops the routes with the session, as a router does without
// graceful restart.
func (a *adjOut) end() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.atClose = len(a.held)
	clear(a.held)
}

// since is when p was first announced on the current session.
func (a *adjOut) since(p netip.Prefix) (time.Time, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.held[p]
	return t, ok
}

// withdrawnAt is the last time Packeteer withdrew p on this session.
func (a *adjOut) withdrawnAt(p netip.Prefix) time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gone[p]
}

// snapshot is a copy of the routes held now, by first announce.
func (a *adjOut) snapshot() map[netip.Prefix]time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return maps.Clone(a.held)
}

// up is how many sessions are established.
func (f *fleet) up() int {
	n := 0
	for _, r := range f.routers {
		if r.established() {
			n++
		}
	}
	return n
}

// allUp reports whether every session is established.
func (f *fleet) allUp() bool { return f.up() == len(f.routers) }

// drops is sessions that ended without a flap, over every router.
func (f *fleet) drops() int64 {
	var n int64
	for _, r := range f.routers {
		n += r.drops.Load()
	}
	return n
}
