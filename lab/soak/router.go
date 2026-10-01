package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// Lab addresses. The router plays the edge (AS 64512, iBGP) and Packeteer
// connects to it from peerAddr.
const (
	labASN     = 64512
	routerID   = "192.0.2.254"
	routerAddr = "127.0.0.1"
	peerAddr   = "127.0.0.2"
	holdTime   = 9
)

// Provider next hops, one per family, by table.provider index.
var (
	nextHopsV4 = [2]string{"192.0.2.1", "192.0.2.2"}
	nextHopsV6 = [2]string{"2001:db8:ffff::1", "2001:db8:ffff::2"}
)

// router is a minimal BGP speaker playing the edge. It keeps no table: it
// encodes UPDATEs straight from the generated one, so the harness stays
// small next to Packeteer and the measurement is Packeteer's. A real
// speaker (GoBGP) would hold its own copy of the full table.
type router struct {
	tbl  table
	ln   net.Listener
	conn chan net.Conn // the established session, handed over once

	mu    sync.Mutex // serializes writes on c
	c     net.Conn
	up    atomic.Bool
	recvd atomic.Int64 // NLRI Packeteer sent us
	done  chan struct{}
}

func startRouter(_ context.Context, port int, tbl table) (*router, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(routerAddr, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("router: %w", err)
	}
	return &router{tbl: tbl, ln: ln, conn: make(chan net.Conn, 1), done: make(chan struct{})}, nil
}

// accept waits for Packeteer and opens the session. Connections from any
// other address are refused.
func (r *router) accept(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = r.ln.Close()
	}()
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return fmt.Errorf("router: accept: %w", err)
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		if host != peerAddr {
			_ = c.Close()
			continue
		}
		if err := r.open(c); err != nil {
			_ = c.Close()
			log.Printf("router: open: %v", err)
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
	open := bgp.NewBGPOpenMessage(labASN, holdTime, routerID, []bgp.OptionParameterInterface{bgp.NewOptionParameterCapability(caps)})
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
	r.c = c
	r.up.Store(true)
	go r.readLoop()
	go r.keepalives()
	return nil
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

// readLoop counts what Packeteer announces (observe must announce nothing)
// and notices the session ending.
func (r *router) readLoop() {
	defer close(r.done)
	defer r.up.Store(false)
	for {
		_ = r.c.SetReadDeadline(time.Now().Add(holdTime * time.Second))
		m, err := readMsg(r.c)
		if err != nil {
			return
		}
		switch m.Header.Type {
		case bgp.BGP_MSG_NOTIFICATION:
			return
		case bgp.BGP_MSG_UPDATE:
			u := m.Body.(*bgp.BGPUpdate)
			n := len(u.NLRI)
			for _, a := range u.PathAttributes {
				if mp, ok := a.(*bgp.PathAttributeMpReachNLRI); ok {
					n += len(mp.Value)
				}
			}
			r.recvd.Add(int64(n))
		}
	}
}

func (r *router) keepalives() {
	t := time.NewTicker(holdTime * time.Second / 3)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			if err := r.send(bgp.NewBGPKeepAliveMessage()); err != nil {
				return
			}
		}
	}
}

func (r *router) send(ms ...*bgp.BGPMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range ms {
		if err := writeMsg(r.c, m); err != nil {
			return err
		}
	}
	return nil
}

// established reports whether Packeteer's session is up.
func (r *router) established(context.Context) bool { return r.up.Load() }

// adjIn counts the prefixes Packeteer sent the router.
func (r *router) adjIn(context.Context) int { return int(r.recvd.Load()) }

func (r *router) stop() {
	_ = r.ln.Close()
	if r.c != nil {
		_ = r.c.Close()
	}
}

// load announces entries [from, to): one UPDATE per run of entries that
// share attributes (one family, one group).
func (r *router) load(_ context.Context, from, to int) error { return r.update(from, to, false) }

// withdraw removes entries [from, to).
func (r *router) withdraw(_ context.Context, from, to int) error { return r.update(from, to, true) }

// endOfRIB marks the initial dump complete for both families.
func (r *router) endOfRIB() error {
	return r.send(bgp.NewEndOfRib(bgp.RF_IPv4_UC), bgp.NewEndOfRib(bgp.RF_IPv6_UC))
}

// maxNLRI keeps an UPDATE well under 4096 bytes (a /32 IPv4 or a /64
// IPv6 NLRI is at most 9 bytes).
const maxNLRI = 256

func (r *router) update(from, to int, withdraw bool) error {
	if r.c == nil {
		return errors.New("router: no session")
	}
	var batch []*bgp.BGPMessage
	for i := from; i < to; {
		j := i + 1
		for j < to && j-i < maxNLRI && r.tbl.group(j) == r.tbl.group(i) && (j < v4Count) == (i < v4Count) {
			j++
		}
		batch = append(batch, r.message(i, j, withdraw))
		if len(batch) == 64 {
			if err := r.send(batch...); err != nil {
				return err
			}
			batch = batch[:0]
		}
		i = j
	}
	return r.send(batch...)
}

// message is one UPDATE for entries [i, j), which share family and group.
func (r *router) message(i, j int, withdraw bool) *bgp.BGPMessage {
	if i < v4Count {
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
	return []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, r.tbl.asPath(i))}),
		bgp.NewPathAttributeLocalPref(100),
	}
}
