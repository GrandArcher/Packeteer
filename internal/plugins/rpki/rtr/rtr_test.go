package rtr

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	return netip.MustParsePrefix(s)
}

func ipv4PDU(t *testing.T, prefix string, maxLen uint8, asn uint32, announce bool) []byte {
	t.Helper()
	p := mustPrefix(t, prefix)
	b := make([]byte, 20)
	b[0], b[1] = protocolVersion, pduIPv4Prefix
	binary.BigEndian.PutUint32(b[4:8], 20)
	if announce {
		b[8] = 1
	}
	b[9], b[10] = uint8(p.Bits()), maxLen
	a := p.Addr().As4()
	copy(b[12:16], a[:])
	binary.BigEndian.PutUint32(b[16:20], asn)
	return b
}

func ipv6PDU(t *testing.T, prefix string, maxLen uint8, asn uint32, announce bool) []byte {
	t.Helper()
	p := mustPrefix(t, prefix)
	b := make([]byte, 32)
	b[0], b[1] = protocolVersion, pduIPv6Prefix
	binary.BigEndian.PutUint32(b[4:8], 32)
	if announce {
		b[8] = 1
	}
	b[9], b[10] = uint8(p.Bits()), maxLen
	a := p.Addr().As16()
	copy(b[12:28], a[:])
	binary.BigEndian.PutUint32(b[28:32], asn)
	return b
}

func cacheResponsePDU() []byte {
	b := make([]byte, 8)
	b[0], b[1] = protocolVersion, pduCacheResponse
	binary.BigEndian.PutUint16(b[2:4], 7)
	binary.BigEndian.PutUint32(b[4:8], 8)
	return b
}

func endOfDataPDU(serial uint32) []byte {
	b := make([]byte, 24)
	b[0], b[1] = protocolVersion, pduEndOfData
	binary.BigEndian.PutUint16(b[2:4], 7)
	binary.BigEndian.PutUint32(b[4:8], 24)
	binary.BigEndian.PutUint32(b[8:12], serial)
	binary.BigEndian.PutUint32(b[12:16], 300)
	binary.BigEndian.PutUint32(b[16:20], 600)
	binary.BigEndian.PutUint32(b[20:24], 3600)
	return b
}

func routerKeyPDU() []byte {
	b := make([]byte, 20)
	b[0], b[1] = protocolVersion, pduRouterKey
	b[2] = 1 // announce flag
	binary.BigEndian.PutUint32(b[4:8], 20)
	return b
}

// stubServer accepts one connection and answers a Reset Query with the
// given records, then holds the connection open.
func stubServer(t *testing.T, records ...[]byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		head := make([]byte, 8)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		if head[1] != pduResetQuery {
			return
		}
		_, _ = conn.Write(cacheResponsePDU())
		for _, pdu := range records {
			_, _ = conn.Write(pdu)
		}
		_, _ = conn.Write(endOfDataPDU(42))
		_, _ = io.Copy(io.Discard, conn)
	}()
	return ln.Addr().String()
}

func startClient(t *testing.T, addr string) *Client {
	t.Helper()
	cfg, err := plugin.ConfigFromYAML("address: " + addr + "\nrefresh: 10s\nstaleness: 1h\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "rpki-lab"})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Status().Up {
			return c
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("client never became up")
	return nil
}

// #158: the RTR client caches the server's payloads and answers RFC 6811
// origin validation for IPv4 and IPv6.
func TestClientValidates(t *testing.T) {
	addr := stubServer(t,
		ipv4PDU(t, "198.51.100.0/24", 24, 64500, true),
		ipv4PDU(t, "203.0.113.0/24", 26, 64501, true),
		ipv6PDU(t, "2001:db8::/32", 48, 64502, true),
	)
	c := startClient(t, addr)
	st := c.Status()
	if !st.Up || st.Stale || st.VRPs != 3 || st.Source != "rpki-lab" {
		t.Fatalf("status = %+v", st)
	}
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIValid {
		t.Fatalf("valid = %q", got)
	}
	if got := c.Validate(mustPrefix(t, "203.0.113.0/26"), 64599); got != plugin.RPKIInvalid {
		t.Fatalf("invalid = %q", got)
	}
	if got := c.Validate(mustPrefix(t, "192.0.2.0/24"), 64500); got != plugin.RPKINotFound {
		t.Fatalf("notfound = %q", got)
	}
	if got := c.Validate(mustPrefix(t, "2001:db8:1::/48"), 64502); got != plugin.RPKIValid {
		t.Fatalf("ipv6 valid = %q", got)
	}
}

// A Router Key PDU (RFC 8210 section 5.9) does not affect prefix origin
// validation and must not abort the load before End of Data.
func TestClientIgnoresRouterKey(t *testing.T) {
	addr := stubServer(t,
		routerKeyPDU(),
		ipv4PDU(t, "198.51.100.0/24", 24, 64500, true),
	)
	c := startClient(t, addr)
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIValid {
		t.Fatalf("validate after router key = %q, want valid", got)
	}
}

// silentResetServer answers a Reset Query with a partial table and never
// sends End of Data. It counts connections so a test can see the client
// redial.
func silentResetServer(t *testing.T, partial []byte) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepts atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer conn.Close()
				head := make([]byte, 8)
				if _, err := io.ReadFull(conn, head); err != nil {
					return
				}
				if head[1] != pduResetQuery {
					return
				}
				_, _ = conn.Write(cacheResponsePDU())
				_, _ = conn.Write(partial)
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String(), &accepts
}

// A reset that stalls before End of Data is dropped and redialed: the
// configured timeout, not refresh, bounds one read while a load is in
// flight.
func TestClientRedialsSilentReset(t *testing.T) {
	addr, accepts := silentResetServer(t, ipv4PDU(t, "198.51.100.0/24", 24, 64500, true))
	cfg, err := plugin.ConfigFromYAML("address: " + addr + "\ntimeout: 1s\nrefresh: 1s\nstaleness: 1h\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "silent"})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := contextWithTimeout(2 * time.Second)
	defer cancel()
	defer func() { _ = c.Stop(ctx) }()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && accepts.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := accepts.Load(); got < 2 {
		t.Fatalf("stalled reset not redialed (connections = %d)", got)
	}
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIUnknown {
		t.Fatalf("partial reset served as %q, want unknown", got)
	}
}

// A serial update re-sent after a lost End of Data must not store a
// second copy, so one withdrawal retires the payload.
func TestHandleReplayedAnnounce(t *testing.T) {
	c := &Client{cfg: Config{Staleness: time.Hour}, cache: rpki.NewVRPs()}
	c.setUp(1, 1)
	pdu := ipv4PDU(t, "198.51.100.0/24", 24, 64500, true)
	serial := func(pdus ...[]byte) {
		t.Helper()
		resp, _ := c.request()
		var err error
		for _, p := range append(pdus, endOfDataPDU(2)) {
			if resp, _, err = c.handle(p, resp); err != nil {
				t.Fatal(err)
			}
		}
		if resp != nil {
			t.Fatal("End of Data left the response open")
		}
	}
	serial(pdu, pdu)
	if got := c.cache.Len(); got != 1 {
		t.Fatalf("replayed announce stored %d payloads", got)
	}
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIValid {
		t.Fatalf("before withdraw = %q, want valid", got)
	}
	serial(ipv4PDU(t, "198.51.100.0/24", 24, 64500, false))
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got == plugin.RPKIValid {
		t.Fatalf("withdrawn payload still validates: %q", got)
	}
}

// A serial delta reaches the cache only at End of Data. An Error Report
// partway through leaves the last complete cache, and a prefix PDU with no
// query outstanding is refused rather than applied.
func TestHandleAbandonedDeltaKeepsCache(t *testing.T) {
	c := &Client{cfg: Config{Staleness: time.Hour}, cache: rpki.NewVRPs()}
	c.cache.Apply([]rpki.Change{{Prefix: mustPrefix(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64500}})
	c.setUp(10, 7)
	if _, _, err := c.handle(ipv4PDU(t, "198.51.100.0/24", 24, 64500, false), nil); err == nil {
		t.Fatal("prefix PDU outside a response was accepted")
	}
	resp, q := c.request()
	if !bytes.Equal(q, serialQuery(7, 10)) || resp == nil || resp.table != nil {
		t.Fatalf("request = %v, want a serial query for session 7 serial 10", q)
	}
	var err error
	for _, pdu := range [][]byte{
		cacheResponsePDU(),
		ipv4PDU(t, "198.51.100.0/24", 24, 64500, false),
		ipv4PDU(t, "203.0.113.0/24", 24, 64501, true),
	} {
		if resp, _, err = c.handle(pdu, resp); err != nil {
			t.Fatal(err)
		}
	}
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIValid {
		t.Fatalf("withdraw applied before End of Data: %q", got)
	}
	if got := c.Validate(mustPrefix(t, "203.0.113.0/24"), 64501); got != plugin.RPKINotFound {
		t.Fatalf("announce applied before End of Data: %q", got)
	}
	if _, _, err := c.handle(errorReportPDU(2), resp); err == nil {
		t.Fatal("error report did not end the session")
	}
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIValid {
		t.Fatalf("abandoned delta changed the cache: %q", got)
	}
	if got := c.cache.Len(); got != 1 {
		t.Fatalf("abandoned delta left %d payloads, want 1", got)
	}
	if c.serial != 10 {
		t.Fatalf("abandoned delta moved the serial to %d", c.serial)
	}
}

// A connection that drops mid-delta keeps the previous cache: the next
// session starts with a reset, not from a half-applied serial.
func TestClientDroppedDeltaKeepsCache(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	dropped := make(chan struct{})
	var accepts atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n := accepts.Add(1)
			go func(conn net.Conn, n int32) {
				defer conn.Close()
				typ, _, _, err := readQuery(conn)
				if err != nil || typ != pduResetQuery {
					return
				}
				if n != 1 {
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				_, _ = conn.Write(cacheResponsePDU())
				_, _ = conn.Write(ipv4PDU(t, "198.51.100.0/24", 24, 64500, true))
				_, _ = conn.Write(endOfDataPDU(10))
				_, _ = conn.Write(serialNotifyPDU(7, 11))
				if typ, _, _, err := readQuery(conn); err != nil || typ != pduSerialQuery {
					return
				}
				_, _ = conn.Write(cacheResponsePDU())
				_, _ = conn.Write(ipv4PDU(t, "198.51.100.0/24", 24, 64500, false))
				close(dropped)
			}(conn, n)
		}
	}()

	cfg, err := plugin.ConfigFromYAML("address: " + ln.Addr().String() + "\nrefresh: 30s\ntimeout: 1s\nstaleness: 1h\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "rpki-lab"})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	select {
	case <-dropped:
	case <-time.After(3 * time.Second):
		t.Fatal("server never sent the partial delta")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && accepts.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := accepts.Load(); got < 2 {
		t.Fatalf("client did not redial after the drop (connections = %d)", got)
	}
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIValid {
		t.Fatalf("after a dropped delta = %q, want the previous cache's valid", got)
	}
}

// A Serial Notify during a serial response draws no second query before
// End of Data (RFC 8210 section 8.2), and the delta still applies.
func TestClientNotifyDuringSerialResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	early := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if typ, _, _, err := readQuery(conn); err != nil || typ != pduResetQuery {
			return
		}
		_, _ = conn.Write(cacheResponsePDU())
		_, _ = conn.Write(ipv4PDU(t, "198.51.100.0/24", 24, 64500, true))
		_, _ = conn.Write(endOfDataPDU(10))
		_, _ = conn.Write(serialNotifyPDU(7, 11))
		if typ, _, _, err := readQuery(conn); err != nil || typ != pduSerialQuery {
			return
		}
		_, _ = conn.Write(cacheResponsePDU())
		_, _ = conn.Write(serialNotifyPDU(7, 12))
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 8)
		n, _ := conn.Read(buf)
		_ = conn.SetReadDeadline(time.Time{})
		if n > 0 {
			early <- struct{}{}
			return
		}
		_, _ = conn.Write(ipv4PDU(t, "203.0.113.0/24", 24, 64501, true))
		_, _ = conn.Write(endOfDataPDU(11))
		_, _ = io.Copy(io.Discard, conn)
	}()

	cfg, err := plugin.ConfigFromYAML("address: " + ln.Addr().String() + "\nrefresh: 30s\ntimeout: 2s\nstaleness: 1h\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "rpki-lab"})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	next := mustPrefix(t, "203.0.113.0/24")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-early:
			t.Fatal("serial notify during a serial response drew a query")
		default:
		}
		if c.Validate(next, 64501) == plugin.RPKIValid {
			if st := c.Status(); !st.Up || st.VRPs != 2 {
				t.Fatalf("status after delta = %+v, want up with 2 VRPs", st)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("serial delta was not applied")
}

// A cache older than the staleness limit is unknown: it fails open.
func TestClientStaleUnknown(t *testing.T) {
	addr := stubServer(t, ipv4PDU(t, "198.51.100.0/24", 24, 64500, true))
	c := startClient(t, addr)
	c.mu.Lock()
	c.updated = time.Now().Add(-2 * time.Hour)
	c.mu.Unlock()
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIUnknown {
		t.Fatalf("stale = %q, want unknown", got)
	}
	if !c.Status().Stale {
		t.Fatal("Status.Stale = false on stale cache")
	}
}

// Without a server the client is down and every lookup is unknown.
func TestClientUnreachableUnknown(t *testing.T) {
	cfg, err := plugin.ConfigFromYAML("address: 127.0.0.1:9\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "down"})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := contextWithTimeout(2 * time.Second)
	defer cancel()
	defer func() { _ = c.Stop(ctx) }()
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIUnknown {
		t.Fatalf("unreachable = %q, want unknown", got)
	}
}

// Strict config validation rejects a missing or malformed server and
// out-of-range timers.
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"missing address", "refresh: 10s\n"},
		{"no port", "address: 192.0.2.1\n"},
		{"bad port", "address: 192.0.2.1:notaport\n"},
		{"refresh too small", "address: 192.0.2.1:3323\nrefresh: 1ms\n"},
		{"staleness below refresh", "address: 192.0.2.1:3323\nrefresh: 10m\nstaleness: 1m\n"},
		{"timeout too large", "address: 192.0.2.1:3323\ntimeout: 1h\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := plugin.ConfigFromYAML(tt.yaml)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(cfg, plugin.Env{}); err == nil {
				t.Fatalf("New accepted %q", tt.yaml)
			}
		})
	}
	// A valid config defaults the timers.
	cfg, err := plugin.ConfigFromYAML("address: 192.0.2.1:3323\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	if c.cfg.Refresh != DefaultRefresh || c.cfg.Staleness != DefaultStaleness || c.cfg.Timeout != DefaultTimeout {
		t.Fatalf("defaults = %+v", c.cfg)
	}
}

func serialNotifyPDU(session uint16, serial uint32) []byte {
	b := make([]byte, 12)
	b[0], b[1] = protocolVersion, pduSerialNotify
	binary.BigEndian.PutUint16(b[2:4], session)
	binary.BigEndian.PutUint32(b[4:8], 12)
	binary.BigEndian.PutUint32(b[8:12], serial)
	return b
}

func errorReportPDU(code uint16) []byte {
	// Header, an empty encapsulated PDU, and empty text (RFC 8210 section 5.10).
	b := make([]byte, 16)
	b[0], b[1] = protocolVersion, pduErrorReport
	binary.BigEndian.PutUint16(b[2:4], code)
	binary.BigEndian.PutUint32(b[4:8], 16)
	return b
}

// readQuery reads one Reset Query or Serial Query from the router.
func readQuery(conn net.Conn) (byte, uint16, uint32, error) {
	head := make([]byte, 8)
	if _, err := io.ReadFull(conn, head); err != nil {
		return 0, 0, 0, err
	}
	typ := head[1]
	session := binary.BigEndian.Uint16(head[2:4])
	n := binary.BigEndian.Uint32(head[4:8])
	if n < 8 || n > 64 {
		return typ, session, 0, io.ErrUnexpectedEOF
	}
	var serial uint32
	if n > 8 {
		rest := make([]byte, n-8)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return typ, session, 0, err
		}
		if typ == pduSerialQuery && len(rest) >= 4 {
			serial = binary.BigEndian.Uint32(rest[:4])
		}
	}
	return typ, session, serial, nil
}

// A Serial Notify before End of Data draws no query. After End of Data, a
// notify for the same session is answered with the client's last serial,
// not the serial in the notify, and that delta is applied.
func TestClientSerialNotifyAppliesDelta(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	first := ipv4PDU(t, "198.51.100.0/24", 24, 64500, true)
	delta := ipv4PDU(t, "203.0.113.0/24", 24, 64501, true)
	notify := serialNotifyPDU(7, 99)
	type query struct {
		typ     byte
		session uint16
		serial  uint32
	}
	early := make(chan struct{}, 1)
	got := make(chan query, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		typ, _, _, err := readQuery(conn)
		if err != nil || typ != pduResetQuery {
			return
		}
		if _, err := conn.Write(notify); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 8)
		n, _ := conn.Read(buf)
		_ = conn.SetReadDeadline(time.Time{})
		if n > 0 {
			early <- struct{}{}
			return
		}
		if _, err := conn.Write(cacheResponsePDU()); err != nil {
			return
		}
		if _, err := conn.Write(first); err != nil {
			return
		}
		if _, err := conn.Write(endOfDataPDU(10)); err != nil {
			return
		}
		if _, err := conn.Write(notify); err != nil {
			return
		}
		typ, session, serial, err := readQuery(conn)
		if err != nil {
			return
		}
		got <- query{typ, session, serial}
		if typ != pduSerialQuery || session != 7 || serial != 10 {
			return
		}
		_, _ = conn.Write(cacheResponsePDU())
		_, _ = conn.Write(delta)
		_, _ = conn.Write(endOfDataPDU(99))
		_, _ = io.Copy(io.Discard, conn)
	}()

	cfg, err := plugin.ConfigFromYAML("address: " + ln.Addr().String() + "\nrefresh: 10s\nstaleness: 1h\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "rpki-lab"})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	var q query
	deadline := time.Now().Add(2 * time.Second)
	for !c.Status().Up && time.Now().Before(deadline) {
		select {
		case <-early:
			t.Fatal("serial notify before End of Data drew a query")
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !c.Status().Up {
		select {
		case <-early:
			t.Fatal("serial notify before End of Data drew a query")
		default:
		}
		t.Fatal("client never became up")
	}
	select {
	case <-early:
		t.Fatal("serial notify before End of Data drew a query")
	case q = <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("no query after serial notify")
	}
	if q.typ != pduSerialQuery || q.session != 7 || q.serial != 10 {
		t.Fatalf("query type %d session %d serial %d, want serial query session 7 serial 10", q.typ, q.session, q.serial)
	}
	deadline = time.Now().Add(2 * time.Second)
	next := mustPrefix(t, "203.0.113.0/24")
	for time.Now().Before(deadline) {
		if c.Validate(next, 64501) == plugin.RPKIValid {
			if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIValid {
				t.Fatalf("original payload = %q, want valid", got)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("serial delta was not applied")
}

// Same-session notify uses the stored serial and is ignored while any
// response is in flight. A different session starts a reset whose End of
// Data replaces the cache instead of merging into it.
func TestHandleSerialNotify(t *testing.T) {
	c := &Client{cfg: Config{Staleness: time.Hour}, cache: rpki.NewVRPs()}
	if resp, reply, err := c.handle(serialNotifyPDU(7, 99), nil); err != nil || reply != nil || resp != nil {
		t.Fatalf("unsynced notify reply=%v resp=%v err=%v", reply, resp, err)
	}
	if _, _, err := c.handle([]byte{protocolVersion, pduSerialNotify}, nil); err == nil {
		t.Fatal("short serial notify accepted")
	}

	c.setUp(10, 7)
	reset, _ := resetRequest()
	serial, _ := c.request()
	for name, open := range map[string]*response{"reset": reset, "serial": serial} {
		got, reply, err := c.handle(serialNotifyPDU(7, 99), open)
		if err != nil || reply != nil || got != open {
			t.Fatalf("notify during %s response reply=%v same=%v err=%v", name, reply, got == open, err)
		}
	}

	resp, reply, err := c.handle(serialNotifyPDU(7, 99), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, serialQuery(7, 10)) || resp == nil || resp.table != nil {
		t.Fatalf("serial query = %v, want session 7 serial 10", reply)
	}
	for _, pdu := range [][]byte{ipv4PDU(t, "198.51.100.0/24", 24, 64500, true), endOfDataPDU(10)} {
		if resp, _, err = c.handle(pdu, resp); err != nil {
			t.Fatal(err)
		}
	}

	resp, reply, err = c.handle(serialNotifyPDU(9, 50), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, resetQuery()) {
		t.Fatalf("session mismatch reply = %v, want reset query", reply)
	}
	if resp == nil || resp.table == nil || resp.table.Len() != 0 {
		t.Fatal("session mismatch did not start an empty table")
	}
	if resp, _, err = c.handle(ipv4PDU(t, "203.0.113.0/24", 24, 64501, true), resp); err != nil {
		t.Fatal(err)
	}
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKIValid {
		t.Fatalf("cache changed before End of Data: %q", got)
	}
	if resp, _, err = c.handle(endOfDataPDU(3), resp); err != nil || resp != nil {
		t.Fatalf("end of data resp=%v err=%v", resp, err)
	}
	if got := c.Validate(mustPrefix(t, "198.51.100.0/24"), 64500); got != plugin.RPKINotFound {
		t.Fatalf("old payload after reset = %q, want notfound", got)
	}
	if got := c.Validate(mustPrefix(t, "203.0.113.0/24"), 64501); got != plugin.RPKIValid {
		t.Fatalf("reset payload = %q, want valid", got)
	}
}

// Error Report code 2 is a retry. A cache that already validated an origin
// keeps those VRPs, and the client opens a new session.
func TestClientErrorReportKeepsCache(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	payload := ipv4PDU(t, "198.51.100.0/24", 24, 64500, true)
	report := errorReportPDU(2)
	var accepts atomic.Int32
	seen := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n := accepts.Add(1)
			go func(conn net.Conn, n int32) {
				defer conn.Close()
				typ, _, _, err := readQuery(conn)
				if err != nil || typ != pduResetQuery {
					return
				}
				if n != 1 {
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				_, _ = conn.Write(cacheResponsePDU())
				_, _ = conn.Write(payload)
				_, _ = conn.Write(endOfDataPDU(10))
				select {
				case <-seen:
				case <-time.After(5 * time.Second):
					return
				}
				_, _ = conn.Write(report)
				_, _ = io.Copy(io.Discard, conn)
			}(conn, n)
		}
	}()

	cfg, err := plugin.ConfigFromYAML("address: " + ln.Addr().String() + "\nrefresh: 30s\ntimeout: 1s\nstaleness: 1h\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "rpki-lab"})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	prefix := mustPrefix(t, "198.51.100.0/24")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && c.Validate(prefix, 64511) != plugin.RPKIInvalid {
		time.Sleep(5 * time.Millisecond)
	}
	if got := c.Validate(prefix, 64511); got != plugin.RPKIInvalid {
		t.Fatalf("before error report = %q, want invalid", got)
	}
	close(seen)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && accepts.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := accepts.Load(); got < 2 {
		t.Fatalf("error report was not retried (connections = %d)", got)
	}
	if got := c.Validate(prefix, 64511); got != plugin.RPKIInvalid {
		t.Fatalf("after error report = %q, want invalid", got)
	}
	if got := c.Status().VRPs; got != 1 {
		t.Fatalf("VRPs = %d after error report, want the previous cache", got)
	}
}

// Error Report code 2 before any End of Data does not publish an empty
// fresh cache. Lookups stay unknown and the client retries.
func TestClientErrorReportWithoutDataStaysUnknown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	report := errorReportPDU(2)
	var accepts atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				typ, _, _, err := readQuery(conn)
				if err != nil || typ != pduResetQuery {
					return
				}
				_, _ = conn.Write(report)
				_, _ = io.Copy(io.Discard, conn)
			}(conn)
		}
	}()

	cfg, err := plugin.ConfigFromYAML("address: " + ln.Addr().String() + "\nrefresh: 30s\ntimeout: 1s\nstaleness: 1h\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "rpki-lab"})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	prefix := mustPrefix(t, "198.51.100.0/24")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && accepts.Load() < 2 {
		st := c.Status()
		if st.Up && !st.Stale && st.VRPs == 0 {
			t.Fatal("error report code 2 marked an empty cache fresh")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := accepts.Load(); got < 2 {
		t.Fatalf("error report was not retried (connections = %d)", got)
	}
	if got := c.Validate(prefix, 64511); got != plugin.RPKIUnknown {
		t.Fatalf("no data = %q, want unknown", got)
	}
	if c.Status().Up {
		t.Fatal("error report left the source up")
	}
}

// A malformed length stops the decoder instead of allocating.
func TestSplitPDUsRejectsBadLength(t *testing.T) {
	buf := make([]byte, 8)
	buf[0], buf[1] = protocolVersion, pduCacheResponse
	binary.BigEndian.PutUint32(buf[4:8], 3)
	if _, _, err := splitPDUs(buf); err == nil {
		t.Fatal("splitPDUs accepted a length below the header")
	}
}
