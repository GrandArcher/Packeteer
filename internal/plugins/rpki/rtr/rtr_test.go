package rtr

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

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

// A malformed length stops the decoder instead of allocating.
func TestSplitPDUsRejectsBadLength(t *testing.T) {
	buf := make([]byte, 8)
	buf[0], buf[1] = protocolVersion, pduCacheResponse
	binary.BigEndian.PutUint32(buf[4:8], 3)
	if _, _, err := splitPDUs(buf); err == nil {
		t.Fatal("splitPDUs accepted a length below the header")
	}
}
