package twamp

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNTPTimestampRoundTrip(t *testing.T) {
	want := time.Date(2026, 10, 25, 12, 34, 56, 123456789, time.UTC)
	var b [8]byte
	putNTP(b[:], want)
	// 2026-10-25T12:34:56Z is 1792931696 seconds since 1970, so the NTP
	// seconds field is that plus the 1900 to 1970 offset.
	if sec := binary.BigEndian.Uint32(b[0:4]); sec != 1792931696+ntpEpochOffset {
		t.Fatalf("seconds = %d", sec)
	}
	got := ntpTime(b[:])
	if d := got.Sub(want); d < -time.Microsecond || d > time.Microsecond {
		t.Fatalf("round trip off by %s", d)
	}
	putNTP(b[:], time.Time{})
	if !ntpTime(b[:]).IsZero() {
		t.Fatal("zero time did not round trip")
	}
}

// TestSenderLayout is the RFC 5357 section 4.1.2 layout: a standard
// TWAMP-Light sender's packet decodes field by field.
func TestSenderLayout(t *testing.T) {
	raw := make([]byte, 14+27)
	binary.BigEndian.PutUint32(raw[0:4], 7)
	binary.BigEndian.PutUint32(raw[4:8], 3900000000)  // NTP seconds
	binary.BigEndian.PutUint32(raw[8:12], 0x80000000) // half a second
	binary.BigEndian.PutUint16(raw[12:14], 0x8001)    // S=1, multiplier 1
	sp, err := ParseSender(raw)
	if err != nil {
		t.Fatal(err)
	}
	if sp.Seq != 7 || sp.ErrorEstimate != 0x8001 || sp.Padding != 27 {
		t.Fatalf("parsed %+v", sp)
	}
	if want := time.Unix(3900000000-ntpEpochOffset, 500000000).UTC(); !sp.Timestamp.Equal(want) {
		t.Fatalf("timestamp %s, want %s", sp.Timestamp, want)
	}
	if _, err := ParseSender(raw[:13]); err != ErrShort {
		t.Fatalf("short packet err = %v", err)
	}
	if got := (SenderPacket{Seq: 7, Timestamp: sp.Timestamp, ErrorEstimate: 0x8001, Padding: 27}).Marshal(); string(got) != string(raw) {
		t.Fatalf("marshal differs:\n%x\n%x", got, raw)
	}
}

// TestReflectorInterop builds the reply to a packet laid out as a
// standard TWAMP-Light sender sends it and checks every field at its RFC
// 5357 section 4.2.1 offset, the echoed sender fields, the TTL, and that
// the reply is the sender's size.
func TestReflectorInterop(t *testing.T) {
	r := NewReflector(0)
	from := netip.MustParseAddrPort("192.0.2.11:50000")
	sent := time.Date(2026, 10, 25, 10, 0, 0, 250000000, time.UTC)
	in := SenderPacket{Seq: 41, Timestamp: sent, ErrorEstimate: 0x0001, Padding: 100}.Marshal()
	now := sent.Add(12 * time.Millisecond)
	out, ok := r.Reply(from, 63, in, now)
	if !ok {
		t.Fatal("no reply")
	}
	if len(out) != len(in) {
		t.Fatalf("reply is %d bytes, sender sent %d", len(out), len(in))
	}
	if seq := binary.BigEndian.Uint32(out[0:4]); seq != 0 {
		t.Fatalf("first reflector seq = %d", seq)
	}
	if ee := binary.BigEndian.Uint16(out[12:14]); ee != UnsyncedErrorEstimate {
		t.Fatalf("error estimate %#x", ee)
	}
	if mbz := binary.BigEndian.Uint16(out[14:16]); mbz != 0 {
		t.Fatalf("MBZ after error estimate = %d", mbz)
	}
	if got := ntpTime(out[16:24]); got.Sub(now) > time.Microsecond || now.Sub(got) > time.Microsecond {
		t.Fatalf("receive timestamp %s, want %s", got, now)
	}
	if ss := binary.BigEndian.Uint32(out[24:28]); ss != 41 {
		t.Fatalf("sender seq echoed as %d", ss)
	}
	if got := ntpTime(out[28:36]); got.Sub(sent) > time.Microsecond || sent.Sub(got) > time.Microsecond {
		t.Fatalf("sender timestamp echoed as %s", got)
	}
	if see := binary.BigEndian.Uint16(out[36:38]); see != 0x0001 {
		t.Fatalf("sender error estimate echoed as %#x", see)
	}
	if mbz := binary.BigEndian.Uint16(out[38:40]); mbz != 0 {
		t.Fatalf("MBZ before TTL = %d", mbz)
	}
	if out[40] != 63 {
		t.Fatalf("sender TTL = %d", out[40])
	}
	rp, err := ParseReflector(out)
	if err != nil || rp.SenderSeq != 41 || rp.SenderTTL != 63 || rp.Padding != 100-MinSenderPadding {
		t.Fatalf("parsed %+v, err %v", rp, err)
	}

	// The second packet of the same session has the next reflector seq;
	// another sender starts at zero.
	out, _ = r.Reply(from, 63, in, now)
	if seq := binary.BigEndian.Uint32(out[0:4]); seq != 1 {
		t.Fatalf("second reflector seq = %d", seq)
	}
	out, _ = r.Reply(netip.MustParseAddrPort("192.0.2.12:50000"), 63, in, now)
	if seq := binary.BigEndian.Uint32(out[0:4]); seq != 0 {
		t.Fatalf("new sender reflector seq = %d", seq)
	}

	// A sender that padded less than 27 octets still gets the full fixed
	// part; a non-TWAMP datagram gets nothing.
	out, ok = r.Reply(from, 63, SenderPacket{Seq: 1}.Marshal(), now)
	if !ok || len(out) != ReflectorMinLen {
		t.Fatalf("unpadded sender: ok %v, %d bytes", ok, len(out))
	}
	if _, ok := r.Reply(from, 63, []byte("ping"), now); ok {
		t.Fatal("a short datagram was answered")
	}
}

func sessions(r *Reflector) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

func TestReflectorSessionsBounded(t *testing.T) {
	r := NewReflector(3)
	now := time.Now()
	in := SenderPacket{Padding: MinSenderPadding}.Marshal()
	for i := 1; i <= 3; i++ {
		r.Reply(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i)), 1, in, now.Add(time.Duration(i)*time.Second))
	}
	if sessions(r) != 3 {
		t.Fatalf("sessions = %d", sessions(r))
	}
	// A fourth sender evicts the least recently seen one (port 1), whose
	// counter then restarts at zero.
	r.Reply(netip.MustParseAddrPort("192.0.2.1:4"), 1, in, now.Add(4*time.Second))
	if sessions(r) != 3 {
		t.Fatalf("sessions after eviction = %d", sessions(r))
	}
	out, _ := r.Reply(netip.MustParseAddrPort("192.0.2.1:1"), 1, in, now.Add(5*time.Second))
	if seq := binary.BigEndian.Uint32(out[0:4]); seq != 0 {
		t.Fatalf("evicted sender resumed at seq %d", seq)
	}
	// Idle sessions go first once the table is full again.
	r.Reply(netip.MustParseAddrPort("192.0.2.1:9"), 1, in, now.Add(20*time.Minute))
	if n := sessions(r); n != 1 {
		t.Fatalf("sessions after idle eviction = %d, want 1", n)
	}
}

func TestServeLoopback(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, conn, NewReflector(0), slog.New(slog.DiscardHandler)) }()

	c, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sent := time.Now()
	if _, err := c.Write(SenderPacket{Seq: 5, Timestamp: sent, ErrorEstimate: UnsyncedErrorEstimate, Padding: MinSenderPadding}.Marshal()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := ParseReflector(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if rp.SenderSeq != 5 || rp.Seq != 0 || n != SenderMinLen+MinSenderPadding {
		t.Fatalf("reply %+v (%d bytes)", rp, n)
	}
	// The loopback TTL is the host default (64 on Linux), never the
	// unknown marker, and the timestamps are the reflector's clock.
	if rp.SenderTTL == UnknownTTL || rp.SenderTTL == 0 {
		t.Fatalf("sender TTL = %d", rp.SenderTTL)
	}
	if rp.ReceiveTimestamp.Before(sent.Add(-time.Second)) || rp.Timestamp.Before(rp.ReceiveTimestamp) {
		t.Fatalf("timestamps receive %s send %s", rp.ReceiveTimestamp, rp.Timestamp)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// On a wildcard listen the reply leaves from the address the test packet
// was sent to, not the one the kernel would pick: a connected sender
// drops a reply from any other address (lab/docker-compose-reorder.yml
// sends to a loopback address and replies leave via another interface).
func TestServeWildcardRepliesFromDestination(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, conn, NewReflector(0), slog.New(slog.DiscardHandler)) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(SenderPacket{Seq: 3, Timestamp: time.Now(), ErrorEstimate: UnsyncedErrorEstimate, Padding: MinSenderPadding}.Marshal()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no reply from 127.0.0.2: %v", err)
	}
	if rp, err := ParseReflector(buf[:n]); err != nil || rp.SenderSeq != 3 {
		t.Fatalf("reply %+v, err %v", rp, err)
	}
}
