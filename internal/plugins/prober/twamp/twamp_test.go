package twamp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/twamp"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var lo = netip.MustParseAddr("127.0.0.1")

func newProber(t *testing.T, y string) plugin.Prober {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	p, err := plugin.Probers.New(TypeName, c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// reflector runs the real Session-Reflector on the loopback and returns
// its port.
func reflector(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: lo.AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = twamp.Serve(ctx, conn, twamp.NewReflector(0), slog.New(slog.DiscardHandler))
	}()
	t.Cleanup(func() { cancel(); <-done })
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// Every packet answered ends the run at the last reply, not Timeout after
// the last send.
func TestTrainInOrder(t *testing.T) {
	port := reflector(t)
	p := newProber(t, "")
	start := time.Now()
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: lo, Port: port, Count: 5, Spacing: 2 * time.Millisecond, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("took %s with every reply in", took)
	}
	if res.Sent != 5 || len(res.RTTs) != 5 || !slices.Equal(res.Order, []int{0, 1, 2, 3, 4}) {
		t.Fatalf("res = %+v", res)
	}
	for _, rtt := range res.RTTs {
		if rtt <= 0 || rtt > time.Second {
			t.Fatalf("rtt %s", rtt)
		}
	}
}

// A reflector that holds every packet of the train and answers them with
// the last two swapped: the prober reports the arrival order, and RTTs
// stay in send order.
func TestTrainReordered(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: lo.AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const count = 4
	go func() {
		var pkts [][]byte
		var from *net.UDPAddr
		buf := make([]byte, 1500)
		for len(pkts) < count {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			from = addr
			pkts = append(pkts, slices.Clone(buf[:n]))
		}
		r := twamp.NewReflector(0)
		src, _ := netip.ParseAddrPort(from.String())
		for _, i := range []int{0, 1, 3, 2} {
			out, _ := r.Reply(src, 64, pkts[i], time.Now())
			_, _ = conn.WriteToUDP(out, from)
			time.Sleep(time.Millisecond)
		}
	}()
	p := newProber(t, "")
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: lo, Port: uint16(conn.LocalAddr().(*net.UDPAddr).Port),
		Count: count, Spacing: time.Millisecond, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != count || len(res.RTTs) != count || !slices.Equal(res.Order, []int{0, 1, 3, 2}) {
		t.Fatalf("res = %+v", res)
	}
	// Packet 2 was answered after packet 3, so its RTT is the longer one.
	if res.RTTs[2] <= res.RTTs[3] {
		t.Fatalf("rtts %v: the held packet should have the longer RTT", res.RTTs)
	}
}

func TestNoReflector(t *testing.T) {
	// A closed loopback port answers with ICMP port unreachable, which the
	// connected socket reports as refused: that is an error, not loss.
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: lo.AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	c.Close()
	p := newProber(t, "")
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: lo, Port: port, Count: 2, Spacing: time.Millisecond, Timeout: 200 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("res = %+v, err = %v, want refused", res, err)
	}
}

func TestSourceUnavailable(t *testing.T) {
	p := newProber(t, "")
	_, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: netip.MustParseAddr("192.0.2.99"), Target: lo, Count: 1, Timeout: 100 * time.Millisecond})
	if !errors.Is(err, plugin.ErrSourceUnavailable) {
		t.Fatalf("err = %v, want ErrSourceUnavailable", err)
	}
}

func TestFamilyMismatch(t *testing.T) {
	p := newProber(t, "")
	_, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: netip.MustParseAddr("::1"), Count: 1, Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "address family") {
		t.Fatalf("err = %v", err)
	}
}

func TestCancel(t *testing.T) {
	port := reflector(t)
	p := newProber(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := p.Probe(ctx, plugin.ProbeRequest{Source: lo, Target: lo, Port: port, Count: 3, Spacing: 50 * time.Millisecond, Timeout: time.Second})
	if !errors.Is(err, context.Canceled) || res.Sent > 1 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestConfig(t *testing.T) {
	for y, want := range map[string]string{
		"port: 70000":          "port 70000 must be between",
		"packet_interval: -1s": "must not be negative",
		"padding: 3":           "padding 3 must be between 27 and 1400",
		"socket: raw":          "field socket not found",
	} {
		c, _ := plugin.ConfigFromYAML(y)
		if _, err := plugin.Probers.New(TypeName, c, plugin.Env{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
	p := newProber(t, "").(*Prober)
	if p.port != twamp.DefaultPort || p.interval != DefaultPacketInterval || p.padding != DefaultPadding {
		t.Fatalf("defaults %+v", p)
	}
	p = newProber(t, "port: 8620\npacket_interval: 5ms\npadding: 100").(*Prober)
	if p.port != 8620 || p.interval != 5*time.Millisecond || p.padding != 100 {
		t.Fatalf("configured %+v", p)
	}
}

// A zero-packet request sends nothing and reports nothing.
func TestZeroCount(t *testing.T) {
	port := reflector(t)
	p := newProber(t, "")
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: lo, Port: port, Count: 0, Timeout: time.Second})
	if err != nil || res.Sent != 0 || len(res.RTTs) != 0 || len(res.Order) != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}
