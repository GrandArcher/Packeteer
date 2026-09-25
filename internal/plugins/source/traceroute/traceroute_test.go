package traceroute

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"golang.org/x/sys/unix"
)

func build(y string) (plugin.TargetSource, error) {
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		return nil, err
	}
	return plugin.Sources.New(TypeName, c, plugin.Env{})
}

func must(t *testing.T, y string) *Source {
	t.Helper()
	s, err := build(y)
	if err != nil {
		t.Fatal(err)
	}
	return s.(*Source)
}

type hopReply struct {
	from    netip.Addr
	reached bool
}

// perTTL counts probes at each TTL so the script can return a specific sample.
type perTTL struct {
	hops  map[int][]hopReply
	seen  map[int]int
	calls atomic.Int32
}

func (p *perTTL) Probe(_ context.Context, _, _ netip.Addr, ttl, _ int, _ time.Duration) (netip.Addr, bool, error) {
	p.calls.Add(1)
	if p.seen == nil {
		p.seen = map[int]int{}
	}
	i := p.seen[ttl]
	p.seen[ttl] = i + 1
	replies := p.hops[ttl]
	if i >= len(replies) {
		return netip.Addr{}, false, nil
	}
	return replies[i].from, replies[i].reached, nil
}

func a(s string) netip.Addr { return netip.MustParseAddr(s) }

func replies(addrs ...string) []hopReply {
	out := make([]hopReply, len(addrs))
	for i, s := range addrs {
		if s == "" {
			continue
		}
		out[i] = hopReply{from: a(s)}
	}
	return out
}

func TestSelectHost(t *testing.T) {
	dest := a("198.51.100.1")
	gw := a("192.0.2.1")
	near := a("203.0.113.1")
	loop := a("127.0.0.1")

	hops := [][]sample{
		{{from: gw}, {from: gw}, {from: gw}},
		{{from: near}, {from: near}, {}},
		{{}, {}, {}},
	}
	got, ok := selectHost(hops, dest, 2)
	if !ok || got != near {
		t.Fatalf("last stable hop = %s ok=%v, want %s", got, ok, near)
	}

	// Destination answers: keep the configured host, not an earlier router.
	hops = [][]sample{
		{{from: gw}, {from: gw}, {from: gw}},
		{{from: dest, reached: true}, {from: dest, reached: true}, {from: dest, reached: true}},
	}
	got, ok = selectHost(hops, dest, 2)
	if !ok || got != dest {
		t.Fatalf("dest answered: got %s ok=%v", got, ok)
	}

	// Flapping hop is not stable. The earlier stable hop is used.
	hops = [][]sample{
		{{from: gw}, {from: gw}, {from: gw}},
		{{from: a("203.0.113.2")}, {from: a("203.0.113.3")}, {from: a("203.0.113.4")}},
	}
	got, ok = selectHost(hops, dest, 2)
	if !ok || got != gw {
		t.Fatalf("flap fell through to %s ok=%v", got, ok)
	}

	// A loopback answer that is not the destination is ignored.
	hops = [][]sample{
		{{from: loop}, {from: loop}, {from: loop}},
		{{from: near}, {from: near}, {from: near}},
	}
	got, ok = selectHost(hops, dest, 2)
	if !ok || got != near {
		t.Fatalf("loopback hop = %s ok=%v", got, ok)
	}

	if _, ok := selectHost([][]sample{{{}}}, dest, 2); ok {
		t.Fatal("silence must not invent a host")
	}
}

func TestDiscoverUsesFakeNetwork(t *testing.T) {
	s := must(t, `
timeout: 1ms
probes: 3
min_replies: 2
max_hops: 8
interval: 1s
targets:
  - {prefix: 198.51.100.0/24, host: 198.51.100.1, weight: 4}
  - {prefix: 203.0.113.0/24, host: 203.0.113.9}
`)
	fake := &perTTL{hops: map[int][]hopReply{}}
	// First destination walks TTL 1 (gateway) then TTL 2 (near) then gap.
	// The fake is shared, so the second destination sees the same topology.
	// Both therefore resolve to the near hop, which is the point of the
	// second case below — split by swapping the script between calls.
	near := replies("203.0.113.50", "203.0.113.50", "203.0.113.50")
	gw := replies("192.0.2.1", "192.0.2.1", "192.0.2.1")
	fake.hops[1] = gw
	fake.hops[2] = near
	s.hop = fake
	s.now = func() time.Time { return time.Unix(1000, 0) }

	// Host answers at TTL 2 for a dedicated trace.
	dest := a("198.51.100.1")
	answered := &perTTL{hops: map[int][]hopReply{
		1: gw,
		2: {{from: dest, reached: true}, {from: dest, reached: true}, {from: dest, reached: true}},
	}}
	host, ok, err := s.trace(context.Background(), answered, dest)
	if err != nil || !ok || host != dest {
		t.Fatalf("host answered: %s ok=%v err=%v", host, ok, err)
	}

	silentDest := a("203.0.113.9")
	quiet := &perTTL{hops: map[int][]hopReply{
		1: gw,
		2: near,
	}}
	host, ok, err = s.trace(context.Background(), quiet, silentDest)
	if err != nil || !ok || host.String() != "203.0.113.50" {
		t.Fatalf("near hop = %s ok=%v err=%v", host, ok, err)
	}
	// gap of 3 after the stable hop, so TTL 2 plus 3 silent = 5 TTLs, 3 probes each.
	if quiet.calls.Load() != 5*3 {
		t.Fatalf("probes sent = %d, want %d (stop after the gap)", quiet.calls.Load(), 5*3)
	}
}

func TestTargetsCacheAndSourceDown(t *testing.T) {
	s := must(t, `
timeout: 1ms
probes: 1
min_replies: 1
max_hops: 4
interval: 1m
targets:
  - {prefix: 198.51.100.0/24, host: 198.51.100.1}
`)
	now := time.Unix(2000, 0)
	s.now = func() time.Time { return now }
	fake := &perTTL{hops: map[int][]hopReply{
		1: {{from: a("198.51.100.1"), reached: true}},
	}}
	s.hop = fake
	ts, err := s.Targets(context.Background())
	if err != nil || len(ts) != 1 || ts[0].Host.String() != "198.51.100.1" || ts[0].Prefix.String() != "198.51.100.0/24" {
		t.Fatalf("ts = %+v err = %v", ts, err)
	}
	calls := fake.calls.Load()
	now = now.Add(time.Second)
	if _, err := s.Targets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.calls.Load() != calls {
		t.Fatalf("cache miss: calls %d -> %d", calls, fake.calls.Load())
	}
	now = now.Add(time.Minute)
	if _, err := s.Targets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.calls.Load() == calls {
		t.Fatal("cache lived past the interval")
	}

	s.hop = errHopper{err: fmtSourceDown()}
	s.have = false
	_, err = s.Targets(context.Background())
	if !errors.Is(err, plugin.ErrSourceUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

type errHopper struct{ err error }

func (e errHopper) Probe(context.Context, netip.Addr, netip.Addr, int, int, time.Duration) (netip.Addr, bool, error) {
	return netip.Addr{}, false, e.err
}

func fmtSourceDown() error {
	return errors.Join(plugin.ErrSourceUnavailable, errors.New("bind"))
}

func TestNoStableHopOmitsTarget(t *testing.T) {
	s := must(t, `
probes: 3
min_replies: 2
max_hops: 2
interval: 1s
targets:
  - {prefix: 198.51.100.0/24}
`)
	s.hop = &perTTL{hops: map[int][]hopReply{
		1: {{from: a("192.0.2.1")}, {from: a("192.0.2.2")}, {from: a("192.0.2.3")}},
	}}
	s.now = time.Now
	ts, err := s.Targets(context.Background())
	if err != nil || len(ts) != 0 {
		t.Fatalf("ts = %+v err = %v", ts, err)
	}
}

func TestConfigErrors(t *testing.T) {
	tests := map[string]string{
		"": "targets is required",
		"targets:\n  - {prefix: 198.51.100.0/24}\nmax_hops: 0":                   "", // 0 means default; this one must succeed
		"targets:\n  - {prefix: 198.51.100.7/24}":                                "did you mean",
		"targets:\n  - {prefix: 198.51.100.0/24, host: 203.0.113.1}":             "must be an address inside",
		"targets:\n  - {prefix: 198.51.100.0/24}\n  - {prefix: 198.51.100.0/24}": "duplicate prefix",
		"targets:\n  - {prefix: 198.51.100.0/24, weight: -1}":                    "weight must not be negative",
		"targets:\n  - {prefix: 198.51.100.0/24}\nmax_hops: 99":                  "max_hops",
		"targets:\n  - {prefix: 198.51.100.0/24}\nprobes: 0":                     "", // default
		"targets:\n  - {prefix: 198.51.100.0/24}\nprobes: 1\nmin_replies: 2":     "min_replies",
		"targets:\n  - {prefix: 198.51.100.0/24}\ninterval: 10ms":                "interval",
		"targets:\n  - {prefix: 198.51.100.0/24}\nsource: not-an-ip":             "source",
		"targets:\n  - {prefix: 2001:db8::/32}\nsource: 192.0.2.11":              "address family",
		"targets:\n  - {prefix: 198.51.100.0/24}\nextra: 1":                      "field extra not found",
	}
	for y, want := range tests {
		_, err := build(y)
		if want == "" {
			if err != nil {
				t.Errorf("%q: unexpected %v", y, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
}

func TestParseExtErr(t *testing.T) {
	data := make([]byte, 16+16)
	binary.LittleEndian.PutUint32(data[0:4], uint32(unix.ECONNREFUSED))
	data[4] = unix.SO_EE_ORIGIN_ICMP
	data[5] = 11 // time exceeded
	data[6] = 0
	binary.LittleEndian.PutUint16(data[16:18], unix.AF_INET)
	copy(data[20:24], []byte{203, 0, 113, 1})
	from, typ, ok := parseExtErrData(data)
	if !ok || typ != 11 || from.String() != "203.0.113.1" {
		t.Fatalf("from=%s typ=%d ok=%v", from, typ, ok)
	}
	hop, reached := classify(false, typ)
	if !hop || reached {
		t.Fatalf("classify time exceeded: hop=%v reached=%v", hop, reached)
	}
	hop, reached = classify(false, 3)
	if !hop || !reached {
		t.Fatalf("classify dest unreach: hop=%v reached=%v", hop, reached)
	}

	v6 := make([]byte, 16+28)
	v6[4] = unix.SO_EE_ORIGIN_ICMP6
	v6[5] = 3 // time exceeded
	binary.LittleEndian.PutUint16(v6[16:18], unix.AF_INET6)
	copy(v6[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())
	from, typ, ok = parseExtErrData(v6)
	if !ok || typ != 3 || from.String() != "2001:db8::1" {
		t.Fatalf("v6 from=%s typ=%d ok=%v", from, typ, ok)
	}
}

func TestLoopbackDiscovery(t *testing.T) {
	s := must(t, `
timeout: 300ms
probes: 1
min_replies: 1
max_hops: 3
interval: 1s
port: 33434
targets:
  - {prefix: 127.0.0.1/32, host: 127.0.0.1}
`)
	s.now = time.Now
	ts, err := s.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 || ts[0].Host.String() != "127.0.0.1" || ts[0].Prefix.String() != "127.0.0.1/32" {
		t.Fatalf("loopback trace = %+v", ts)
	}
}

func TestLoopbackV6(t *testing.T) {
	s := must(t, `
timeout: 300ms
probes: 1
min_replies: 1
max_hops: 3
interval: 1s
port: 33434
targets:
  - {prefix: "::1/128", host: "::1"}
`)
	s.now = time.Now
	ts, err := s.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 || ts[0].Host.String() != "::1" {
		t.Fatalf("v6 loopback trace = %+v", ts)
	}
}

func TestBindMissingSource(t *testing.T) {
	_, _, err := udpHopper{}.Probe(context.Background(),
		a("192.0.2.99"), a("192.0.2.1"), 1, 33434, 200*time.Millisecond)
	if !errors.Is(err, plugin.ErrSourceUnavailable) {
		t.Fatalf("err = %v, want ErrSourceUnavailable", err)
	}
}
