package flow

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/source/static"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func quiet() plugin.Env {
	return plugin.Env{Logger: slog.New(slog.DiscardHandler)}
}

func build(y string) (plugin.TargetSource, error) {
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		return nil, err
	}
	return plugin.Sources.New(TypeName, c, quiet())
}

func mustSource(t *testing.T, y string) *Source {
	t.Helper()
	s, err := build(y)
	if err != nil {
		t.Fatal(err)
	}
	return s.(*Source)
}

func pin(s *Source, at time.Time) {
	s.now = func() time.Time { return at }
}

func targetsOf(t *testing.T, s *Source) []plugin.Target {
	t.Helper()
	ts, err := s.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// Recorded NetFlow v5 export: one flow, 1024 bytes to 203.0.113.10.
// Documentation prefixes only.
var recordedNetFlowV5 = []byte{
	0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xcb, 0x00, 0x71, 0x0a,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestRecordedNetFlowV5(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\n")
	pin(s, time.Unix(1_700_000_000, 0))
	s.ingest(time.Unix(1_700_000_000, 0), netip.MustParseAddr("192.0.2.8"), recordedNetFlowV5)
	ts := targetsOf(t, s)
	if len(ts) != 1 {
		t.Fatalf("targets = %+v", ts)
	}
	if ts[0].Prefix.String() != "203.0.113.0/24" || ts[0].Host.String() != "203.0.113.10" || ts[0].Weight != 1024 {
		t.Fatalf("target = %+v", ts[0])
	}
}

func TestNetFlowV5SamplingTopNExcludeAndWindow(t *testing.T) {
	s := mustSource(t, `
listen: ["127.0.0.1:2055"]
window: 30s
top_n: 1
min_bytes: 1000
aggregate_v4: 24
exclude: ["192.0.2.0/24"]
`)
	t0 := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return t0 }
	// sampling interval 100 in the low 14 bits: 10 octets -> 1000 bytes.
	s.ingest(t0, netip.MustParseAddr("192.0.2.8"), buildV5(100, []v5rec{
		{dst: netip.MustParseAddr("198.51.100.10"), octets: 10},
		{dst: netip.MustParseAddr("198.51.100.50"), octets: 5}, // same /24, lighter host
		{dst: netip.MustParseAddr("203.0.113.9"), octets: 8},   // 800 bytes, under min and not top
		{dst: netip.MustParseAddr("192.0.2.20"), octets: 100},  // excluded
		{dst: netip.MustParseAddr("10.1.2.3"), octets: 100},    // private
		{dst: netip.MustParseAddr("224.0.0.1"), octets: 100},   // multicast
	}))
	ts := targetsOf(t, s)
	if len(ts) != 1 || ts[0].Prefix.String() != "198.51.100.0/24" || ts[0].Weight != 1500 || ts[0].Host.String() != "198.51.100.10" {
		t.Fatalf("targets = %+v", ts)
	}
	vols, err := s.Volumes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gotV := map[string]float64{}
	for _, v := range vols {
		gotV[v.Prefix.String()] = v.Mbps()
	}
	// 1500 bytes over the 30s window, and the 800-byte prefix that top_n
	// and min_bytes kept out of the probe list. 1500*8/30/1e6 = 0.0004.
	if len(gotV) != 2 || gotV["198.51.100.0/24"] != 1500*8/30.0/1e6 || gotV["203.0.113.0/24"] != 800*8/30.0/1e6 {
		t.Fatalf("volumes = %v", gotV)
	}
	s.now = func() time.Time { return t0.Add(31 * time.Second) }
	if got := targetsOf(t, s); len(got) != 0 {
		t.Fatalf("window did not expire: %+v", got)
	}
}

func TestRIBMapping(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\nwindow: 1m\ntop_n: 10\n")
	pin(s, time.Unix(1_700_000_000, 0))
	cover := netip.MustParsePrefix("198.51.0.0/16")
	s.SetPrefixLookup(func(a netip.Addr) (netip.Prefix, bool) {
		if cover.Contains(a) {
			return cover, true
		}
		if a.String() == "203.0.113.5" {
			return netip.MustParsePrefix("0.0.0.0/0"), true // ignored
		}
		if a.String() == "203.0.113.6" {
			return netip.MustParsePrefix("198.51.100.0/24"), true // does not contain dst
		}
		return netip.Prefix{}, false
	})
	now := time.Unix(1_700_000_000, 0)
	s.ingest(now, netip.MustParseAddr("192.0.2.8"), buildV5(0, []v5rec{
		{dst: netip.MustParseAddr("198.51.100.10"), octets: 100},
		{dst: netip.MustParseAddr("198.51.200.10"), octets: 50},
		{dst: netip.MustParseAddr("203.0.113.5"), octets: 40},
		{dst: netip.MustParseAddr("203.0.113.6"), octets: 30},
	}))
	ts := targetsOf(t, s)
	if len(ts) != 2 {
		t.Fatalf("targets = %+v", ts)
	}
	if ts[0].Prefix != cover || ts[0].Weight != 150 || ts[0].Host.String() != "198.51.100.10" {
		t.Fatalf("covered = %+v", ts[0])
	}
	if ts[1].Prefix.String() != "203.0.113.0/24" || ts[1].Weight != 70 {
		t.Fatalf("fallback = %+v", ts[1])
	}
}

func TestIPv6Aggregate(t *testing.T) {
	s := mustSource(t, "listen: '[::1]:2055'\naggregate_v6: 48\n")
	pin(s, time.Unix(1_700_000_000, 0))
	s.ingest(time.Unix(1_700_000_000, 0), netip.MustParseAddr("192.0.2.8"), buildIPFIX(1,
		tmplSetIPFIX(256, [][2]uint16{{ieDstV6, 16}, {ieInBytes, 8}}),
		dataSet(256, ip6rec(netip.MustParseAddr("2001:db8:1:2::5"), 80)),
	))
	ts := targetsOf(t, s)
	if len(ts) != 1 || ts[0].Prefix.String() != "2001:db8:1::/48" || ts[0].Host.String() != "2001:db8:1:2::5" || ts[0].Weight != 80 {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestNetFlowV9TemplateThenDataAndSampling(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\n")
	pin(s, time.Unix(1_700_000_000, 0))
	exp := netip.MustParseAddr("192.0.2.9")
	now := time.Unix(1_700_000_000, 0)
	// Data before the template is ignored.
	early := buildV9(7, dataSet(256, v4rec(netip.MustParseAddr("198.51.100.8"), 999)))
	s.ingest(now, exp, early)
	if len(targetsOf(t, s)) != 0 {
		t.Fatal("data without a template was counted")
	}
	// Options template carries the sampling interval; the data template does not.
	opt := optionsSetV9(257, 4, [][2]uint16{{1, 4}}, [][2]uint16{{ieSamplingInterval, 4}})
	flowT := tmplSetV9(256, [][2]uint16{{ieOutBytes, 4}, {ieDstV4, 4}, {ieInBytes, 4}})
	s.ingest(now, exp, buildV9(7, opt, flowT))
	optData := dataSet(257, putU32(0), putU32(10)) // scope, interval 10
	// out bytes 1, in bytes 25: in bytes wins even though it is later.
	flow := dataSet(256, putU32(1), v4only(netip.MustParseAddr("203.0.113.4")), putU32(25))
	s.ingest(now, exp, buildV9(7, optData, flow))
	ts := targetsOf(t, s)
	if len(ts) != 1 || ts[0].Prefix.String() != "203.0.113.0/24" || ts[0].Weight != 250 {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestIPFIXEnterpriseAndVariableLength(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\n")
	pin(s, time.Unix(1_700_000_000, 0))
	// Enterprise IE (PEN 9, type 100, 4 bytes) then a variable-length octet count
	// then the destination. The enterprise value must be skipped, not parsed as an address.
	set := ipfixEnterpriseTemplate(256)
	val := append([]byte{0x11, 0x22, 0x33, 0x44}, 0x04) // var length 4
	val = append(val, putU32(500)...)
	val = append(val, netip.MustParseAddr("198.51.100.7").AsSlice()...)
	s.ingest(time.Unix(1_700_000_000, 0), netip.MustParseAddr("192.0.2.8"), buildIPFIX(3, set, dataSet(256, val)))
	ts := targetsOf(t, s)
	if len(ts) != 1 || ts[0].Prefix.String() != "198.51.100.0/24" || ts[0].Host.String() != "198.51.100.7" || ts[0].Weight != 500 {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestSFlowSamples(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:6343\naggregate_v6: 48\n")
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	exp := netip.MustParseAddr("192.0.2.8")
	s.ingest(now, exp, buildSFlowV4(10, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.20"), 1500))
	s.ingest(now, exp, buildSFlowV6(1, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8:aaaa:bbbb::1"), 128))
	s.ingest(now, exp, buildSFlowEthernet(netip.MustParseAddr("203.0.113.15"), 60))
	// Explicit sampled IPv4 wins over a header that names a different destination.
	s.ingest(now, exp, buildSFlowPreferExplicit())
	ts := targetsOf(t, s)
	got := map[string]float64{}
	for _, tg := range ts {
		got[tg.Prefix.String()] = tg.Weight
		if tg.Prefix.String() == "198.51.100.0/24" && tg.Host.String() != "198.51.100.20" {
			t.Errorf("host = %s", tg.Host)
		}
	}
	if got["198.51.100.0/24"] != 1500*10+40 { // sampled (1500*10) plus the explicit record in the mixed sample (40, rate 1)
		t.Fatalf("v4 weight = %v targets %+v", got["198.51.100.0/24"], ts)
	}
	if got["2001:db8:aaaa::/48"] != 128 {
		t.Fatalf("v6 = %v", got["2001:db8:aaaa::/48"])
	}
	if got["203.0.113.0/24"] != 60 {
		t.Fatalf("ethernet = %v", got["203.0.113.0/24"])
	}
}

func TestSFlowExpandedSample(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:6343\n")
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	rec := sampledV4Record(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.8"), 200)
	var recs []byte
	recs = append(recs, rec...)
	body := make([]byte, 44+len(recs))
	binary.BigEndian.PutUint32(body[12:], 4) // sampling rate, after seq + source type/index
	binary.BigEndian.PutUint32(body[40:], 1) // one record
	copy(body[44:], recs)
	s.ingest(now, netip.MustParseAddr("192.0.2.8"), sflowDatagram(sample(sflowFormatExpanded, body)))
	ts := targetsOf(t, s)
	if len(ts) != 1 || ts[0].Prefix.String() != "198.51.100.0/24" || ts[0].Weight != 800 || ts[0].Host.String() != "198.51.100.8" {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestSFlowVLANHeader(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:6343\n")
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	hdr := make([]byte, 18+20)
	hdr[12], hdr[13] = 0x81, 0x00
	hdr[16], hdr[17] = 0x08, 0x00
	hdr[18] = 0x45
	binary.BigEndian.PutUint16(hdr[20:], 100)
	copy(hdr[34:38], netip.MustParseAddr("203.0.113.40").AsSlice())
	raw := make([]byte, 16+len(hdr))
	binary.BigEndian.PutUint32(raw[0:], sflowHeaderEthernet)
	binary.BigEndian.PutUint32(raw[4:], uint32(len(hdr)))
	binary.BigEndian.PutUint32(raw[12:], uint32(len(hdr)))
	copy(raw[16:], hdr)
	s.ingest(now, netip.MustParseAddr("192.0.2.8"), sflowDatagram(flowSampleBody(1, record(sflowRawHeader, raw))))
	ts := targetsOf(t, s)
	if len(ts) != 1 || ts[0].Prefix.String() != "203.0.113.0/24" || ts[0].Host.String() != "203.0.113.40" || ts[0].Weight != 100 {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestShortAndGarbagePackets(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\n")
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	exp := netip.MustParseAddr("192.0.2.8")
	for _, p := range [][]byte{nil, {0}, {0, 5}, {0, 0, 0, 5}, {0, 9}, {0, 10}, make([]byte, 20), {0xff, 0xff, 0xff, 0xff}} {
		s.ingest(now, exp, p)
	}
	if len(targetsOf(t, s)) != 0 {
		t.Fatal("garbage produced targets")
	}
	s.ingest(now, exp, recordedNetFlowV5)
	if len(targetsOf(t, s)) != 1 {
		t.Fatal("valid packet after garbage was dropped")
	}
}

func TestPrefixCap(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\nwindow: 1m\ntop_n: 10\n")
	pin(s, time.Unix(1_700_000_000, 0))
	s.win.max = 1
	now := time.Unix(1_700_000_000, 0)
	s.ingest(now, netip.MustParseAddr("192.0.2.8"), buildV5(0, []v5rec{
		{dst: netip.MustParseAddr("198.51.100.1"), octets: 10},
		{dst: netip.MustParseAddr("203.0.113.1"), octets: 5},  // dropped, smaller than the only slot
		{dst: netip.MustParseAddr("203.0.113.2"), octets: 50}, // replaces the smaller prefix
	}))
	ts := targetsOf(t, s)
	if len(ts) != 1 || ts[0].Prefix.String() != "203.0.113.0/24" || ts[0].Weight != 50 {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestUDPListener(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:0\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stop, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		if err := s.Stop(stop); err != nil {
			t.Error(err)
		}
	}()
	dst, err := net.ResolveUDPAddr("udp", s.conns[0].LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(recordedNetFlowV5); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		ts, err := s.Targets(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(ts) == 1 && ts[0].Prefix.String() == "203.0.113.0/24" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for flow target: %+v", ts)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestListenFailure(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := mustSource(t, "listen: "+ln.LocalAddr().String()+"\n")
	err = s.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigErrors(t *testing.T) {
	tests := map[string]string{
		"":                             "listen is required",
		"listen: []":                   "listen is required",
		"listen: not-a-port":           "not host:port",
		"listen: example.invalid:2055": "must be an IP address",
		"listen: 127.0.0.1:99999":      "port",
		"listen: [127.0.0.1:2055, 127.0.0.1:2055]":                            "duplicate",
		"listen: 127.0.0.1:2055\nwindow: 10ms":                                "must be between",
		"listen: 127.0.0.1:2055\nwindow: -1s":                                 "must be between",
		"listen: 127.0.0.1:2055\ntop_n: -1":                                   "top_n",
		"listen: 127.0.0.1:2055\ntop_n: 100000":                               "top_n",
		"listen: 127.0.0.1:2055\naggregate_v4: 33":                            "aggregate_v4",
		"listen: 127.0.0.1:2055\naggregate_v6: 129":                           "aggregate_v6",
		"listen: 127.0.0.1:2055\nexclude: [198.51.100.1/24]":                  "host bits",
		"listen: 127.0.0.1:2055\nexclude: [198.51.100.0/24, 198.51.100.0/24]": "duplicate",
		"listen: 127.0.0.1:2055\nnope: true":                                  "field nope not found",
	}
	for y, want := range tests {
		_, err := build(y)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
}

func TestDefaults(t *testing.T) {
	s := mustSource(t, "listen: ':2055'\n")
	if s.window != defaultWindow || s.topN != defaultTopN || s.agg4 != 24 || s.agg6 != 48 || s.listen[0] != ":2055" {
		t.Fatalf("defaults = %+v listen %v", s, s.listen)
	}
	// Idle source is not an error.
	if ts := targetsOf(t, s); len(ts) != 0 {
		t.Fatalf("idle = %+v", ts)
	}
}

type nopProber struct{ plugin.Base }

func (nopProber) Probe(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
	return plugin.ProbeResult{}, nil
}

func TestMergedWithStatic(t *testing.T) {
	fs := mustSource(t, "listen: 127.0.0.1:9\nwindow: 1m\ntop_n: 10\n")
	pin(fs, time.Unix(1_700_000_000, 0))
	fs.ingest(time.Unix(1_700_000_000, 0), netip.MustParseAddr("192.0.2.8"), buildV5(0, []v5rec{
		{dst: netip.MustParseAddr("198.51.100.10"), octets: 500},
		{dst: netip.MustParseAddr("203.0.113.5"), octets: 80},
	}))
	st, err := static.New(mustConfig(t, "targets: [{prefix: 198.51.100.0/24, host: 198.51.100.9}]"), quiet())
	if err != nil {
		t.Fatal(err)
	}
	e, err := probe.New(
		[]probe.Provider{{Name: "a", Source: netip.MustParseAddr("192.0.2.11")}},
		[]probe.NamedProber{{Name: "nop", Prober: nopProber{}}},
		[]probe.NamedSource{{Name: "static", Source: st}, {Name: "flow", Source: fs}},
		probe.Options{Interval: time.Second, Timeout: time.Second, Packets: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	ts := e.Targets(context.Background())
	if len(ts) != 2 {
		t.Fatalf("merged = %+v", ts)
	}
	if ts[0].Prefix.String() != "198.51.100.0/24" || ts[0].Host.String() != "198.51.100.9" {
		t.Fatalf("static should win the duplicate: %+v", ts[0])
	}
	if ts[1].Prefix.String() != "203.0.113.0/24" || ts[1].Host.String() != "203.0.113.5" || ts[1].Weight != 80 {
		t.Fatalf("flow-only = %+v", ts[1])
	}
}

func mustConfig(t *testing.T, y string) plugin.Config {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type v5rec struct {
	dst    netip.Addr
	octets uint32
}

func buildV5(sampling uint16, recs []v5rec) []byte {
	b := make([]byte, 24+48*len(recs))
	binary.BigEndian.PutUint16(b[0:], 5)
	binary.BigEndian.PutUint16(b[2:], uint16(len(recs)))
	binary.BigEndian.PutUint16(b[22:], sampling)
	for i, r := range recs {
		o := 24 + 48*i
		copy(b[o+4:o+8], r.dst.AsSlice())
		binary.BigEndian.PutUint32(b[o+20:], r.octets)
	}
	return b
}

func buildV9(domain uint32, sets ...[]byte) []byte {
	var body []byte
	for _, s := range sets {
		body = append(body, s...)
	}
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], 9)
	binary.BigEndian.PutUint16(h[2:], uint16(len(sets)))
	binary.BigEndian.PutUint32(h[16:], domain)
	return append(h, body...)
}

func buildIPFIX(domain uint32, sets ...[]byte) []byte {
	var body []byte
	for _, s := range sets {
		body = append(body, s...)
	}
	h := make([]byte, 16)
	binary.BigEndian.PutUint16(h[0:], 10)
	binary.BigEndian.PutUint16(h[2:], uint16(16+len(body)))
	binary.BigEndian.PutUint32(h[12:], domain)
	return append(h, body...)
}

func tmplSetV9(id uint16, fields [][2]uint16) []byte {
	return templateSet(0, id, fields, false)
}

func tmplSetIPFIX(id uint16, fields [][2]uint16) []byte {
	return templateSet(2, id, fields, false)
}

func templateSet(setID, id uint16, fields [][2]uint16, enterprise bool) []byte {
	_ = enterprise
	n := len(fields)
	length := 4 + 4 + n*4
	b := make([]byte, length)
	binary.BigEndian.PutUint16(b[0:], setID)
	binary.BigEndian.PutUint16(b[2:], uint16(length))
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], uint16(n))
	for i, f := range fields {
		binary.BigEndian.PutUint16(b[8+i*4:], f[0])
		binary.BigEndian.PutUint16(b[10+i*4:], f[1])
	}
	return b
}

func optionsSetV9(id uint16, scopeLen uint16, scopes, opts [][2]uint16) []byte {
	n := len(scopes) + len(opts)
	length := 4 + 6 + n*4
	b := make([]byte, length)
	binary.BigEndian.PutUint16(b[0:], 1)
	binary.BigEndian.PutUint16(b[2:], uint16(length))
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], scopeLen)
	binary.BigEndian.PutUint16(b[8:], uint16(len(opts)*4))
	off := 10
	for _, group := range [][][2]uint16{scopes, opts} {
		for _, f := range group {
			binary.BigEndian.PutUint16(b[off:], f[0])
			binary.BigEndian.PutUint16(b[off+2:], f[1])
			off += 4
		}
	}
	return b
}

func ipfixEnterpriseTemplate(id uint16) []byte {
	// set id 2, template id, field count 3:
	// enterprise type 100 len 4 pen 9, variable in-bytes, dst v4.
	fields := 4 + 4 + 8 + 4 + 4 // header of template record is separate
	// flowset header 4 + template header 4 + field1 8 + field2 4 + field3 4
	length := 4 + 4 + 8 + 4 + 4
	_ = fields
	b := make([]byte, length)
	binary.BigEndian.PutUint16(b[0:], 2)
	binary.BigEndian.PutUint16(b[2:], uint16(length))
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], 3)
	off := 8
	binary.BigEndian.PutUint16(b[off:], 100|0x8000)
	binary.BigEndian.PutUint16(b[off+2:], 4)
	binary.BigEndian.PutUint32(b[off+4:], 9)
	off += 8
	binary.BigEndian.PutUint16(b[off:], ieInBytes)
	binary.BigEndian.PutUint16(b[off+2:], 0xffff)
	off += 4
	binary.BigEndian.PutUint16(b[off:], ieDstV4)
	binary.BigEndian.PutUint16(b[off+2:], 4)
	return b
}

func dataSet(id uint16, parts ...[]byte) []byte {
	var recs []byte
	for _, p := range parts {
		recs = append(recs, p...)
	}
	length := 4 + len(recs)
	pad := (4 - length%4) % 4
	b := make([]byte, length+pad)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[4:], recs)
	return b
}

func putU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func v4only(a netip.Addr) []byte { return a.AsSlice() }

func v4rec(a netip.Addr, octets uint32) []byte {
	return append(append([]byte{}, a.AsSlice()...), putU32(octets)...)
}

func ip6rec(a netip.Addr, octets uint64) []byte {
	b := make([]byte, 16+8)
	copy(b, a.AsSlice())
	binary.BigEndian.PutUint64(b[16:], octets)
	return b
}

func buildSFlowV4(rate uint32, src, dst netip.Addr, ipLen uint32) []byte {
	rec := sampledV4Record(src, dst, ipLen)
	return sflowDatagram(flowSampleBody(rate, rec))
}

func buildSFlowV6(rate uint32, src, dst netip.Addr, ipLen uint32) []byte {
	body := make([]byte, 56)
	binary.BigEndian.PutUint32(body[0:], ipLen)
	binary.BigEndian.PutUint32(body[4:], 6)
	copy(body[8:24], src.AsSlice())
	copy(body[24:40], dst.AsSlice())
	rec := record(sflowSampledIPv6, body)
	return sflowDatagram(flowSampleBody(rate, rec))
}

func buildSFlowEthernet(dst netip.Addr, ipLen uint16) []byte {
	hdr := make([]byte, 14+20)
	hdr[12], hdr[13] = 0x08, 0x00
	hdr[14] = 0x45
	binary.BigEndian.PutUint16(hdr[16:], ipLen)
	copy(hdr[30:34], dst.AsSlice())
	raw := make([]byte, 16+len(hdr))
	binary.BigEndian.PutUint32(raw[0:], sflowHeaderEthernet)
	binary.BigEndian.PutUint32(raw[4:], uint32(len(hdr)))
	binary.BigEndian.PutUint32(raw[12:], uint32(len(hdr)))
	copy(raw[16:], hdr)
	return sflowDatagram(flowSampleBody(1, record(sflowRawHeader, raw)))
}

func buildSFlowPreferExplicit() []byte {
	// Header says 203.0.113.9; sampled IPv4 says 198.51.100.30. Explicit wins.
	hdr := make([]byte, 14+20)
	hdr[12], hdr[13] = 0x08, 0x00
	hdr[14] = 0x45
	binary.BigEndian.PutUint16(hdr[16:], 40)
	copy(hdr[30:34], netip.MustParseAddr("203.0.113.9").AsSlice())
	raw := make([]byte, 16+len(hdr))
	binary.BigEndian.PutUint32(raw[0:], sflowHeaderEthernet)
	binary.BigEndian.PutUint32(raw[4:], uint32(len(hdr)))
	binary.BigEndian.PutUint32(raw[12:], uint32(len(hdr)))
	copy(raw[16:], hdr)
	ip := sampledV4Record(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.30"), 40)
	return sflowDatagram(flowSampleBody(1, record(sflowRawHeader, raw), record(sflowSampledIPv4, ip[8:])))
}

func sampledV4Record(src, dst netip.Addr, ipLen uint32) []byte {
	body := make([]byte, 32)
	binary.BigEndian.PutUint32(body[0:], ipLen)
	binary.BigEndian.PutUint32(body[4:], 6)
	copy(body[8:12], src.AsSlice())
	copy(body[12:16], dst.AsSlice())
	return record(sflowSampledIPv4, body)
}

func record(format uint32, body []byte) []byte {
	b := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(b[0:], format)
	binary.BigEndian.PutUint32(b[4:], uint32(len(body)))
	copy(b[8:], body)
	return b
}

func flowSampleBody(rate uint32, records ...[]byte) []byte {
	var recs []byte
	for _, r := range records {
		recs = append(recs, r...)
	}
	body := make([]byte, 32+len(recs))
	binary.BigEndian.PutUint32(body[0:], 1) // seq
	binary.BigEndian.PutUint32(body[8:], rate)
	binary.BigEndian.PutUint32(body[28:], uint32(len(records)))
	copy(body[32:], recs)
	return sample(sflowFormatFlow, body)
}

func sample(format uint32, body []byte) []byte {
	b := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(b[0:], format)
	binary.BigEndian.PutUint32(b[4:], uint32(len(body)))
	copy(b[8:], body)
	return b
}

func sflowDatagram(samples ...[]byte) []byte {
	var body []byte
	for _, s := range samples {
		body = append(body, s...)
	}
	h := make([]byte, 28+len(body))
	binary.BigEndian.PutUint32(h[0:], 5)
	binary.BigEndian.PutUint32(h[4:], 1) // ipv4 agent
	copy(h[8:12], netip.MustParseAddr("192.0.2.10").AsSlice())
	binary.BigEndian.PutUint32(h[24:], uint32(len(samples)))
	copy(h[28:], body)
	return h
}

func TestStopWithoutStart(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:0\n")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestListenErrorIsNotClosed(t *testing.T) {
	if isClosed(errors.New("nope")) {
		t.Fatal("unrelated error looked closed")
	}
}
