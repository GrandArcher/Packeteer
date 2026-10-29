package ipfix

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(t *testing.T, y string) (plugin.Exporter, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.Exporters.New(TypeName, c, plugin.Env{Name: "i"})
}

func TestConfigValidation(t *testing.T) {
	x, err := build(t, "address: collector.example.net:2055\n")
	if err != nil {
		t.Fatal(err)
	}
	if s := x.Streams(); len(s) != 1 || s[0] != plugin.StreamFlows {
		t.Fatalf("streams = %v, IPFIX carries flows only", s)
	}
	for name, y := range map[string]string{
		"no address":       "observation_domain: 3\n",
		"no port":          "address: collector.example.net\n",
		"bad port":         "address: \"collector.example.net:99999\"\n",
		"no host":          "address: \":2055\"\n",
		"negative refresh": "address: a:2055\ntemplate_interval: -1m\n",
		"streams":          "address: a:2055\nstreams: [events]\n",
	} {
		if _, err := build(t, y); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// parsed is the minimum an IPFIX collector reads back: the header, the
// templates in the message, and the data records decoded with them.
type parsed struct {
	domain, seq uint32
	templates   map[uint16][]field
	records     map[uint16][]map[uint16][]byte
}

func parse(t *testing.T, b []byte, known map[uint16][]field) parsed {
	t.Helper()
	if binary.BigEndian.Uint16(b) != 10 || int(binary.BigEndian.Uint16(b[2:])) != len(b) {
		t.Fatalf("bad header: % x (len %d)", b[:16], len(b))
	}
	p := parsed{seq: binary.BigEndian.Uint32(b[8:]), domain: binary.BigEndian.Uint32(b[12:]),
		templates: map[uint16][]field{}, records: map[uint16][]map[uint16][]byte{}}
	for id, f := range known {
		p.templates[id] = f
	}
	body := b[16:]
	for len(body) > 0 {
		id, n := binary.BigEndian.Uint16(body), int(binary.BigEndian.Uint16(body[2:]))
		set := body[4:n]
		body = body[n:]
		if id == 2 {
			for len(set) > 0 {
				tid, cnt := binary.BigEndian.Uint16(set), int(binary.BigEndian.Uint16(set[2:]))
				set = set[4:]
				var fs []field
				for i := 0; i < cnt; i++ {
					fs = append(fs, field{binary.BigEndian.Uint16(set), binary.BigEndian.Uint16(set[2:])})
					set = set[4:]
				}
				p.templates[tid] = fs
			}
			continue
		}
		fs, ok := p.templates[id]
		if !ok {
			t.Fatalf("data set %d before its template", id)
		}
		for len(set) > 0 {
			rec := map[uint16][]byte{}
			for _, f := range fs {
				l := int(f.length)
				if f.length == 0xffff {
					l = int(set[0])
					set = set[1:]
				}
				rec[f.ie] = set[:l]
				set = set[l:]
			}
			p.records[id] = append(p.records[id], rec)
		}
	}
	return p
}

func listen(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func read(t *testing.T, c *net.UDPConn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func start(t *testing.T, c *net.UDPConn, extra string) *Exporter {
	t.Helper()
	x, err := build(t, "address: "+c.LocalAddr().String()+"\nobservation_domain: 7\n"+extra)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Stop(context.Background()) })
	return x.(*Exporter)
}

func flow(dst string, bytes uint64, provider, id string) plugin.ExportRecord {
	d := netip.MustParseAddr(dst)
	pfx := netip.PrefixFrom(d, 24)
	src := netip.MustParseAddr("203.0.113.9")
	if d.Is6() {
		pfx = netip.PrefixFrom(d, 48)
		src = netip.MustParseAddr("2001:db8:ffff::9")
	}
	return plugin.ExportRecord{Stream: plugin.StreamFlows, Flow: &plugin.FlowRecord{
		Time: time.UnixMilli(1790000000123), Src: src, Dst: d, Proto: 6, Bytes: bytes,
		Prefix: pfx.Masked().String(), Provider: provider, ImprovementID: id}}
}

func TestExportEncodesTaggedFlows(t *testing.T) {
	c := listen(t)
	x := start(t, c, "")
	x.now = func() time.Time { return time.Unix(1790000000, 0) }
	err := x.Export(context.Background(), []plugin.ExportRecord{
		flow("192.0.2.10", 1500, "transit-b", "00000000000000ab"),
		flow("2001:db8::5", 900, "", ""),
		flow("192.0.2.77", 40, "transit-a", ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	p := parse(t, read(t, c), nil)
	if p.domain != 7 || p.seq != 0 {
		t.Fatalf("domain %d seq %d", p.domain, p.seq)
	}
	if len(p.templates[templateV4]) != len(fieldsV4) || len(p.templates[templateV6]) != len(fieldsV6) {
		t.Fatalf("templates = %v", p.templates)
	}
	v4, v6 := p.records[templateV4], p.records[templateV6]
	if len(v4) != 2 || len(v6) != 1 {
		t.Fatalf("records v4=%d v6=%d", len(v4), len(v6))
	}
	r := v4[0]
	if netip.AddrFrom4([4]byte(r[12])).String() != "192.0.2.10" || netip.AddrFrom4([4]byte(r[8])).String() != "203.0.113.9" {
		t.Fatalf("addresses = % x / % x", r[8], r[12])
	}
	if r[4][0] != 6 || binary.BigEndian.Uint64(r[1]) != 1500 || r[13][0] != 24 {
		t.Fatalf("proto/bytes/prefix length = %v %d %d", r[4], binary.BigEndian.Uint64(r[1]), r[13][0])
	}
	if binary.BigEndian.Uint64(r[153]) != 1790000000123 {
		t.Fatalf("flowEndMilliseconds = %d", binary.BigEndian.Uint64(r[153]))
	}
	if string(r[82]) != "transit-b" || binary.BigEndian.Uint64(r[148]) != 0xab {
		t.Fatalf("tag = %q id %#x", r[82], binary.BigEndian.Uint64(r[148]))
	}
	if string(v4[1][82]) != "transit-a" || binary.BigEndian.Uint64(v4[1][148]) != 0 {
		t.Fatalf("native flow must carry its provider and ID 0: %q %d", v4[1][82], binary.BigEndian.Uint64(v4[1][148]))
	}
	if netip.AddrFrom16([16]byte(v6[0][28])).String() != "2001:db8::5" || v6[0][30][0] != 48 || len(v6[0][82]) != 0 {
		t.Fatalf("v6 record = %v", v6[0])
	}
}

func TestSequenceCountsDataRecordsAndTemplatesRepeat(t *testing.T) {
	c := listen(t)
	x := start(t, c, "template_interval: 1h\n")
	clock := time.Unix(1790000000, 0)
	x.now = func() time.Time { return clock }
	send := func(n int) {
		var b []plugin.ExportRecord
		for i := 0; i < n; i++ {
			b = append(b, flow("192.0.2.10", 1, "transit-b", ""))
		}
		if err := x.Export(context.Background(), b); err != nil {
			t.Fatal(err)
		}
	}
	send(2)
	first := parse(t, read(t, c), nil)
	send(1)
	raw := read(t, c)
	if binary.BigEndian.Uint16(raw[16:]) == 2 {
		t.Fatal("templates must not be repeated before template_interval")
	}
	second := parse(t, raw, first.templates)
	if first.seq != 0 || second.seq != 2 {
		t.Fatalf("sequence = %d then %d, want 0 then 2", first.seq, second.seq)
	}
	clock = clock.Add(2 * time.Hour)
	send(1)
	third := parse(t, read(t, c), nil)
	if len(third.templates) != 2 || third.seq != 3 {
		t.Fatalf("after template_interval: templates %d seq %d", len(third.templates), third.seq)
	}
}

func TestLargeBatchSplitsIntoMessagesUnderMTU(t *testing.T) {
	c := listen(t)
	x := start(t, c, "")
	var b []plugin.ExportRecord
	for i := 0; i < 100; i++ {
		b = append(b, flow("192.0.2.10", uint64(i), "transit-b", "00000000000000ab"))
	}
	if err := x.Export(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	known := map[uint16][]field{}
	total, msgs := 0, 0
	for total < 100 {
		raw := read(t, c)
		if len(raw) > maxMessage {
			t.Fatalf("message of %d bytes", len(raw))
		}
		p := parse(t, raw, known)
		for id, f := range p.templates {
			known[id] = f
		}
		total += len(p.records[templateV4])
		msgs++
	}
	if msgs < 2 || total != 100 {
		t.Fatalf("%d records in %d messages", total, msgs)
	}
}

func TestProviderNameIsTruncatedAndExportBeforeStartFails(t *testing.T) {
	x, err := build(t, "address: 127.0.0.1:2055\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Export(context.Background(), []plugin.ExportRecord{flow("192.0.2.10", 1, "p", "")}); err == nil {
		t.Fatal("export before Start must fail")
	}
	rec := record(*flow("192.0.2.10", 1, strings.Repeat("x", 400), "").Flow, false)
	if rec[len(rec)-255] != 254 {
		t.Fatalf("provider length byte = %d, want 254", rec[len(rec)-255])
	}
}
