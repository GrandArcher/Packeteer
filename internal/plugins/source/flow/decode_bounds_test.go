package flow

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"testing"
)

var boundsExporter = netip.MustParseAddr("192.0.2.8")

// hugeTemplateSet is an 8-byte set (10 for options) whose record claims
// 65535 fields and carries none.
func hugeTemplateSet(setID uint16) []byte {
	b := []byte{0, 0, 0, 0, 1, 0, 0xff, 0xff}
	if setID == 3 {
		b = append(b, 0, 1)
	}
	binary.BigEndian.PutUint16(b[0:], setID)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

// withdrawSet is an IPFIX template withdrawal; id 2 withdraws every template
// of the domain.
func withdrawSet(id uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:], 2)
	binary.BigEndian.PutUint16(b[2:], 8)
	binary.BigEndian.PutUint16(b[4:], id)
	return b
}

// sampledTemplate and sampledData make one IPFIX record that carries its own
// sampling interval of 100.
func sampledTemplate() []byte {
	return tmplSetIPFIX(256, [][2]uint16{{ieSamplingInterval, 4}, {ieInBytes, 4}, {ieDstV4, 4}})
}

func sampledData() []byte {
	return dataSet(256, putU32(100), putU32(1000), v4only(netip.MustParseAddr("198.51.100.7")))
}

// checkDecoder asserts the bookkeeping that bounds decoder memory.
func checkDecoder(t *testing.T, d *decoder) {
	t.Helper()
	n := 0
	for k, ds := range d.doms {
		if len(ds.tmpl) == 0 {
			t.Fatalf("domain %+v kept with no templates (rate %d)", k, ds.rate)
		}
		n += len(ds.tmpl)
	}
	if n != d.ntmpl || n > maxTemplates {
		t.Fatalf("templates counted %d, held %d, cap %d", d.ntmpl, n, maxTemplates)
	}
}

func bytesPerDecode(runs int, decode func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < runs; i++ {
		decode()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / uint64(runs)
}

// FAB-02: before the length check, each of these sets allocated about 393 KB
// and the walk went on to the next one.
func TestHugeFieldCountAllocatesLittle(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  []byte
		dec  func(*decoder, netip.Addr, []byte) ([]observation, error)
	}{
		{"ipfix template", repeatSets(buildIPFIX, hugeTemplateSet(2)), (*decoder).decodeIPFIX},
		{"ipfix options", repeatSets(buildIPFIX, hugeTemplateSet(3)), (*decoder).decodeIPFIX},
		{"v9 template", repeatSets(buildV9, hugeTemplateSet(0)), (*decoder).decodeV9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &decoder{}
			var err error
			per := bytesPerDecode(50, func() {
				var obs []observation
				obs, err = tc.dec(d, boundsExporter, tc.pkt)
				putObs(obs)
			})
			if err == nil {
				t.Fatal("short template accepted")
			}
			if per > 16<<10 {
				t.Fatalf("one decode allocated %d bytes", per)
			}
			if len(d.doms) != 0 {
				t.Fatalf("templates learned: %d", len(d.doms))
			}
		})
	}
}

func repeatSets(build func(uint32, ...[]byte) []byte, set []byte) []byte {
	sets := make([][]byte, 1000)
	for i := range sets {
		sets[i] = set
	}
	return build(1, sets...)
}

func TestTemplateErrorEndsDatagram(t *testing.T) {
	valid := tmplSetIPFIX(256, [][2]uint16{{ieInBytes, 4}, {ieDstV4, 4}})
	data := dataSet(256, putU32(500), v4only(netip.MustParseAddr("198.51.100.7")))
	d := &decoder{}
	obs, err := d.decodeIPFIX(boundsExporter, buildIPFIX(1, hugeTemplateSet(2), valid, data))
	if err == nil || len(obs) != 0 || len(d.doms) != 0 {
		t.Fatalf("sets after a bad template were read: err %v, obs %+v, domains %d", err, obs, len(d.doms))
	}
	// Data for an unknown template is not a template error: the walk goes on.
	obs, err = d.decodeIPFIX(boundsExporter, buildIPFIX(1, dataSet(300, putU32(1)), valid, data))
	if err == nil || len(obs) != 1 || obs[0].bytes != 500 {
		t.Fatalf("err %v, obs %+v", err, obs)
	}
	v9 := &decoder{}
	obs, err = v9.decodeV9(boundsExporter, buildV9(1, hugeTemplateSet(0), tmplSetV9(256, [][2]uint16{{ieInBytes, 4}, {ieDstV4, 4}}), data))
	if err == nil || len(obs) != 0 || len(v9.doms) != 0 {
		t.Fatalf("v9 sets after a bad template were read: err %v, obs %+v, domains %d", err, obs, len(v9.doms))
	}
}

// FAB-07: a domain that learned a sampling rate and then withdrew its
// templates leaves nothing behind.
func TestWithdrawnDomainsDropRates(t *testing.T) {
	d := &decoder{}
	for dom := uint32(0); dom < 3*maxTemplates; dom++ {
		obs, err := d.decodeIPFIX(boundsExporter, buildIPFIX(dom, sampledTemplate(), sampledData()))
		if err != nil || len(obs) != 1 || obs[0].bytes != 100*1000 {
			t.Fatalf("domain %d: err %v, obs %+v", dom, err, obs)
		}
		if r := d.doms[domainKey{boundsExporter, 10, dom}].rate; r != 100 {
			t.Fatalf("domain %d: rate %d", dom, r)
		}
		// Even domains withdraw every template, odd ones the one id.
		w := uint16(2)
		if dom%2 == 1 {
			w = 256
		}
		if _, err := d.decodeIPFIX(boundsExporter, buildIPFIX(dom, withdrawSet(w))); err != nil {
			t.Fatal(err)
		}
	}
	checkDecoder(t, d)
	if len(d.doms) != 0 || d.ntmpl != 0 {
		t.Fatalf("withdrawn domains kept: %d domains, %d templates", len(d.doms), d.ntmpl)
	}
	// The rate went with the templates: a new template without the
	// interval counts octets unscaled.
	plain := tmplSetIPFIX(256, [][2]uint16{{ieInBytes, 4}, {ieDstV4, 4}})
	obs, err := d.decodeIPFIX(boundsExporter, buildIPFIX(1, plain, dataSet(256, putU32(1000), v4only(netip.MustParseAddr("198.51.100.7")))))
	if err != nil || len(obs) != 1 || obs[0].bytes != 1000 || obs[0].sampled {
		t.Fatalf("stale rate applied: err %v, obs %+v", err, obs)
	}
}

func TestDomainsCappedByTemplateTable(t *testing.T) {
	d := &decoder{}
	full := 0
	for dom := uint32(0); dom < 2*maxTemplates; dom++ {
		if _, err := d.decodeIPFIX(boundsExporter, buildIPFIX(dom, sampledTemplate(), sampledData())); err != nil {
			full++
		}
	}
	checkDecoder(t, d)
	if len(d.doms) != maxTemplates || full != maxTemplates {
		t.Fatalf("domains %d, refused %d, cap %d", len(d.doms), full, maxTemplates)
	}
	// A full table still takes a refresh of a template it already holds.
	refresh := tmplSetIPFIX(256, [][2]uint16{{ieInBytes, 4}, {ieDstV4, 4}})
	if _, err := d.decodeIPFIX(boundsExporter, buildIPFIX(0, refresh)); err != nil {
		t.Fatalf("refresh refused: %v", err)
	}
	if got := len(d.doms[domainKey{boundsExporter, 10, 0}].tmpl[256].fields); got != 2 {
		t.Fatalf("refresh not stored: %d fields", got)
	}
	checkDecoder(t, d)
}
