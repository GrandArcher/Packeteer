package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/flow"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var docSpace = append(append([]netip.Prefix{}, docV4...), docV6)

func inDocSpace(p netip.Prefix) bool {
	for _, d := range docSpace {
		if d.Bits() <= p.Bits() && d.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func TestTableIsDocumentationSpaceAndUnique(t *testing.T) {
	for _, n := range []int{v4Count + 2, 20000, 70000} {
		tbl := newTable(n)
		seen := map[netip.Prefix]bool{}
		for i := range n {
			p := tbl.prefix(i)
			if !p.IsValid() || p != p.Masked() {
				t.Fatalf("n=%d entry %d: %v not a masked prefix", n, i, p)
			}
			if !inDocSpace(p) {
				t.Fatalf("n=%d entry %d: %v outside documentation space", n, i, p)
			}
			if seen[p] {
				t.Fatalf("n=%d entry %d: %v repeated", n, i, p)
			}
			seen[p] = true
			if h := tbl.host(i); !p.Contains(h) || !h.IsGlobalUnicast() {
				t.Fatalf("entry %d: host %v not a usable address in %v", i, h, p)
			}
			for _, a := range tbl.asPath(i) {
				if !(a >= 64496 && a <= 64511) && !(a >= 65536 && a <= 65551) {
					t.Fatalf("entry %d: AS %d is not a documentation ASN", i, a)
				}
			}
		}
	}
}

func TestTableFullSize(t *testing.T) {
	tbl := newTable(1250000)
	if tbl.v6Bits != 53 {
		t.Fatalf("v6 length /%d, want /53", tbl.v6Bits)
	}
	last := tbl.prefix(tbl.n - 1)
	if !docV6.Contains(last.Addr()) || last.Bits() != 53 {
		t.Fatalf("last entry %v", last)
	}
	if tbl.prefix(v4Count) == tbl.prefix(v4Count+1) {
		t.Fatal("IPv6 entries collide")
	}
	if got := tbl.prefix(0); got != netip.MustParsePrefix("192.0.2.0/24") {
		t.Fatalf("first entry %v", got)
	}
	if got := tbl.prefix(510); got != netip.MustParsePrefix("192.0.2.255/32") {
		t.Fatalf("entry 510 %v", got)
	}
}

// The exporter's IPFIX decodes in Packeteer's own flow source, and the hot
// set becomes its busiest targets.
func TestExporterFeedsFlowSource(t *testing.T) {
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().String()
	l.Close()
	c, err := plugin.ConfigFromYAML("listen: " + addr + "\nwindow: 1m\ntop_n: 10\n")
	if err != nil {
		t.Fatal(err)
	}
	src, err := plugin.Sources.New(flow.TypeName, c, plugin.Env{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	tbl := newTable(v4Count + 100)
	src.(*flow.Source).SetPrefixLookup(func(a netip.Addr) (netip.Prefix, bool) {
		for i := range tbl.n {
			if p := tbl.prefix(i); p.Contains(a) && (p.Bits() == 24 || a.Is6()) {
				return p, true
			}
		}
		return netip.Prefix{}, false
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := src.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer src.Stop(context.Background())

	exp := newExporter(tbl, tbl.n)
	go func() { _ = exp.run(ctx, addr, 20000) }()
	deadline := time.Now().Add(10 * time.Second)
	var got []plugin.Target
	for time.Now().Before(deadline) {
		got, _ = src.Targets(ctx)
		v4, v6 := false, false
		for _, tg := range got {
			v4 = v4 || tg.Prefix.Addr().Is4()
			v6 = v6 || tg.Prefix.Addr().Is6()
		}
		if v4 && v6 && len(got) == 10 {
			for _, tg := range got {
				if !inDocSpace(tg.Prefix) {
					t.Fatalf("target %v outside documentation space", tg.Prefix)
				}
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("flow source targets after 10s: %v (records sent %d)", got, exp.sent.Load())
}

func TestDataMessagesStayOneFamilyAndFit(t *testing.T) {
	e := newExporter(newTable(v4Count+5000), 3000)
	now := time.Now()
	total := 0
	for range 200 {
		b, n := e.data(now, 1000)
		if len(b) > maxPayload || n == 0 {
			t.Fatalf("message of %d bytes with %d records", len(b), n)
		}
		id := int(b[16])<<8 | int(b[17])
		size := recV4
		if id == tmplV6 {
			size = recV6
		}
		if want := 20 + n*size; len(b) != want {
			t.Fatalf("message %d bytes, want %d for %d records of template %d", len(b), want, n, id)
		}
		total += n
	}
	if e.seq != uint32(total) {
		t.Fatalf("sequence %d, want %d", e.seq, total)
	}
}

func TestParseProc(t *testing.T) {
	p, err := parseStatus("Name:\tpacketeer\nVmHWM:\t  204800 kB\nVmRSS:\t  102400 kB\nThreads:\t17\n")
	if err != nil || p.RSS != 100<<20 || p.HWM != 200<<20 || p.Threads != 17 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := parseStatus("Name: x\n"); err == nil {
		t.Fatal("missing fields accepted")
	}
	cpu, err := parseStatCPU("42 (pack eter) S 1 42 42 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 17 0 1 0 0")
	if err != nil || cpu != 3 {
		t.Fatalf("cpu %v %v", cpu, err)
	}
	u, err := parseSNMP("Ip: a b\nIp: 1 2\nUdp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\nUdp: 1000 2 7 900 5 0\n")
	if err != nil || u.In != 1000 || u.RcvbufErrors != 5 {
		t.Fatalf("%+v %v", u, err)
	}
	m, err := parseMetrics(strings.NewReader("# HELP x\npacketeer_ready 1\npacketeer_rib_prefixes 1.25e+06\npacketeer_bgp_session_up{peer=\"127.0.0.1\"} 1\n"))
	if err != nil || !m.Ready || !m.SessionUp || m.RIBPrefixes != 1250000 {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := parseMetrics(strings.NewReader("packeteer_ready 1\n")); err == nil {
		t.Fatal("metrics without rib size accepted")
	}
}

func TestBudgetFileProfilesAndGeneratedConfig(t *testing.T) {
	for _, name := range []string{"smoke", "pr", "soak", "routes3m"} {
		p, err := loadProfile("budgets.yaml", name)
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case "smoke":
		case "routes3m":
			// Opt-in 3M table (#103). Report only: no measured budgets yet,
			// and this name must not become what CI's load job runs.
			if p.Prefixes != 3000000 {
				t.Fatalf("routes3m prefixes %d, want 3000000", p.Prefixes)
			}
			if p.Budgets != (Budgets{}) {
				t.Fatalf("routes3m budgets must stay unset until a measured run: %+v", p.Budgets)
			}
			tbl := newTable(p.Prefixes)
			if !tbl.valid() || tbl.v6Bits != 54 {
				t.Fatalf("routes3m table %+v, want a valid /54 IPv6 half", tbl)
			}
			last := tbl.prefix(p.Prefixes - 1)
			if !docV6.Contains(last.Addr()) || last.Bits() != 54 {
				t.Fatalf("routes3m last prefix %v", last)
			}
		case "pr":
			if p.Prefixes != 1250000 {
				t.Fatalf("pr prefixes changed: %d", p.Prefixes)
			}
			fallthrough
		default:
			if p.Prefixes < 1000000 {
				t.Fatalf("%s: %d prefixes is not full-table sized", name, p.Prefixes)
			}
			if p.Budgets.RSSPeakMB == 0 || p.Budgets.LearnSeconds == 0 || p.Budgets.RSSGrowthMB == 0 ||
				p.Budgets.CPUAvgCores == 0 || p.Budgets.UDPDropPct == 0 || p.Budgets.ShutdownSeconds == 0 {
				t.Fatalf("%s: a core budget is unset: %+v", name, p.Budgets)
			}
		}
		cfg, err := config.Parse([]byte(packeteerConfig(p, ports{BGP: 11179, Flow: 12055, HTTP: 18081}, "/var/lib/packeteer")))
		if err != nil {
			t.Fatalf("%s: generated config: %v", name, err)
		}
		if cfg.Mode != config.ModeObserve || len(cfg.Allowlist.Prefixes) != 0 {
			t.Fatalf("%s: generated config must be observe with an empty allowlist", name)
		}
	}
	if _, err := loadProfile("budgets.yaml", "nope"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	// The load job and the weekly soak must keep their own profiles.
	for _, path := range []string{"../../.github/workflows/ci.yml", "../../.github/workflows/soak.yml"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "routes3m") {
			t.Fatalf("%s names the opt-in 3M profile", path)
		}
	}
	ci, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ci), "bash lab/soak.sh packeteer:ci pr\n") {
		t.Fatal("load job must keep running the pr profile")
	}
}

func TestReportFailsOverBudget(t *testing.T) {
	b := Budgets{RSSPeakMB: 100, MinMeasured: 10}
	r := Result{Profile: "x", RSSPeakMB: 90, Measured: 20, Failures: []string{}}
	if text, ok := report(r, b); !ok || !strings.Contains(text, "| peak RSS | 90 MiB | ≤ 100 MiB | ok |") {
		t.Fatalf("ok=%v\n%s", ok, text)
	}
	r.RSSPeakMB = 120
	if text, ok := report(r, b); ok || !strings.Contains(text, "**OVER**") {
		t.Fatalf("over budget passed:\n%s", text)
	}
	r.RSSPeakMB, r.Measured = 90, 5
	if _, ok := report(r, b); ok {
		t.Fatal("minimum not enforced")
	}
	r.Measured = 20
	r.Failures = []string{"observe mode sent 1 routes to the router"}
	if text, ok := report(r, b); ok || !strings.Contains(text, "FAIL") {
		t.Fatal("invariant failure passed")
	}
}

func TestGrowthUsesMedians(t *testing.T) {
	// One spike in warmup and one at the end do not set either level.
	warm := []float64{100, 500, 100, 101, 100}
	post := []float64{102, 103, 104, 105, 110, 110, 111, 900}
	base, end := growth(warm, post)
	if base != 100 || end != 110 {
		t.Fatalf("base %v end %v", base, end)
	}
	if percentile([]float64{1, 2, 3, 4, 100}, 99) != 100 || percentile(nil, 99) != 0 {
		t.Fatal("percentile")
	}
	b, e := growth(nil, nil)
	if b != 0 || e != 0 {
		t.Fatalf("empty: %v %v", b, e)
	}
	// No warmup samples: the first half is the baseline.
	b, e = growth(nil, []float64{10, 12, 11, 40})
	if b != 10 || e != 11 {
		t.Fatalf("no warmup: base %v end %v", b, e)
	}
}

// repeatN is n copies of v, for RSS series in the growth tests.
func repeatN(v float64, n int) []float64 {
	s := make([]float64, n)
	for i := range s {
		s[i] = v
	}
	return s
}

// TestGrowthIgnoresScavengerValley is the shape of Actions run
// 36902639588. Warmup sits near 4620 (one early spike). After warmup,
// RSS dips to 4480 for the first half and refills to 4820. The old
// tenth-of-the-window medians read the dip against the refill (340 MiB).
// The warmup median against the second half is 200, inside the pr budget.
// A second half that stays 400 above warmup is still over that budget.
func TestGrowthIgnoresScavengerValley(t *testing.T) {
	p, err := loadProfile("budgets.yaml", "pr")
	if err != nil {
		t.Fatal(err)
	}
	if p.Budgets.RSSPeakMB != 6144 || p.Budgets.RSSGrowthMB != 256 {
		t.Fatalf("pr peak or growth budget changed: peak %v growth %v", p.Budgets.RSSPeakMB, p.Budgets.RSSGrowthMB)
	}
	soak, err := loadProfile("budgets.yaml", "soak")
	if err != nil {
		t.Fatal(err)
	}
	if soak.Budgets.RSSPeakMB != 6656 {
		t.Fatalf("soak peak budget changed: %v", soak.Budgets.RSSPeakMB)
	}
	warm := append([]float64{5000}, repeatN(4620, 29)...)
	valley := append(repeatN(4480, 40), repeatN(4820, 40)...)
	base, end := growth(warm, valley)
	got := end - base
	if base != 4620 || end != 4820 || got > p.Budgets.RSSGrowthMB {
		t.Fatalf("valley refill: base %v end %v growth %v budget %v", base, end, got, p.Budgets.RSSGrowthMB)
	}
	// Same valley, but the second half never comes back down.
	leak := append(repeatN(4480, 40), repeatN(5020, 40)...)
	base, end = growth(warm, leak)
	if end-base <= p.Budgets.RSSGrowthMB {
		t.Fatalf("leak of %v MiB passed a %v budget", end-base, p.Budgets.RSSGrowthMB)
	}
}
