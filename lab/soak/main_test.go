package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/flow"
	"github.com/GrandArcher/Packeteer/lab/soak/shape"
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
			if i%tbl.setLen == 0 {
				checkDocASNs(t, i, tbl.attrs(i))
			}
		}
	}
}

func isDocASN(a uint32) bool { return a >= 64496 && a <= 64511 || a >= 65536 && a <= 65551 }

func checkDocASNs(t *testing.T, i int, a attrSet) {
	t.Helper()
	for _, as := range a.path {
		if !isDocASN(as) {
			t.Fatalf("entry %d: path AS %d is not a documentation ASN", i, as)
		}
	}
	for _, c := range a.comms {
		if !isDocASN(c >> 16) {
			t.Fatalf("entry %d: community %d:%d is not a documentation ASN", i, c>>16, c&0xffff)
		}
	}
	for _, l := range a.large {
		if !isDocASN(l[0]) {
			t.Fatalf("entry %d: large community AS %d is not a documentation ASN", i, l[0])
		}
	}
}

func TestTableFullSize(t *testing.T) {
	tbl := newTable(1250000)
	if !tbl.valid() {
		t.Fatal("1.25M table is not valid")
	}
	last := tbl.prefix(tbl.n - 1)
	if !docV6.Contains(last.Addr()) {
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
	if m.ProbePrefixCommits != 0 || m.FlowPrefixesTracked != 0 {
		t.Fatalf("missing optional gauges must stay zero: %+v", m)
	}
	m, err = parseMetrics(strings.NewReader("packeteer_ready 1\npacketeer_rib_prefixes 10\npacketeer_probe_prefix_commits 12\npacketeer_flow_prefixes_tracked 50000\npacketeer_go_mutex_wait_seconds_total 3.5\n"))
	if err != nil || m.ProbePrefixCommits != 12 || m.FlowPrefixesTracked != 50000 || m.MutexWaitSeconds != 3.5 {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := parseMetrics(strings.NewReader("packeteer_ready 1\n")); err == nil {
		t.Fatal("metrics without rib size accepted")
	}
}

func TestActivePerHourScalesAfterWarmup(t *testing.T) {
	var p probePace
	p.sample(10*time.Second, time.Minute, 100, 1)
	p.sample(time.Minute, time.Minute, 400, 1000)
	p.sample(2*time.Minute, time.Minute, 1000, 50000)
	if got := p.perHour(120, 60); got != 36000 {
		t.Fatalf("per hour %v, want 36000", got)
	}
	if p.passive != 50000 {
		t.Fatalf("passive %v", p.passive)
	}
	back := probePace{warm: 100, end: 10, warmSet: true}
	if got := back.perHour(120, 60); got != 0 {
		t.Fatalf("backwards counter %v", got)
	}
	unset := probePace{end: 100}
	if got := unset.perHour(120, 60); got != 6000 {
		t.Fatalf("unset warmup %v, want 6000", got)
	}
	if got := (probePace{end: 10}).perHour(0.5, 0); got != 0 {
		t.Fatalf("short soak %v", got)
	}
}

func TestBudgetFileProfilesAndGeneratedConfig(t *testing.T) {
	for _, name := range []string{"smoke", "pr", "soak", "routes3m", "large", "rate"} {
		p, err := loadProfile("budgets.yaml", name)
		if err != nil {
			t.Fatal(err)
		}
		cfgText := packeteerConfig(p, ports{BGP: 11179, Flow: 12055, HTTP: 18081}, "/var/lib/packeteer")
		switch name {
		case "smoke":
			if p.Budgets != (Budgets{}) {
				t.Fatalf("smoke budgets must stay unset: %+v", p.Budgets)
			}
			if !strings.Contains(cfgText, "rate_limit_pps: 100000\n") {
				t.Fatal("smoke keeps the load-test packet rate")
			}
		case "rate":
			// Opt-in real packet rate (#125). Not a CI profile.
			if p.Prefixes != 20000 || p.StaticTargets != 375 || p.RateLimitPPS != 100 {
				t.Fatalf("rate profile %+v", p)
			}
			if p.Budgets != (Budgets{}) {
				t.Fatalf("rate budgets must stay unset: %+v", p.Budgets)
			}
			if !strings.Contains(cfgText, "rate_limit_pps: 100\n") {
				t.Fatal("rate profile must generate 100 pps")
			}
		case "routes3m":
			// Opt-in 3M table (#103) with the pr per-million budgets (#217).
			// This name must not become what CI's load job runs.
			if p.Prefixes != 3000000 {
				t.Fatalf("routes3m prefixes %d, want 3000000", p.Prefixes)
			}
			wantBudget(t, name, "peak", p.Budgets.RSSPeakMB, 3*4915.2)
			tbl := newTable(p.Prefixes)
			if !tbl.valid() {
				t.Fatalf("routes3m table %+v, want a valid table", tbl)
			}
			last := tbl.prefix(p.Prefixes - 1)
			if !docV6.Contains(last.Addr()) {
				t.Fatalf("routes3m last prefix %v", last)
			}
		case "large":
			// About 5M paths (#217): the pr per-million budgets times 5.
			if p.Prefixes != 5000000 {
				t.Fatalf("large prefixes %d, want 5000000", p.Prefixes)
			}
			tbl := newTable(p.Prefixes)
			last := tbl.prefix(p.Prefixes - 1)
			if !tbl.valid() || !docV6.Contains(last.Addr()) {
				t.Fatalf("large table %+v, last prefix %v, want a valid table inside the documentation block", tbl, last)
			}
			wantBudget(t, name, "learn", p.Budgets.LearnSeconds, 360)
			wantBudget(t, name, "peak", p.Budgets.RSSPeakMB, 24576)
			wantBudget(t, name, "growth", p.Budgets.RSSGrowthMB, 1536)
			wantBudget(t, name, "slope", p.Budgets.RSSSlopeMB, 768)
		case "pr":
			if p.Prefixes != 1250000 {
				t.Fatalf("pr prefixes changed: %d", p.Prefixes)
			}
			// The scaled budgets equal the flat ones they replaced (#217).
			wantBudget(t, name, "learn", p.Budgets.LearnSeconds, 90)
			wantBudget(t, name, "peak", p.Budgets.RSSPeakMB, 6144)
			wantBudget(t, name, "growth", p.Budgets.RSSGrowthMB, 384)
			wantBudget(t, name, "slope", p.Budgets.RSSSlopeMB, 192)
			if p.Budgets.MinActivePerHour != 180000 || p.Budgets.MinPassiveTracked != 50000 {
				t.Fatalf("pr probe budgets %+v", p.Budgets)
			}
			if p.RateLimitPPS != 0 || !strings.Contains(cfgText, "rate_limit_pps: 100000\n") {
				t.Fatal("pr must keep rate_limit_pps 100000")
			}
		}
		if name == "pr" || name == "soak" || name == "large" {
			if p.Prefixes < 1000000 {
				t.Fatalf("%s: %d prefixes is not full-table sized", name, p.Prefixes)
			}
			if p.Budgets.RSSSlopeMB == 0 {
				t.Fatalf("%s: the leak-slope budget is unset", name)
			}
			if p.Budgets.RSSPeakMB == 0 || p.Budgets.LearnSeconds == 0 || p.Budgets.RSSGrowthMB == 0 ||
				p.Budgets.CPUAvgCores == 0 || p.Budgets.UDPDropPct == 0 || p.Budgets.ShutdownSeconds == 0 ||
				p.Budgets.MinActivePerHour != 180000 || p.Budgets.MinPassiveTracked != 50000 {
				t.Fatalf("%s: a core budget is unset: %+v", name, p.Budgets)
			}
		}
		cfg, err := config.Parse([]byte(cfgText))
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
	// The load job and the weekly soak must keep their own profiles. The
	// large table (#217) has its own scheduled workflow and never runs on
	// a pull request.
	large, err := os.ReadFile("../../.github/workflows/load-large.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(large), "lab/soak.sh packeteer:large large") || strings.Contains(string(large), "pull_request") ||
		!strings.Contains(string(large), "vars.LARGE_RUNNER") {
		t.Fatal("load-large.yml must run the large profile on a configured runner and not on pull requests")
	}
	for _, path := range []string{"../../.github/workflows/ci.yml", "../../.github/workflows/soak.yml"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "routes3m") {
			t.Fatalf("%s names the opt-in 3M profile", path)
		}
		if strings.Contains(string(b), "packeteer:large") {
			t.Fatalf("%s names the large-table profile", path)
		}
		if strings.Contains(string(b), "packeteer:ci rate") || strings.Contains(string(b), "packeteer:soak rate") {
			t.Fatalf("%s names the opt-in rate profile", path)
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
	wantBudget(t, "pr", "peak", p.Budgets.RSSPeakMB, 6144)
	wantBudget(t, "pr", "growth", p.Budgets.RSSGrowthMB, 384)
	soak, err := loadProfile("budgets.yaml", "soak")
	if err != nil {
		t.Fatal(err)
	}
	wantBudget(t, "soak", "peak", soak.Budgets.RSSPeakMB, 6656)
	wantBudget(t, "soak", "growth", soak.Budgets.RSSGrowthMB, 512)
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

// readRSS loads a logged RSS series (MiB, one sample per line).
func readRSS(t *testing.T, name string) []float64 {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var out []float64
	for _, f := range strings.Fields(string(b)) {
		v, err := strconv.ParseFloat(f, 64)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, v)
	}
	return out
}

// TestRiseLastThird replays the RSS logged by green load runs on
// 2026-10-10 against the pr slope budget, then adds a steady climb to
// the same runs and expects it to fail. A pr run is 120 samples at 5s;
// the last third is 40.
func TestRiseLastThird(t *testing.T) {
	p, err := loadProfile("budgets.yaml", "pr")
	if err != nil {
		t.Fatal(err)
	}
	wantBudget(t, "pr", "growth", p.Budgets.RSSGrowthMB, 384)
	for _, name := range []string{"rss-main-a.txt", "rss-pr-a.txt", "rss-pr-b.txt"} {
		rss := readRSS(t, name)
		if len(rss) != 120 {
			t.Fatalf("%s: %d samples", name, len(rss))
		}
		if got := riseLastThird(rss); got > p.Budgets.RSSSlopeMB {
			t.Errorf("%s: healthy run reads a %.0f MiB rise, budget %v", name, got, p.Budgets.RSSSlopeMB)
		}
		// The same run with 12 MiB per sample added through its last
		// third: about 470 MiB across the third on top of what it did.
		leaky := slices.Clone(rss)
		for i := 80; i < len(leaky); i++ {
			leaky[i] += float64(i-80) * 12
		}
		if got := riseLastThird(leaky); got <= p.Budgets.RSSSlopeMB {
			t.Errorf("%s: a steady climb reads only %.0f MiB, budget %v", name, got, p.Budgets.RSSSlopeMB)
		}
	}
}

func TestRiseLastThirdShapes(t *testing.T) {
	const n = 120
	ramp := func(from, step float64, at int) []float64 {
		s := repeatN(from, n)
		for i := at; i < n; i++ {
			s[i] = from + float64(i-at)*step
		}
		return s
	}
	// 10 MiB per sample over the last third: the slope reads 390 MiB across
	// 39 gaps and the last sixth sits 290 above the middle third.
	if got := riseLastThird(ramp(4000, 10, 80)); got < 280 || got > 300 {
		t.Fatalf("steady climb: %v", got)
	}
	if got := riseLastThird(repeatN(4800, n)); got != 0 {
		t.Fatalf("flat: %v", got)
	}
	// Falling is not a leak.
	if got := riseLastThird(ramp(5000, -10, 80)); got != 0 {
		t.Fatalf("falling: %v", got)
	}
	// One step at the last sample, as run 38058626210 ended, is not a trend.
	step := repeatN(4800, n)
	step[n-1] = 5100
	if got := riseLastThird(step); got != 0 {
		t.Fatalf("single step: %v", got)
	}
	// A plateau that dips and refills inside the third is no net climb:
	// the slope alone would read 325 here.
	saw := repeatN(4900, n)
	for i := 80; i < 100; i++ {
		saw[i] = 4600
	}
	if got := riseLastThird(saw); got != 0 {
		t.Fatalf("dip then refill: %v", got)
	}
	// Too few samples to say.
	if got := riseLastThird([]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 100}); got != 0 {
		t.Fatalf("short run: %v", got)
	}
	if got := riseLastThird(nil); got != 0 {
		t.Fatalf("no samples: %v", got)
	}
}

func TestReportFailsWhenStillRising(t *testing.T) {
	b := Budgets{RSSSlopeMB: 320}
	r := Result{Profile: "x", RSSSlopeMB: 100, Failures: []string{}}
	if text, ok := report(r, b); !ok || !strings.Contains(text, "| RSS still rising, last third | 100 MiB | ≤ 320 MiB | ok |") {
		t.Fatalf("ok=%v\n%s", ok, text)
	}
	r.RSSSlopeMB = 400
	if text, ok := report(r, b); ok || !strings.Contains(text, "**OVER**") {
		t.Fatalf("a climbing run passed:\n%s", text)
	}
}

// wantBudget compares a resolved budget with the figure it must equal. The
// per-million values are decimals, so the product is checked to a hundredth.
func wantBudget(t *testing.T, profile, what string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.01 {
		t.Fatalf("%s %s budget = %v, want %v", profile, what, got, want)
	}
}

// Budgets are per million prefixes, so the same file gives a bigger limit to
// a bigger table, and a figure left out stays unchecked (#217).
func TestBudgetsScaleWithTable(t *testing.T) {
	b := Budgets{LearnSecondsPerM: 72, RSSPeakMBPerM: 5000, RSSGrowthMBPerM: 300, RSSSlopeMBPerM: 150, CPUAvgCores: 2}
	small, big := b.scaled(1_000_000), b.scaled(5_000_000)
	if small.LearnSeconds != 72 || small.RSSPeakMB != 5000 || small.RSSGrowthMB != 300 || small.RSSSlopeMB != 150 {
		t.Fatalf("1M: %+v", small)
	}
	if big.LearnSeconds != 360 || big.RSSPeakMB != 25000 || big.RSSGrowthMB != 1500 || big.RSSSlopeMB != 750 {
		t.Fatalf("5M: %+v", big)
	}
	if big.CPUAvgCores != 2 {
		t.Fatalf("a table-independent budget was scaled: %v", big.CPUAvgCores)
	}
	if got := (Budgets{}).scaled(5_000_000); got.RSSPeakMB != 0 || got.LearnSeconds != 0 || got.RSSGrowthMB != 0 || got.RSSSlopeMB != 0 {
		t.Fatalf("unset budgets became checked: %+v", got)
	}
	// 20 GiB of RSS fails the 1M peak budget and passes the 5M one.
	r := Result{Profile: "x", RSSPeakMB: 20000, Failures: []string{}}
	if _, ok := report(r, small); ok {
		t.Fatal("20 GiB passed a 1M table budget")
	}
	if _, ok := report(r, big); !ok {
		t.Fatal("20 GiB failed a 5M table budget")
	}
}

func TestNegativeBudgetRejected(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/b.yaml"
	y := "profiles:\n  x:\n    prefixes: 20000\n    duration: 1m\n    warmup: 10s\n    sample: 2s\n    budgets: {rss_peak_mb_per_mprefix: -1}\n"
	if err := os.WriteFile(path, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path, "x"); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("err = %v, want a negative budget error", err)
	}
	// The flat names are gone: a stale key is an error, not an ignored limit.
	y = strings.Replace(y, "rss_peak_mb_per_mprefix: -1", "rss_peak_mb: 6144", 1)
	if err := os.WriteFile(path, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path, "x"); err == nil {
		t.Fatal("a flat rss_peak_mb key was accepted")
	}
}

// The IPv6 half keeps the shape file's length mix: every length class of
// the shape holds its share of the entries once moved by the layout's shift.
func TestTableFollowsShapeLengthMix(t *testing.T) {
	sh := shape.Default()
	n := 300000
	tbl := newTable(n)
	if !tbl.valid() {
		t.Fatal("table not valid")
	}
	m := n - v4Count
	want := map[int]float64{}
	for l, c := range sh.IPv6.Length {
		want[min(64, max(32, l+tbl.v6.shift))] += float64(c) / float64(sh.IPv6.Prefixes)
	}
	got := map[int]int{}
	seen := make(map[netip.Prefix]bool, m)
	for i := v4Count; i < n; i++ {
		p := tbl.prefix(i)
		if seen[p] {
			t.Fatalf("entry %d: %v repeated", i, p)
		}
		seen[p] = true
		got[p.Bits()]++
	}
	all := make([]netip.Prefix, 0, m)
	for p := range seen {
		all = append(all, p)
	}
	slices.SortFunc(all, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	for k := 1; k < len(all); k++ {
		if all[k-1].Overlaps(all[k]) {
			t.Fatalf("%v and %v overlap", all[k-1], all[k])
		}
	}
	for d, w := range want {
		if diff := math.Abs(float64(got[d])/float64(m) - w); diff > 0.002 {
			t.Errorf("/%d holds %.4f of the IPv6 entries, shape says %.4f", d, float64(got[d])/float64(m), w)
		}
	}
}

func TestLayoutRefusesMoreThanTheBlockHolds(t *testing.T) {
	if layoutV6(shape.Default().IPv6.Length, maxV6+1) != nil {
		t.Fatal("a table past 2001:db8::/32 must not lay out")
	}
	if newTable(v4Count + maxV6 + 1).valid() {
		t.Fatal("table past the block reports valid")
	}
}

// Attribute sets are drawn from the shape: path length, origin, communities
// and large communities follow the dump's counts, and sets are distinct.
func TestAttributesFollowShape(t *testing.T) {
	sh := shape.Default()
	tbl := newTable(1250000)
	if per := 1e6 / sh.SetsPerMillion(); math.Abs(float64(tbl.setLen)-per) > 0.5 || tbl.setLen >= 64 {
		t.Fatalf("%d prefixes per attribute set, shape says %.2f (the table used 64 before #341)", tbl.setLen, per)
	}
	mean := func(h map[int]int) float64 {
		sum, tot := 0, 0
		for k, v := range h {
			sum += k * v
			tot += v
		}
		return float64(sum) / float64(tot)
	}
	const groups = 100000
	var hops, comms, large, incomplete float64
	distinct := map[string]bool{}
	for g := range groups {
		a := tbl.attrs(g * tbl.setLen)
		checkDocASNs(t, g, a)
		hops += float64(len(a.path))
		comms += float64(len(a.comms))
		large += float64(len(a.large))
		if a.origin == 2 {
			incomplete++
		}
		distinct[fmt.Sprint(a)] = true
	}
	near := func(name string, got, want float64) {
		t.Helper()
		if math.Abs(got-want) > 0.03*want {
			t.Errorf("%s mean %.3f, shape says %.3f", name, got, want)
		}
	}
	near("AS path length", hops/groups, mean(sh.ASPathLength))
	near("communities", comms/groups, mean(sh.Communities))
	near("large communities", large/groups, mean(sh.LargeCommunities))
	near("incomplete origin share", incomplete/groups, float64(sh.Origin[2])/float64(sh.Routes))
	if len(distinct) < groups*95/100 {
		t.Errorf("%d distinct attribute sets in %d groups", len(distinct), groups)
	}
	if a, b := tbl.attrs(777), tbl.attrs(777); fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatal("attribute set is not a function of the entry")
	}
}

// Every UPDATE the router builds parses back with the attributes the table
// asked for, and fits the 4096-byte limit.
func TestRouterMessagesCarryShapeAttributes(t *testing.T) {
	tbl := newTable(v4Count + 200000)
	r := &router{tbl: tbl}
	sawComm, sawLarge := false, false
	for _, i := range []int{0, 3, 6, v4Count, v4Count + 3, v4Count + 90000} {
		for g := range 2000 {
			start := i + g*tbl.setLen*7
			if i < v4Count {
				start = i
			}
			end := start + tbl.setLen
			if start < v4Count && end > v4Count || end > tbl.n {
				continue
			}
			b, err := r.message(start, end, false).Serialize()
			if err != nil || len(b) > 4096 {
				t.Fatalf("entry %d: %d bytes, %v", start, len(b), err)
			}
			m, err := bgp.ParseBGPMessage(b)
			if err != nil {
				t.Fatalf("entry %d: %v", start, err)
			}
			want := tbl.attrs(start)
			var gotPath []uint32
			var comms []uint32
			large := 0
			for _, a := range m.Body.(*bgp.BGPUpdate).PathAttributes {
				switch v := a.(type) {
				case *bgp.PathAttributeAsPath:
					for _, p := range v.Value {
						gotPath = append(gotPath, p.GetAS()...)
					}
				case *bgp.PathAttributeCommunities:
					comms = v.Value
				case *bgp.PathAttributeLargeCommunities:
					large = len(v.Values)
				}
			}
			if !slices.Equal(gotPath, want.path) || !slices.Equal(comms, want.comms) || large != len(want.large) {
				t.Fatalf("entry %d: path %v comms %v large %d, want %+v", start, gotPath, comms, large, want)
			}
			sawComm = sawComm || len(comms) > 0
			sawLarge = sawLarge || large > 0
		}
	}
	if !sawComm || !sawLarge {
		t.Fatalf("communities seen %v, large communities seen %v", sawComm, sawLarge)
	}
}
