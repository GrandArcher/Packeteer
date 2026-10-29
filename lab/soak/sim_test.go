package main

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/plugins/prober/sim"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func simProfile(t *testing.T) Profile {
	t.Helper()
	p, err := loadProfile("budgets.yaml", "realtable3m")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRealtable3mProfile(t *testing.T) {
	p := simProfile(t)
	if !p.Real || !p.Simulate || p.Peers != 3 || p.ScaleTo != 3_000_000 || p.sessions() != 3 || p.VIPTargets != 100000 ||
		p.Inject != 0 || p.Churn != 0 || p.FlowRate != 0 || p.StaticTargets != 0 {
		t.Fatalf("profile %+v", p)
	}
	// The per-million budgets are the realtable ones, never raised.
	one, err := loadProfile("budgets.yaml", "realtable")
	if err != nil {
		t.Fatal(err)
	}
	for name, pair := range map[string][2]float64{
		"learn":  {p.Budgets.LearnSecondsPerM, one.Budgets.LearnSecondsPerM},
		"peak":   {p.Budgets.RSSPeakMBPerM, one.Budgets.RSSPeakMBPerM},
		"growth": {p.Budgets.RSSGrowthMBPerM, one.Budgets.RSSGrowthMBPerM},
		"slope":  {p.Budgets.RSSSlopeMBPerM, one.Budgets.RSSSlopeMBPerM},
		"cpu":    {p.Budgets.CPUAvgCores, one.Budgets.CPUAvgCores},
		"api":    {p.Budgets.APIP99Ms, one.Budgets.APIP99Ms},
	} {
		if pair[0] != pair[1] || pair[0] == 0 {
			t.Errorf("%s budget %v, realtable has %v", name, pair[0], pair[1])
		}
	}
	// The budgets follow the paths the views hold, not prefixes times
	// sessions.
	view := &realTable{sets: [][]bgp.PathAttributeInterface{{seqPath(64500, 64510)}}, entries: []realEntry{{netip.MustParsePrefix("2001:db8::/32"), 0}}}
	if err := p.useReal(&realSet{prefixes: 3_000_000, paths: 8_000_000, views: []*realTable{view, {}, {}}, peers: 40}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.vipASNs, []uint32{64510}) {
		t.Fatalf("vip ASNs %v", p.vipASNs)
	}
	wantBudget(t, "realtable3m", "peak", p.Budgets.RSSPeakMB, 8*4915.2)
	wantBudget(t, "realtable3m", "learn", p.Budgets.LearnSeconds, 8*72)
	if p.Prefixes != 3_000_000 {
		t.Fatalf("prefixes %d", p.Prefixes)
	}
}

func TestSimulatedProfileRules(t *testing.T) {
	base := simProfile(t)
	for name, mut := range map[string]func(*Profile){
		"simulate without vip":      func(p *Profile) { p.VIPTargets = 0 },
		"peers beyond next hops":    func(p *Profile) { p.Peers = maxViews + 1 },
		"peers with sessions":       func(p *Profile) { p.Sessions = 2 },
		"negative scale":            func(p *Profile) { p.ScaleTo = -1 },
		"inject":                    func(p *Profile) { p.Inject = 50 },
		"static targets":            func(p *Profile) { p.StaticTargets = 10 },
		"flows":                     func(p *Profile) { p.FlowRate = 100 },
		"prefixes beside the dump":  func(p *Profile) { p.Prefixes = 1000 },
		"vip without simulate":      func(p *Profile) { p.Simulate = false },
		"outage targets":            func(p *Profile) { p.OutageTargets = 3 },
		"churn":                     func(p *Profile) { p.Churn = 60 },
		"multiply onto three peers": nil,
	} {
		bad := base
		if mut == nil {
			if err := bad.multiply(2); err == nil {
				t.Errorf("%s accepted", name)
			}
			continue
		}
		mut(&bad)
		if err := bad.validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	syn, err := loadProfile("budgets.yaml", "pr")
	if err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Profile){
		"peers":    func(p *Profile) { p.Peers = 2 },
		"scale_to": func(p *Profile) { p.ScaleTo = 2_000_000 },
		"simulate": func(p *Profile) { p.Simulate = true },
	} {
		bad := syn
		mut(&bad)
		if err := bad.validate(); err == nil || !strings.Contains(err.Error(), "real profile") {
			t.Errorf("synthetic profile with %s: %v", name, err)
		}
	}
}

// The generated config for a simulated run: observe, the sim prober and no
// other, three providers per family with a type, ASN, cost, and a commit
// where one is modeled, and a model the sim prober accepts for every one of
// those providers.
func TestSimulatedConfigIsObserveWithOnlyTheSimProber(t *testing.T) {
	p := simProfile(t)
	p.vipASNs = []uint32{64500, 64501}
	text := packeteerConfig(p, ports{BGP: 11179, Flow: 12055, HTTP: 18081}, "/var/lib/packeteer")
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if cfg.Mode != config.ModeObserve || cfg.Announcer != nil && cfg.Announcer.Type != "" {
		t.Fatalf("mode %q announcer %+v", cfg.Mode, cfg.Announcer)
	}
	if len(cfg.Probers) != 1 || cfg.Probers[0].Type != "sim" || !cfg.SimulatedProbes() {
		t.Fatalf("probers %+v: a simulated run must probe with the sim prober alone", cfg.Probers)
	}
	var kinds []string
	for _, s := range cfg.Sources {
		kinds = append(kinds, s.Type)
	}
	if !slices.Equal(kinds, []string{"flow", "vip"}) {
		t.Fatalf("sources %v: only the flow collector and the vip expansion, both of which only name targets", kinds)
	}
	if len(cfg.Providers) != 6 || len(cfg.BGP.Neighbors) != 3 {
		t.Fatalf("%d providers, %d neighbors", len(cfg.Providers), len(cfg.BGP.Neighbors))
	}
	var names []string
	types := map[string]int{}
	for _, pr := range cfg.Providers {
		names = append(names, pr.Name)
		types[pr.Type]++
		if pr.ASN == 0 || pr.Cost == nil {
			t.Errorf("provider %s has no ASN or cost", pr.Name)
		}
		for _, f := range []string{pr.SourceIP, pr.NextHop} {
			if !strings.HasPrefix(f, "192.0.2.") && !strings.HasPrefix(f, "2001:db8:") {
				t.Errorf("provider %s uses %s, not a documentation address", pr.Name, f)
			}
		}
	}
	if types["transit"] != 4 || types["peer"] != 2 {
		t.Fatalf("provider types %v", types)
	}
	if len(cfg.Telemetry) != 1 || !strings.Contains(text, "commit_mbps: 2000") || !strings.Contains(text, "commit_mbps: 1000") {
		t.Fatalf("commit fields missing:\n%s", text)
	}
	if !strings.Contains(text, "asns: [64500, 64501]") || !strings.Contains(text, "max_targets: 100000") {
		t.Fatalf("vip source:\n%s", text)
	}
	if _, err := sim.New(plugin.NewConfig(&cfg.Probers[0].Config), plugin.Env{Providers: names}); err != nil {
		t.Fatalf("the model does not match the providers: %v", err)
	}
	if strings.Contains(text, "type: fixed\n    config:\n      paths") {
		t.Fatal("the fixed prober is configured")
	}
}

// The three routes the model gives a destination differ, and each route
// carries a stated loss and delay.
func TestSimulatedRoutesAreStatedAndDistinct(t *testing.T) {
	seen := map[float64]bool{}
	for _, r := range simRoutes {
		if r.name == "" || r.rtt <= 0 || r.loss <= 0 || r.spread <= 0 || seen[r.rtt] {
			t.Errorf("route %+v", r)
		}
		seen[r.rtt] = true
	}
	for _, name := range []string{"transit-a", "transit-b", "ix-peer"} {
		if !strings.Contains(simProber(), "provider: "+name+",") || !strings.Contains(simProber(), "provider: "+name+"6,") {
			t.Errorf("no model for %s on both families", name)
		}
	}
}

func writeProc(t *testing.T, echo4, echo6 string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	snmp := "Ip: Forwarding InReceives\nIp: 1 99\nIcmp: InMsgs InErrors OutMsgs OutEchos OutEchoReps\nIcmp: 5 0 9 " + echo4 + " 2\nUdp: InDatagrams RcvbufErrors\nUdp: 7 0\n"
	if err := os.WriteFile(filepath.Join(root, "net", "snmp"), []byte(snmp), 0o644); err != nil {
		t.Fatal(err)
	}
	if echo6 != "" {
		if err := os.WriteFile(filepath.Join(root, "net", "snmp6"), []byte("Icmp6OutMsgs 4\nIcmp6OutEchos "+echo6+"\nIcmp6OutEchoReplies 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// A simulated run fails when the host's ICMP echo counter moves, for
// either family, and when the counter cannot be read.
func TestEchoCounterGuardsTheLab(t *testing.T) {
	n, err := echoesSent(writeProc(t, "3", "4"))
	if err != nil || n != 7 {
		t.Fatalf("echoes %d %v, want IPv4 and IPv6 added", n, err)
	}
	if n, err := echoesSent(writeProc(t, "3", "")); err != nil || n != 3 {
		t.Fatalf("a host without IPv6: %d %v", n, err)
	}
	if why := echoFault(writeProc(t, "3", "4"), 7); why != "" {
		t.Fatalf("unchanged counter: %q", why)
	}
	for name, root := range map[string]string{"IPv4": writeProc(t, "4", "4"), "IPv6": writeProc(t, "3", "5")} {
		if why := echoFault(root, 7); !strings.Contains(why, "moved from 7 to 8") || !strings.Contains(why, "no probe may leave the lab") {
			t.Errorf("%s echo: %q", name, why)
		}
	}
	if why := echoFault(t.TempDir(), 0); !strings.Contains(why, "cannot read") {
		t.Errorf("no counter: %q", why)
	}
}

func TestSimulatedReportSaysSo(t *testing.T) {
	r := Result{Profile: "realtable3m", Prefixes: 3_000_000, Mode: "observe", Sessions: 3, Simulated: true, Measured: 5000, Failures: []string{},
		Table: &TableInfo{Peers: 40, Views: 3, IPv4: 2_000_000, IPv6: 1_000_000, Sets: 900000, Derived: 1_900_000, Paths: 8_000_000}}
	text, _ := report(r, Budgets{MinMeasured: 2500})
	for _, want := range []string{"SIMULATED**", "prefixes measured (SIMULATED)", "active prefixes measured per hour (SIMULATED)", "3 of the dump's 40 peers", "1900000 prefixes added by scale_to"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	r.Simulated = false
	text, _ = report(r, Budgets{})
	if strings.Contains(text, "SIMULATED") {
		t.Errorf("a measured run is labeled simulated:\n%s", text)
	}
}

// The simulated profile needs the dump at config time and the script
// refuses a profile or session count that does not fit.
func TestSimulatedRunNeedsDumpAndScriptChecksProfile(t *testing.T) {
	if err := cmdConfig([]string{"-budgets", "budgets.yaml", "-profile", "realtable3m"}); err == nil || !strings.Contains(err.Error(), "-mrt") {
		t.Fatalf("config without a dump: %v", err)
	}
	for _, tc := range []struct {
		env  string
		args []string
		want string
	}{
		{"REALTABLE_PROFILE=routes3m", []string{"img"}, "REALTABLE_PROFILE must be"},
		{"REALTABLE_PROFILE=realtable3m", []string{"img", "2"}, "MULTIPLY must be 1 for realtable3m"},
	} {
		cmd := exec.Command("bash", append([]string{"../realtable.sh"}, tc.args...)...)
		cmd.Env = append(os.Environ(), tc.env)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 2 || !strings.Contains(string(out), tc.want) {
			t.Errorf("%s %v: %v %s", tc.env, tc.args, err, out)
		}
	}
}
