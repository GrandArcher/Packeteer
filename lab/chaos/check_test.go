package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// frrOutput is the shape `vtysh -c 'show bgp ipv4 unicast json' -c 'show
// bgp neighbors json'` prints on FRR 10 (fields trimmed to the ones read,
// plus some that are not), with text before and between the objects.
const frrOutput = `edge# {
 "vrfId": 0,
 "vrfName": "default",
 "routerId": "192.0.2.254",
 "localAS": 64512,
 "routes": { "198.51.100.0/24": [
  {"valid":true,"bestpath":true,"locPrf":250,"peerId":"192.0.2.10","nexthops":[{"ip":"192.0.2.2","afi":"ipv4"}]},
  {"valid":true,"weight":32768,"peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0","afi":"ipv4"}]}
 ] }
}
edge# {
  "192.0.2.10":{"remoteAs":64512,"localAs":64512,"bgpState":"Established","bgpTimerHoldTimeMsecs":9000,
    "neighborCapabilities":{"4byteAs":"advertisedAndReceived","gracefulRestartCapability":"advertised"},
    "gracefulRestartInfo":{"localGrMode":"Helper*","remoteGrMode":"Disable"},
    "messageStats":{"depthInq":0,"opensSent":2,"opensRecv":2,"updatesSent":4,"updatesRecv":7}},
  "192.0.2.20":{"remoteAs":64512,"bgpState":"Active","bgpTimerHoldTimeMsecs":0,
    "messageStats":{"updatesRecv":3}}
}
`

func TestParseSample(t *testing.T) {
	s, err := parseSample(frrOutput)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.From("192.0.2.10"); !slices.Equal(got, []string{"198.51.100.0/24"}) {
		t.Fatalf("from pk-a: %v", got)
	}
	if s.Holds("192.0.2.20") {
		t.Fatal("pk-b holds routes")
	}
	a, b := s.Peers["192.0.2.10"], s.Peers["192.0.2.20"]
	if !a.Established() || a.HoldMs != 9000 || a.UpdatesRecv != 7 || a.GR || a.RemoteAS != 64512 {
		t.Fatalf("pk-a: %+v", a)
	}
	if b.Established() || b.UpdatesRecv != 3 {
		t.Fatalf("pk-b: %+v", b)
	}
	if len(checkSample(s, pairAddrs())) != 0 {
		t.Fatalf("clean sample: %+v", checkSample(s, pairAddrs()))
	}

	for _, bad := range []string{"", "% Unknown command", `{"routes":{}}`, `{"192.0.2.10":{}}`, `{"routes": [}`} {
		if _, err := parseSample(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestGracefulRestartDetected(t *testing.T) {
	for _, tc := range []struct {
		caps, mode string
		want       bool
	}{
		{`"gracefulRestartCapability":"advertised"`, "Disable", false},
		{`"gracefulRestart":"advertisedAndReceived"`, "Disable", true},
		{`"gracefulRestartCapability":"received"`, "NotApplicable", true},
		{`"4byteAs":"advertisedAndReceived"`, "Restart", true},
		{`"4byteAs":"advertisedAndReceived"`, "Helper", true},
	} {
		out := `{"routes":{}} {"192.0.2.10":{"remoteAs":64512,"bgpState":"Established","neighborCapabilities":{` + tc.caps + `},"gracefulRestartInfo":{"remoteGrMode":"` + tc.mode + `"}}}`
		s, err := parseSample(out)
		if err != nil {
			t.Fatal(err)
		}
		if s.Peers["192.0.2.10"].GR != tc.want {
			t.Errorf("%s / %s: GR %v, want %v", tc.caps, tc.mode, !tc.want, tc.want)
		}
	}
}

func TestCheckSample(t *testing.T) {
	up := Peer{State: "Established", RemoteAS: 64512}
	at := time.Unix(0, 0)
	for _, tc := range []struct {
		name   string
		routes map[string][]string
		peers  map[string]Peer
		want   []string
	}{
		{"not learned", map[string][]string{"203.0.113.0/24": {"192.0.2.10"}}, nil, []string{invLearnedRIB}},
		{"both instances", map[string][]string{"198.51.100.0/24": {"(unspec)", "192.0.2.10", "192.0.2.20"}}, nil, []string{invHABoth}},
		{"not documentation", map[string][]string{"10.0.0.0/8": {"(unspec)"}}, nil, []string{invDocumentation}},
		{"public ASN", nil, map[string]Peer{"192.0.2.10": {State: "Established", RemoteAS: 65552}}, []string{invDocumentation}},
		{"graceful restart", nil, map[string]Peer{"192.0.2.20": {State: "Established", RemoteAS: 64512, GR: true}}, []string{invGR}},
		{"graceful restart on a down session is not read", nil, map[string]Peer{"192.0.2.20": {State: "Idle", RemoteAS: 64512, GR: true}}, nil},
		{"clean", map[string][]string{"198.51.100.0/24": {"(unspec)", "192.0.2.20"}, "2001:db8:1::/48": {"(unspec)"}}, map[string]Peer{"192.0.2.10": up}, nil},
	} {
		got := checkSample(Sample{At: at, Routes: tc.routes, Peers: tc.peers}, pairAddrs())
		var names []string
		for _, v := range got {
			names = append(names, v.Invariant)
		}
		if !slices.Equal(names, tc.want) {
			t.Errorf("%s: %v (%+v), want %v", tc.name, names, got, tc.want)
		}
	}
}

func TestDownTrackerAllowsGraceOnly(t *testing.T) {
	var d downTracker
	at := time.Unix(100, 0)
	held := func(at time.Time, state string) Sample {
		return Sample{At: at, Routes: map[string][]string{"198.51.100.0/24": {"(unspec)", "192.0.2.10"}},
			Peers: map[string]Peer{"192.0.2.10": {State: state}}}
	}
	if v := d.check(held(at, "Idle"), pairAddrs()); v != nil {
		t.Fatalf("first sample: %+v", v)
	}
	if v := d.check(held(at.Add(downGrace), "Idle"), pairAddrs()); v != nil {
		t.Fatalf("inside the grace: %+v", v)
	}
	v := d.check(held(at.Add(downGrace+time.Second), "Idle"), pairAddrs())
	if len(v) != 1 || v[0].Invariant != invDownRoutes || !strings.Contains(v[0].Detail, "192.0.2.10 is Idle") {
		t.Fatalf("past the grace: %+v", v)
	}
	// Established again clears the timer.
	d.check(held(at.Add(10*time.Second), "Idle"), pairAddrs())
	d.check(held(at.Add(11*time.Second), "Established"), pairAddrs())
	if v := d.check(held(at.Add(12*time.Second), "Idle"), pairAddrs()); v != nil {
		t.Fatalf("after recovery: %+v", v)
	}
}

func TestCheckConfigs(t *testing.T) {
	root := filepath.Join("..", "..")
	ex := filepath.Join(root, example)
	ha := []string{filepath.Join(root, "lab/packeteer-ha-a.yaml"), filepath.Join(root, "lab/packeteer-ha-b.yaml")}
	at := time.Unix(0, 0)
	if v := checkConfigs(Profile{Name: "lab", InjectLab: true, Configs: ha}, ex, at); len(v) != 0 {
		t.Fatalf("HA lab configs in an inject-lab profile: %+v", v)
	}
	v := checkConfigs(Profile{Name: "plain", Configs: ha}, ex, at)
	if len(v) != 2 || !strings.Contains(v[0].Detail, "not an inject-lab profile") {
		t.Fatalf("inject outside an inject-lab profile: %+v", v)
	}

	dir := t.TempDir()
	raw, err := os.ReadFile(ha[0])
	if err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(dir, "public.yaml")
	if err := os.WriteFile(public, []byte(strings.ReplaceAll(string(raw), "    - 198.51.100.0/24", "    - 198.51.100.0/24\n    - 100.64.0.0/10")), 0o644); err != nil {
		t.Fatal(err)
	}
	v = checkConfigs(Profile{Name: "lab", InjectLab: true, Configs: []string{public}}, ex, at)
	if len(v) != 1 || !strings.Contains(v[0].Detail, "allowlist.prefixes entry 100.64.0.0/10 is not a documentation prefix") {
		t.Fatalf("non-documentation allowlist: %+v", v)
	}
	mit, err := os.ReadFile(filepath.Join(root, "lab/packeteer-mitigation.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	mitPublic := filepath.Join(dir, "mitigation.yaml")
	if err := os.WriteFile(mitPublic, []byte(strings.Replace(string(mit), "  allowlist:\n    - 198.51.100.0/24", "  allowlist:\n    - 198.51.100.0/24\n    - 100.64.0.0/10", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	v = checkConfigs(Profile{Name: "lab", InjectLab: true, Configs: []string{mitPublic}}, ex, at)
	if len(v) != 1 || !strings.Contains(v[0].Detail, "mitigation.allowlist entry 100.64.0.0/10 is not a documentation prefix") {
		t.Fatalf("non-documentation mitigation allowlist: %+v", v)
	}
	// The HA config as the "example": an example that is not observe fails.
	v = checkConfigs(Profile{Name: "lab", InjectLab: true, Configs: ha}, ha[0], at)
	if len(v) != 1 || !strings.Contains(v[0].Detail, "must stay observe") {
		t.Fatalf("inject example: %+v", v)
	}

	if v := checkLiveMode(Profile{Name: "plain"}, "pk-a", "inject", at); len(v) != 1 || v[0].Invariant != invConfig {
		t.Fatalf("live inject: %+v", v)
	}
	if v := checkLiveMode(Profile{Name: "plain"}, "pk-a", "observe", at); v != nil {
		t.Fatalf("live observe: %+v", v)
	}
}

func TestDocumentationHelpers(t *testing.T) {
	for p, want := range map[string]bool{
		"192.0.2.0/24": true, "198.51.100.128/25": true, "203.0.113.7/32": true, "2001:db8::/32": true,
		"2001:db8:1::/48": true, "198.51.0.0/16": false, "2001::/16": false, "10.0.0.0/8": false, "junk": false,
	} {
		if isDocPrefix(p) != want {
			t.Errorf("isDocPrefix(%s) = %v", p, !want)
		}
	}
	for a, want := range map[uint32]bool{64496: true, 64511: true, 64512: true, 65534: true, 65536: true, 65551: true, 65535: false, 65552: false} {
		if isLabASN(a) != want {
			t.Errorf("isLabASN(%d) = %v", a, !want)
		}
	}
}

func TestLoadProfile(t *testing.T) {
	p, err := loadProfile("short.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "short" || p.Duration != time.Minute || !p.InjectLab || !slices.Equal(p.Faults, faultKinds) {
		t.Fatalf("%+v", p)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown fault": "name: x\nduration: 1m\nconfigs: [a]\nfaults: [reboot]\n",
		"no duration":   "name: x\nconfigs: [a]\nfaults: [sigkill]\n",
		"unknown key":   "name: x\nduration: 1m\nconfigs: [a]\nfaults: [sigkill]\nmode: inject\n",
		"no configs":    "name: x\nduration: 1m\nfaults: [sigkill]\n",
	} {
		f := filepath.Join(dir, "p.yaml")
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadProfile(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
