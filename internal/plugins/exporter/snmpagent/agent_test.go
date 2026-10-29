package snmpagent

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GrandArcher/Packeteer/internal/plugins/snmpcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var testEnv = map[string]string{"SNMP_COMMUNITY": "lab-community", "SNMP_USER": "nms", "SNMP_AUTH": "auth-pass-123", "SNMP_PRIV": "priv-pass-456"}

func newAgent(t *testing.T, y string) (*Agent, string) {
	t.Helper()
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	probe.Close()
	c, err := plugin.ConfigFromYAML("listen: " + addr + "\n" + y)
	if err != nil {
		t.Fatal(err)
	}
	x, err := plugin.Exporters.New(TypeName, c, plugin.Env{Getenv: func(k string) string { return testEnv[k] }})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Stop(context.Background()) })
	return x.(*Agent), addr
}

const bothYAML = "community_env: SNMP_COMMUNITY\nusername_env: SNMP_USER\nauth_env: SNMP_AUTH\nauth_protocol: SHA256\npriv_env: SNMP_PRIV\n"

func g(name string, v float64, kv ...string) plugin.MetricSample {
	l := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		l[kv[i]] = kv[i+1]
	}
	return plugin.MetricSample{Name: name, Labels: l, Value: v}
}

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func snapshot(at time.Time, commits float64) plugin.MetricsRecord {
	return plugin.MetricsRecord{Time: at, Samples: []plugin.MetricSample{
		g("packeteer_build_info", 1, "version", "0.9.0", "mode", "observe"),
		g("packeteer_ready", 1),
		g("packeteer_improvements_active", 3),
		g("packeteer_rib_prefixes", 1200),
		g("packeteer_probe_prefix_commits", commits),
		g("packeteer_ha_active", 0, "id", "a"),
		g("packeteer_provider_up", 1, "provider", "transit-b", "exclude", "false"),
		g("packeteer_provider_up", 0, "provider", "transit-a", "exclude", "false"),
		g("packeteer_probe_loss_ratio", 0.02, "provider", "transit-a", "prefix", "192.0.2.0/24"),
		g("packeteer_probe_loss_ratio", 0.04, "provider", "transit-a", "prefix", "198.51.100.0/24"),
		g("packeteer_probe_rtt_seconds", 0.0125, "provider", "transit-a", "prefix", "192.0.2.0/24"),
		g("packeteer_probe_jitter_seconds", 0.0005, "provider", "transit-a", "prefix", "192.0.2.0/24"),
		g("packeteer_telemetry_up", 1, "provider", "transit-b", "interface", "ether1", "percentile", "separate"),
		g("packeteer_telemetry_in_bps", 250e6, "provider", "transit-b", "interface", "ether1", "percentile", "separate"),
		g("packeteer_telemetry_out_bps", 80e6, "provider", "transit-b", "interface", "ether1", "percentile", "separate"),
		g("packeteer_telemetry_in_95th_bps", 400e6, "provider", "transit-b", "interface", "ether1", "percentile", "separate"),
		g("packeteer_telemetry_out_95th_bps", 120e6, "provider", "transit-b", "interface", "ether1", "percentile", "separate"),
		g("packeteer_telemetry_commit_bps", 500e6, "provider", "transit-b", "interface", "ether1", "percentile", "separate"),
		g("packeteer_telemetry_up", 0, "provider", "transit-a", "interface", "ether2", "percentile", "separate"),
		g("packeteer_telemetry_in_bps", 0, "provider", "transit-a", "interface", "ether2", "percentile", "separate"),
	}}
}

func feed(t *testing.T, a *Agent, recs ...plugin.MetricsRecord) {
	t.Helper()
	var batch []plugin.ExportRecord
	for i := range recs {
		batch = append(batch, plugin.ExportRecord{Stream: plugin.StreamMetrics, Metrics: &recs[i]})
	}
	if err := a.Export(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
}

func v2c(t *testing.T, addr, community string) *gosnmp.GoSNMP {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	c := &gosnmp.GoSNMP{Target: host, Port: uint16(p), Version: gosnmp.Version2c, Community: community,
		Timeout: 300 * time.Millisecond, Retries: 0, Logger: gosnmp.NewLogger(nil)}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Conn.Close() })
	return c
}

func v3(t *testing.T, addr, user, auth, priv string, flags gosnmp.SnmpV3MsgFlags) *gosnmp.GoSNMP {
	t.Helper()
	c := v2c(t, addr, "")
	c.Conn.Close()
	c.Version = gosnmp.Version3
	c.SecurityModel = gosnmp.UserSecurityModel
	c.MsgFlags = flags
	c.Timeout = time.Second
	usm := &gosnmp.UsmSecurityParameters{UserName: user, AuthenticationProtocol: gosnmp.NoAuth, PrivacyProtocol: gosnmp.NoPriv,
		Logger: gosnmp.NewLogger(nil)}
	if flags != gosnmp.NoAuthNoPriv {
		usm.AuthenticationProtocol, usm.AuthenticationPassphrase = gosnmp.SHA256, auth
	}
	if flags == gosnmp.AuthPriv {
		usm.PrivacyProtocol, usm.PrivacyPassphrase = gosnmp.AES, priv
	}
	c.SecurityParameters = usm
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Conn.Close() })
	return c
}

func str(v any) string {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return ""
}

func walk(t *testing.T, c *gosnmp.GoSNMP, root string) map[string]gosnmp.SnmpPDU {
	t.Helper()
	out := map[string]gosnmp.SnmpPDU{}
	err := c.Walk(root, func(p gosnmp.SnmpPDU) error {
		out[strings.TrimPrefix(p.Name, "."+snmpcfg.DefaultEnterpriseOID+".")] = p
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func TestV2cWalkServesTheStatusAndProviders(t *testing.T) {
	a, addr := newAgent(t, bothYAML)
	feed(t, a, snapshot(t0.Add(-30*time.Second), 1000), snapshot(t0, 1060))
	a.now = func() time.Time { return t0.Add(7 * time.Second) }
	got := walk(t, v2c(t, addr, "lab-community"), "."+snmpcfg.DefaultEnterpriseOID)

	text := map[string]string{"2.1.0": "0.9.0", "2.2.0": "observe", "3.1.2.1": "transit-a", "3.1.2.2": "transit-b"}
	for k, w := range text {
		if g := str(got[k].Value); g != w {
			t.Errorf("%s = %q, want %q", k, g, w)
		}
	}
	nums := map[string]uint64{
		"2.5.0": 3, "2.6.0": 1200, "2.7.0": 120 /* 60 results in 30 s */, "2.8.0": 7,
		"3.1.4.1": 30, "3.1.5.1": 12500, "3.1.6.1": 500, // transit-a loss permille (mean 3%), rtt and jitter in microseconds
		"3.1.8.2": 250000, "3.1.9.2": 80000, "3.1.10.2": 400000, "3.1.11.2": 120000, "3.1.13.2": 500000, // kbit/s
	}
	for k, w := range nums {
		if g := gosnmp.ToBigInt(got[k].Value).Uint64(); got[k].Type != gosnmp.Gauge32 || g != w {
			t.Errorf("%s = %v (%v), want gauge %d", k, got[k].Value, got[k].Type, w)
		}
	}
	truths := map[string]int{"2.3.0": 1, "2.4.0": 3 /* standby */, "3.1.3.1": 2, "3.1.3.2": 1, "3.1.7.2": 1, "3.1.7.1": 2}
	for k, w := range truths {
		if got[k].Type != gosnmp.Integer || got[k].Value != w {
			t.Errorf("%s = %v, want %d", k, got[k].Value, w)
		}
	}
	// A reading Packeteer does not have is absent, not zero.
	for _, k := range []string{"3.1.4.2", "3.1.8.1", "3.1.13.1", "3.1.12.2"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s is present: %v", k, got[k].Value)
		}
	}
}

func TestEmptyBeforeFirstSnapshot(t *testing.T) {
	_, addr := newAgent(t, bothYAML)
	c := v2c(t, addr, "lab-community")
	r, err := c.Get([]string{"." + snmpcfg.DefaultEnterpriseOID + ".2.2.0"})
	if err != nil || r.Variables[0].Type != gosnmp.NoSuchObject {
		t.Fatalf("get = %+v, %v", r, err)
	}
	r, err = c.GetNext([]string{"." + snmpcfg.DefaultEnterpriseOID})
	if err != nil || r.Variables[0].Type != gosnmp.EndOfMibView {
		t.Fatalf("getnext = %+v, %v", r, err)
	}
}

func TestGetNextBulkAndTooBig(t *testing.T) {
	a, addr := newAgent(t, bothYAML)
	feed(t, a, snapshot(t0, 1000))
	c := v2c(t, addr, "lab-community")
	root := "." + snmpcfg.DefaultEnterpriseOID

	r, err := c.GetNext([]string{root + ".2.1.0"})
	if err != nil || r.Variables[0].Name != root+".2.2.0" || str(r.Variables[0].Value) != "observe" {
		t.Fatalf("getnext = %+v, %v", r, err)
	}
	// Past the last object.
	r, err = c.GetNext([]string{root + ".4"})
	if err != nil || r.Variables[0].Type != gosnmp.EndOfMibView {
		t.Fatalf("getnext past the end = %+v, %v", r, err)
	}
	// One non-repeater and a repeater walking the provider names.
	r, err = c.GetBulk([]string{root + ".2.1.0", root + ".3.1.2"}, 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Variables) != 6 || r.Variables[0].Name != root+".2.2.0" || r.Variables[1].Name != root+".3.1.2.1" || r.Variables[2].Name != root+".3.1.2.2" {
		t.Fatalf("bulk = %+v", r.Variables)
	}
	if r.Variables[3].Name != root+".3.1.3.1" {
		t.Errorf("a repetition continues from the previous binding: %s", r.Variables[3].Name)
	}

	// More bindings than the agent reads.
	names := make([]string, maxVarbinds+1)
	for i := range names {
		names[i] = root + ".2.1.0"
	}
	c.MaxOids = 200
	r, err = c.Get(names)
	if err != nil || r.Error != gosnmp.TooBig {
		t.Fatalf("oversized get: %+v, %v", r, err)
	}
}

func TestSetIsRefused(t *testing.T) {
	a, addr := newAgent(t, bothYAML)
	feed(t, a, snapshot(t0, 1000))
	c := v2c(t, addr, "lab-community")
	r, err := c.Set([]gosnmp.SnmpPDU{{Name: "." + snmpcfg.DefaultEnterpriseOID + ".2.2.0", Type: gosnmp.OctetString, Value: "inject"}})
	if err != nil || r.Error != gosnmp.NotWritable {
		t.Fatalf("set = %+v, %v", r, err)
	}
	if v, _ := a.cur.Load().get(append(append([]uint32{}, a.base...), 2, 2, 0)); v.v != "observe" {
		t.Fatalf("the mode changed to %v", v.v)
	}
}

func TestWrongCommunityGetsNoAnswer(t *testing.T) {
	a, addr := newAgent(t, bothYAML)
	feed(t, a, snapshot(t0, 1000))
	c := v2c(t, addr, "public")
	if _, err := c.Get([]string{"." + snmpcfg.DefaultEnterpriseOID + ".2.2.0"}); err == nil {
		t.Fatal("a wrong community was answered")
	}
}

func TestV3AuthPrivWalk(t *testing.T) {
	a, addr := newAgent(t, bothYAML)
	feed(t, a, snapshot(t0, 1000))
	c := v3(t, addr, "nms", "auth-pass-123", "priv-pass-456", gosnmp.AuthPriv)
	got := walk(t, c, "."+snmpcfg.DefaultEnterpriseOID+".2")
	if str(got["2.2.0"].Value) != "observe" || len(got) < 6 {
		t.Fatalf("walk = %v", got)
	}
}

func TestV3RefusesWhatTheUserIsNot(t *testing.T) {
	a, addr := newAgent(t, bothYAML)
	feed(t, a, snapshot(t0, 1000))
	oid := []string{"." + snmpcfg.DefaultEnterpriseOID + ".2.2.0"}
	for name, c := range map[string]*gosnmp.GoSNMP{
		"wrong password": v3(t, addr, "nms", "auth-pass-WRONG", "priv-pass-456", gosnmp.AuthPriv),
		"wrong user":     v3(t, addr, "other", "auth-pass-123", "priv-pass-456", gosnmp.AuthPriv),
		// A client that asks for less than the configured level must not
		// get an answer: that would skip authentication.
		"no auth": v3(t, addr, "nms", "", "", gosnmp.NoAuthNoPriv),
		"no priv": v3(t, addr, "nms", "auth-pass-123", "", gosnmp.AuthNoPriv),
	} {
		if r, err := c.Get(oid); err == nil {
			t.Errorf("%s: answered %+v", name, r.Variables)
		}
	}
	_ = a
}

func TestV2cOffWhenOnlyV3(t *testing.T) {
	a, addr := newAgent(t, strings.Replace(bothYAML, "community_env: SNMP_COMMUNITY\n", "", 1))
	feed(t, a, snapshot(t0, 1000))
	if _, err := v2c(t, addr, "lab-community").Get([]string{"." + snmpcfg.DefaultEnterpriseOID + ".2.2.0"}); err == nil {
		t.Fatal("v2c was answered with no community configured")
	}
}

func TestAllowFrom(t *testing.T) {
	a, addr := newAgent(t, bothYAML+"allow_from: [192.0.2.0/24]\n")
	feed(t, a, snapshot(t0, 1000))
	if _, err := v2c(t, addr, "lab-community").Get([]string{"." + snmpcfg.DefaultEnterpriseOID + ".2.2.0"}); err == nil {
		t.Fatal("a client outside allow_from was answered")
	}
	b, addr := newAgent(t, bothYAML+"allow_from: [192.0.2.0/24, '127.0.0.1']\n")
	feed(t, b, snapshot(t0, 1000))
	if _, err := v2c(t, addr, "lab-community").Get([]string{"." + snmpcfg.DefaultEnterpriseOID + ".2.2.0"}); err != nil {
		t.Fatalf("a listed client: %v", err)
	}
}

func TestProbeRateNeedsTwoSnapshotsAndIgnoresRestarts(t *testing.T) {
	a, _ := newAgent(t, bothYAML)
	rate := func() (uint32, bool) {
		r, ok := a.cur.Load().get(append(append([]uint32{}, a.base...), 2, 7, 0))
		if !ok {
			return 0, false
		}
		return r.v.(uint32), true
	}
	feed(t, a, snapshot(t0, 500))
	if _, ok := rate(); ok {
		t.Fatal("a rate from one snapshot")
	}
	feed(t, a, snapshot(t0.Add(30*time.Second), 515))
	if r, ok := rate(); !ok || r != 30 {
		t.Fatalf("rate = %d, %v, want 30 per minute", r, ok)
	}
	feed(t, a, snapshot(t0.Add(60*time.Second), 3)) // the controller restarted: the counter fell
	if _, ok := rate(); ok {
		t.Fatal("a rate across a counter reset")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"no listen", "community_env: SNMP_COMMUNITY", "listen"},
		{"bad listen", "listen: nonsense\ncommunity_env: SNMP_COMMUNITY", "host:port"},
		{"hostname listen", "listen: example.net:161\ncommunity_env: SNMP_COMMUNITY", "IP address"},
		{"port zero", "listen: 127.0.0.1:0\ncommunity_env: SNMP_COMMUNITY", "port"},
		{"open agent", "listen: 127.0.0.1:161", "community_env (v2c) or username_env (v3)"},
		{"unset community", "listen: 127.0.0.1:161\ncommunity_env: NOPE", "NOPE is not set"},
		{"v3 keys without user", "listen: 127.0.0.1:161\ncommunity_env: SNMP_COMMUNITY\nauth_env: SNMP_AUTH", "need username_env"},
		{"engine without user", "listen: 127.0.0.1:161\ncommunity_env: SNMP_COMMUNITY\nengine_id: '8000000001'", "need username_env"},
		{"v3 no auth", "listen: 127.0.0.1:161\nusername_env: SNMP_USER", "auth_env"},
		{"v3 bad engine", "listen: 127.0.0.1:161\nusername_env: SNMP_USER\nauth_env: SNMP_AUTH\npriv_env: SNMP_PRIV\nengine_id: zz", "engine_id"},
		{"bad oid", "listen: 127.0.0.1:161\ncommunity_env: SNMP_COMMUNITY\nenterprise_oid: 1.3.x", "enterprise_oid"},
		{"bad allow", "listen: 127.0.0.1:161\ncommunity_env: SNMP_COMMUNITY\nallow_from: [nowhere]", "allow_from"},
		{"literal secret", "listen: 127.0.0.1:161\ncommunity: public", "field community not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := plugin.ConfigFromYAML(tt.yaml)
			if err != nil {
				t.Fatal(err)
			}
			_, err = plugin.Exporters.New(TypeName, c, plugin.Env{Getenv: func(k string) string { return testEnv[k] }})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestStartFailsWhenThePortIsTaken(t *testing.T) {
	_, addr := newAgent(t, bothYAML)
	c, _ := plugin.ConfigFromYAML("listen: " + addr + "\ncommunity_env: SNMP_COMMUNITY")
	x, err := plugin.Exporters.New(TypeName, c, plugin.Env{Getenv: func(k string) string { return testEnv[k] }})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Start(context.Background()); err == nil {
		x.Stop(context.Background())
		t.Fatal("a second agent bound the same port")
	}
}
