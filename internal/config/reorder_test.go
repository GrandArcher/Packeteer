package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestReorderOffByDefault(t *testing.T) {
	cfg, err := Parse([]byte(indirectBase))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Probe.Reorder != nil {
		t.Fatalf("reorder = %+v, want nil", cfg.Probe.Reorder)
	}
}

func TestReorderDefaults(t *testing.T) {
	cfg, err := Parse([]byte(indirectBase + `  timeout: 3s
  reorder:
    responders:
      - address: 203.0.113.9
      - address: 2001:db8::9
        port: 8620
      - address: 198.51.100.1
        type: ICMP
`))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Probe.Reorder
	if r.Packets != 20 || r.Spacing != 20*time.Millisecond || r.Timeout != 3*time.Second || r.Interval != 30*time.Second || r.Flows != 4 {
		t.Fatalf("defaults %+v", r)
	}
	want := []ReorderResponder{
		{Address: "203.0.113.9", Port: 862, Type: "twamp"},
		{Address: "2001:db8::9", Port: 8620, Type: "twamp"},
		{Address: "198.51.100.1", Type: "icmp"},
	}
	for i, w := range want {
		if r.Responders[i] != w {
			t.Fatalf("responder %d = %+v, want %+v", i, r.Responders[i], w)
		}
	}
}

func TestReorderValidation(t *testing.T) {
	cases := map[string]string{
		"reorder: {}": "responders must list at least one",
		"reorder: {packets: 1, responders: [{address: 203.0.113.9}]}":                              "packets 1 must be between 2 and 200",
		"reorder: {packets: 201, responders: [{address: 203.0.113.9}]}":                            "packets 201 must be between",
		"reorder: {spacing: 2s, responders: [{address: 203.0.113.9}]}":                             "spacing 2s must be between 1ms and 1s",
		"reorder: {timeout: 31s, responders: [{address: 203.0.113.9}]}":                            "timeout 31s must be between 1ms and 30s",
		"reorder: {interval: 500ms, responders: [{address: 203.0.113.9}]}":                         "interval 500ms must be between 1s and three times probe.interval (1m30s)",
		"reorder: {interval: 2m, responders: [{address: 203.0.113.9}]}":                            "interval 2m0s must be between",
		"reorder: {flows: 17, responders: [{address: 203.0.113.9}]}":                               "flows 17 must be between 1 and 16",
		"reorder: {responders: [{address: nope}]}":                                                 "responders[0]: address \"nope\" is not a valid IP address",
		"reorder: {responders: [{address: 203.0.113.9, port: 70000}]}":                             "responders[0]: port 70000 must be between",
		"reorder: {responders: [{address: 203.0.113.9, type: icmp, port: 862}]}":                   "responders[0]: port is not used by an icmp responder",
		"reorder: {responders: [{address: 203.0.113.9, type: udp}]}":                               "responders[0]: type \"udp\" is invalid",
		"reorder: {responders: [{address: 203.0.113.9}, {address: 203.0.113.9, port: 862}]}":       "responders[1]: duplicate",
		"exclude: {prefixes: [203.0.113.0/24]}\n  reorder: {responders: [{address: 203.0.113.9}]}": "responders[0]: address 203.0.113.9 is inside probe.exclude prefix 203.0.113.0/24",
		"reorder: {responders: [{address: 203.0.113.9, ttl: 3}]}":                                  "field ttl not found",
	}
	for y, want := range cases {
		_, err := Parse([]byte(indirectBase + "  " + y + "\n"))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
	// Two responders on one host with different ports or types are distinct.
	if _, err := Parse([]byte(indirectBase + "  reorder: {responders: [{address: 203.0.113.9}, {address: 203.0.113.9, port: 8620}, {address: 203.0.113.9, type: icmp}]}\n")); err != nil {
		t.Fatal(err)
	}
}

// A config whose measurement cannot finish before its readings go stale is
// refused: ten silent twamp responders at four flows are 40 trains of
// 20*20ms plus the 2s timeout, plus 800 packets at 100 pps.
func TestReorderCycleValidation(t *testing.T) {
	var many strings.Builder
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&many, "{address: 203.0.113.%d}, ", i)
	}
	_, err := Parse([]byte(indirectBase + "  reorder: {responders: [" + many.String() + "]}\n"))
	if want := "can take 1m44s, so a reading can wait 3m28s to be replaced, more than three times probe.interval (1m30s)"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
	if _, err := Parse([]byte(indirectBase + "  reorder: {responders: [{address: 203.0.113.9}, {address: 203.0.113.9, type: icmp}]}\n")); err != nil {
		t.Fatal(err)
	}
	// per_asn_pps paces every train as if the responders shared an ASN.
	_, err = Parse([]byte(indirectBase + "  per_asn_pps: 1\n  reorder: {timeout: 1s, responders: [{address: 203.0.113.9}]}\n"))
	if want := "can take 1m25.6s"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

// Only providers probed here count, and an icmp responder is one train.
func TestReorderCycle(t *testing.T) {
	c := &Config{Domain: "pop-a", Providers: []Provider{{Name: "a"}, {Name: "b"}, {Name: "far", Domain: "pop-b"}}}
	c.Probe.RateLimitPPS = 100
	c.Probe.Reorder = &ProbeReorder{Packets: 10, Spacing: 10 * time.Millisecond, Timeout: time.Second, Flows: 3,
		Responders: []ReorderResponder{{Type: "twamp"}, {Type: "icmp"}}}
	// 2 providers * (3 + 1) trains * (100ms + 1s) + 80 packets at 100 pps.
	if got, want := c.reorderCycle(), 8*1100*time.Millisecond+800*time.Millisecond; got != want {
		t.Fatalf("cycle %s, want %s", got, want)
	}
}
