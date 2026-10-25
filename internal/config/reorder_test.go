package config

import (
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
	if r.Responders[0].Estimate() || !r.Responders[2].Estimate() {
		t.Fatal("estimate flags wrong")
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
