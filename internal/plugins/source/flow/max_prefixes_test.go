package flow

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestMaxPrefixesConfig(t *testing.T) {
	if s := mustSource(t, "listen: 127.0.0.1:2055\n"); s.maxPrefixes != 20000 {
		t.Fatalf("default max_prefixes = %d, want 20000", s.maxPrefixes)
	}
	// A top_n past the old 10000 is allowed once the window can hold it.
	s := mustSource(t, "listen: 127.0.0.1:2055\ntop_n: 30000\nmax_prefixes: 40000\n")
	if s.maxPrefixes != 40000 || s.topN != 30000 || s.maxTargets != 30000 {
		t.Fatalf("max_prefixes %d top_n %d max_targets %d", s.maxPrefixes, s.topN, s.maxTargets)
	}
	for y, want := range map[string]string{
		"listen: 127.0.0.1:2055\nmax_prefixes: -1":                                                   "max_prefixes -1 must be between 1 and 250000",
		"listen: 127.0.0.1:2055\nmax_prefixes: 250001":                                               "max_prefixes 250001 must be between 1 and 250000",
		"listen: 127.0.0.1:2055\ntop_n: 200\nmax_prefixes: 100":                                      "exceeds max_prefixes 100",
		"listen: 127.0.0.1:2055\ntop_n: 30000":                                                       "exceeds max_prefixes 20000",
		"listen: 127.0.0.1:2055\ntop_n: 100\nmax_targets: 300\nmax_prefixes: 200\ntail_interval: 1m": "max_targets (top_n when unset) 300 exceeds max_prefixes 200",
	} {
		if _, err := build(y); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
}

func TestMaxPrefixesTruncationCounted(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\ntop_n: 2\nmax_prefixes: 2\n")
	t0 := time.Unix(1_700_000_000, 0)
	pin(s, t0)
	exp := netip.MustParseAddr("192.0.2.8")
	type rec = struct {
		dst    string
		proto  uint8
		octets uint32
	}
	// Two cells fill the bucket. Equal bytes never displace one, so the
	// other two prefixes are refused.
	s.ingest(t0, exp, v5proto(rec{"198.51.100.10", 17, 100}, rec{"203.0.113.10", 17, 100},
		rec{"192.0.2.77", 17, 100}, rec{"198.18.0.9", 17, 100}))
	if got := s.Truncated()["max_prefixes"]; got != 2 {
		t.Fatalf("truncated = %d, want 2 refused", got)
	}
	// A larger prefix takes a cell by evicting one: the eviction counts too.
	s.ingest(t0, exp, v5proto(rec{"192.0.2.77", 17, 5000}))
	if got := s.Truncated()["max_prefixes"]; got != 3 {
		t.Fatalf("truncated = %d, want 3 (2 refused + 1 evicted)", got)
	}
	if top := s.win.top(t0, 1, 0); len(top) != 1 || top[0].prefix != netip.MustParsePrefix("192.0.2.0/24") {
		t.Fatalf("the larger prefix did not take a cell: %+v", top)
	}
}

func TestProblemsMaxTargetsWithinMaxPrefixes(t *testing.T) {
	y := problemsYAML + "  max_targets: 300\n"
	if _, err := build(y + "max_prefixes: 200\n"); err == nil || !strings.Contains(err.Error(), "problems.max_targets 300 exceeds max_prefixes 200") {
		t.Fatalf("err = %v", err)
	}
	if _, err := build(y + "max_prefixes: 300\n"); err != nil {
		t.Fatal(err)
	}
}
