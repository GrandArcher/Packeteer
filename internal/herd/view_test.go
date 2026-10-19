package herd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

func TestVantagesAreListedSeparatelyNeverMerged(t *testing.T) {
	a := newMember(t, 64501, nil)
	b := newMember(t, 64502, func(h *config.Herd) { h.Vantage.Country = "DE" })
	a.serve(b.node)
	a.seedN(3, 64510)
	// b has its own measurements of the same origin through another provider.
	b.seed(b.mkRecord("b1", 64510, 64503, "198.51.100.0/24", t0.Add(-time.Minute), 80, 90), route("198.51.100.0/24", 64503, 64510))
	b.puller(a, 64510).Round(context.Background())

	v, err := BuildView(context.Background(), b.store, "origin_asn=64510", 64502, map[string]uint32{a.node.ID(): 64501}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Vantages) != 2 {
		t.Fatalf("vantages = %+v, want this node and a", v.Vantages)
	}
	local, remote := v.Vantages[0], v.Vantages[1]
	if !local.Local || local.Member != "local" || local.ASN != 64502 || local.Country != "DE" || local.Records != 1 || local.ProviderASN != 64503 {
		t.Errorf("local vantage = %+v", local)
	}
	if remote.Local || remote.Member != a.node.ID() || remote.ASN != 64501 || remote.Country != "US" || remote.Records != 3 || remote.Identity != "pinned_key" {
		t.Errorf("remote vantage = %+v", remote)
	}
	if remote.Latest.Signature == "" || remote.Latest.FetchedAt == nil || remote.Latest.GeneratedAt == nil {
		t.Errorf("remote row lacks provenance: %+v", remote.Latest)
	}
	if remote.Latest.RTTAvgMs == nil || *remote.Latest.RTTAvgMs != 11 || *local.Latest.RTTAvgMs != 85 {
		t.Errorf("each vantage keeps its own numbers: remote %+v local %+v", remote.Latest, local.Latest)
	}
	if len(remote.History) != 3 || !remote.History[0].Time.After(remote.History[2].Time) {
		t.Errorf("history is not newest first: %+v", remote.History)
	}

	// A member that is no longer a configured peer is not shown.
	v, err = BuildView(context.Background(), b.store, "origin_asn=64510", 64502, map[string]uint32{}, t0)
	if err != nil || len(v.Vantages) != 1 || !v.Vantages[0].Local {
		t.Errorf("after the peer was removed: %+v, %v", v.Vantages, err)
	}
}

func TestVantageQueryIsStrict(t *testing.T) {
	m := newMember(t, 64501, nil)
	for q, want := range map[string]string{
		"":                                    "name an origin_asn or a prefix",
		"bogus=1":                             `unknown parameter "bogus"`,
		"origin_asn=x":                        "is not an ASN",
		"origin_asn=64510&provider_asn=0":     "is not an ASN",
		"prefix=198.51.100.5/24":              "prefix",
		"prefix=198.51.100.0/24&match=nearby": "match",
		"origin_asn=64510&from=yesterday":     "from",
		"origin_asn=64510&%zz":                "malformed",
	} {
		_, err := BuildView(context.Background(), m.store, q, 64501, nil, t0)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want it to contain %q", q, err, want)
		}
	}
}

func TestRecordValidationRefusesWhatDoesNotMatchItsSamples(t *testing.T) {
	m := newMember(t, 64501, nil)
	good := m.mkRecord("g", 64510, 64501, "198.51.100.0/24", t0, 10, 20, 30)
	if err := good.Validate(config.HerdOriginASN); err != nil {
		t.Fatalf("a valid record: %v", err)
	}
	f := func(v float64) *float64 { return &v }
	tests := map[string]func(*Record){
		"schema":              func(r *Record) { r.Schema = "herd/v2" },
		"loss off":            func(r *Record) { r.LossPct = f(0) },
		"avg off":             func(r *Record) { r.RTTAvgMs = f(1) },
		"min off":             func(r *Record) { r.RTTMinMs = f(0) },
		"more replies":        func(r *Record) { r.Sent = 2 },
		"negative rtt":        func(r *Record) { r.Samples[0].RTTMs = -1 },
		"host out of order":   func(r *Record) { r.Samples[1].Host = 3 },
		"prefix at origin":    func(r *Record) { r.Prefix = "198.51.100.0/24" },
		"bad vantage":         func(r *Record) { r.Vantage = "usa" },
		"bad method":          func(r *Record) { r.Method = "carrier-pigeon" },
		"zero asn in path":    func(r *Record) { r.ASPaths = [][]uint32{{64501, 0}} },
		"failed with numbers": func(r *Record) { r.Failed = true },
		"no routes":           func(r *Record) { r.Routes = 0 },
	}
	for name, mutate := range tests {
		r := good
		r.Samples = append([]Sample(nil), good.Samples...)
		mutate(&r)
		if err := r.Validate(config.HerdOriginASN); err == nil {
			t.Errorf("%s: a bad record validated", name)
		}
	}
	if err := good.Validate(config.HerdRoute); err == nil {
		t.Error("a record validated against the wrong envelope granularity")
	}
}
