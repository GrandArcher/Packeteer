package httpapi

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/probe"
)

func reorderInput() Input {
	in := sampleInput()
	at := in.At
	ref := netip.MustParseAddr("203.0.113.9")
	echo := netip.MustParseAddr("198.51.100.1")
	in.ReorderConfigured = true
	in.Reorder = []probe.ReorderResult{
		{Provider: "transit-b", Responder: ref, Port: 862, Type: probe.ResponderTWAMP,
			Flows: []probe.FlowReorder{
				{Flow: 1, ReorderStats: probe.ReorderStats{Sent: 20, Received: 20}},
				{Flow: 2, ReorderStats: probe.ReorderStats{Sent: 20, Received: 20, Reordered: 4, RatioPct: 20, Extent: 1, NReordering: 1}},
			},
			Worst: probe.ReorderStats{Sent: 20, Received: 20, Reordered: 4, RatioPct: 20, Extent: 1, NReordering: 1}, WorstFlow: 2, Time: at},
		{Provider: "transit-a", Responder: ref, Port: 862, Type: probe.ResponderTWAMP,
			Flows: []probe.FlowReorder{{Flow: 1, ReorderStats: probe.ReorderStats{Sent: 20, Received: 20}}},
			Worst: probe.ReorderStats{Sent: 20, Received: 20}, WorstFlow: 1, Time: at},
		{Provider: "transit-a", Responder: echo, Type: probe.ResponderICMP, Estimate: true,
			Flows: []probe.FlowReorder{{Flow: 1, ReorderStats: probe.ReorderStats{Sent: 20, Received: 19, Reordered: 2, RatioPct: 10.5263, Extent: 2, NReordering: 1}}},
			Worst: probe.ReorderStats{Sent: 20, Received: 19, Reordered: 2, RatioPct: 10.5263, Extent: 2, NReordering: 1}, WorstFlow: 1, Time: at},
		{Provider: "transit-b", Responder: echo, Type: probe.ResponderICMP, Estimate: true,
			Flows: []probe.FlowReorder{{Flow: 1, ReorderStats: probe.ReorderStats{Sent: 20}, Err: "rate limit: context deadline exceeded"}},
			Err:   "rate limit: context deadline exceeded", Time: at},
	}
	return in
}

func TestReorderAPI(t *testing.T) {
	snap := Assemble(reorderInput())
	if len(snap.Reorder) != 4 || !snap.ReorderConfigured {
		t.Fatalf("reorder rows %+v", snap.Reorder)
	}
	// Sorted by provider then responder.
	if snap.Reorder[0].Provider != "transit-a" || snap.Reorder[0].Responder != "198.51.100.1" || snap.Reorder[1].Responder != "203.0.113.9" {
		t.Fatalf("order %+v", snap.Reorder)
	}
	// The controlled reading is the headline even though the estimate is
	// worse; a provider with only a failed estimate has none.
	a, b := snap.Providers[0], snap.Providers[1]
	if a.Name != "transit-a" || a.Reorder == nil || a.Reorder.RatioPct != 0 || a.Reorder.Estimate || a.Reorder.Responder != "203.0.113.9" {
		t.Fatalf("transit-a headline %+v", a.Reorder)
	}
	if b.Reorder == nil || b.Reorder.RatioPct != 20 || b.Reorder.Extent != 1 || b.Reorder.NReordering != 1 || b.Reorder.Estimate {
		t.Fatalf("transit-b headline %+v", b.Reorder)
	}

	ts := newTestServer(t, snap, "", "")
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/reorder", "", "")
	if code != http.StatusOK {
		t.Fatalf("code %d: %s", code, body)
	}
	var got struct {
		Configured bool      `json:"configured"`
		Reorder    []Reorder `json:"reorder"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Configured || len(got.Reorder) != 4 {
		t.Fatalf("body %s", body)
	}
	bRef := got.Reorder[3]
	if bRef.Provider != "transit-b" || bRef.Type != "twamp" || bRef.Port != 862 || !bRef.OK || bRef.Estimate ||
		bRef.WorstFlow != 2 || bRef.Worst.RatioPct != 20 || len(bRef.Flows) != 2 || bRef.Flows[1].Reordered != 4 {
		t.Fatalf("transit-b row %+v", bRef)
	}
	bEcho := got.Reorder[2]
	if bEcho.OK || !bEcho.Estimate || bEcho.Error == "" || bEcho.Flows[0].Error == "" || bEcho.WorstFlow != 0 {
		t.Fatalf("failed estimate row %+v", bEcho)
	}
	text := string(body)
	for _, want := range []string{`"estimate":true`, `"n_reordering":1`, `"ratio_pct":10.5263`} {
		if !strings.Contains(text, want) {
			t.Fatalf("body lacks %s: %s", want, text)
		}
	}

	code, _, body = do(t, http.MethodGet, ts.URL+"/api/providers", "", "")
	if code != http.StatusOK || !strings.Contains(string(body), `"reorder":{"ratio_pct":20,"extent":1,"n_reordering":1,"estimate":false,"responder":"203.0.113.9"`) {
		t.Fatalf("providers %d: %s", code, body)
	}

	// Estimates are the headline only when nothing better answered.
	in := reorderInput()
	in.Reorder = in.Reorder[2:3]
	if h := Assemble(in).Providers[0].Reorder; h == nil || !h.Estimate || h.RatioPct != 10.5263 {
		t.Fatalf("estimate-only headline %+v", h)
	}

	// Off: no rows, configured false, no headline.
	off := Assemble(sampleInput())
	if off.ReorderConfigured || len(off.Reorder) != 0 || off.Providers[0].Reorder != nil {
		t.Fatalf("off: %+v", off.Reorder)
	}
	_, _, body = do(t, http.MethodGet, newTestServer(t, off, "", "").URL+"/api/reorder", "", "")
	if string(body) != "" && !strings.Contains(string(body), `"configured":false,"reorder":[]`) {
		t.Fatalf("off body %s", body)
	}
}

func TestReorderMetrics(t *testing.T) {
	text := string(Metrics(Assemble(reorderInput())))
	for _, want := range []string{
		`packeteer_reorder_success{provider="transit-b",responder="203.0.113.9",type="twamp",estimate="false"} 1`,
		`packeteer_reorder_success{provider="transit-b",responder="198.51.100.1",type="icmp",estimate="true"} 0`,
		`packeteer_reorder_ratio{provider="transit-b",responder="203.0.113.9",type="twamp",estimate="false",flow="1"} 0`,
		`packeteer_reorder_ratio{provider="transit-b",responder="203.0.113.9",type="twamp",estimate="false",flow="2"} 0.2`,
		`packeteer_reorder_extent{provider="transit-a",responder="198.51.100.1",type="icmp",estimate="true",flow="1"} 2`,
		`packeteer_reorder_n{provider="transit-b",responder="203.0.113.9",type="twamp",estimate="false",flow="2"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics lack %s:\n%s", want, text)
		}
	}
	// A failed train has no ratio series.
	if strings.Contains(text, `packeteer_reorder_ratio{provider="transit-b",responder="198.51.100.1"`) {
		t.Fatal("failed estimate exported a ratio")
	}
	// Off: no reorder series at all.
	if off := string(Metrics(Assemble(sampleInput()))); strings.Contains(off, "packeteer_reorder") {
		t.Fatalf("off metrics:\n%s", off)
	}
}
