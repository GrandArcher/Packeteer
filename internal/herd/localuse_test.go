package herd

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// attributionOf is this node's attribution through AS64520 for AS64513
// once the given peer rows are stored next to this node's degraded one.
func attributionOf(t *testing.T, down map[string]bool, rows func(f *fleet)) []Attribution {
	t.Helper()
	f := newFleet(t)
	f.put("", "US", 64520, 64513, "", time.Minute, 60, 90)
	rows(f)
	b := f.board()
	b.Down = down
	ev, err := b.Events(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ev.Events {
		if e.Kind == kindOrigin && e.Value == "64513" {
			return e.Here
		}
	}
	t.Fatalf("no event for AS64513: %+v", ev.Events)
	return nil
}

// "My upstream or the destination" (#686): this node sees AS64513 degraded
// through AS64520 and the other members' rows point at the destination,
// the provider, or this edge.
func TestAttributionPointsAtDestinationProviderOrThisEdge(t *testing.T) {
	m := time.Minute
	tests := []struct {
		name string
		down map[string]bool
		rows func(f *fleet)
		want Attribution
	}{
		{"bad only here", nil, func(f *fleet) {
			f.put(peerA, "DE", 64520, 64513, "", m, 0, 20)
			f.put(peerB, "JP", 64521, 64513, "", m, 0, 30)
		}, Attribution{PointsAt: PointsThisEdge, ViaReporting: 1, ElsewhereReporting: 1}},
		{"bad through the same provider ASN only", nil, func(f *fleet) {
			f.put(peerA, "DE", 64520, 64513, "", m, 40, 20)
			f.put(peerB, "JP", 64520, 64513, "", m, 30, 30)
			f.put(peerC, "BR", 64521, 64513, "", m, 0, 30)
		}, Attribution{PointsAt: PointsProvider, ViaReporting: 2, ViaDegraded: 2, ElsewhereReporting: 1}},
		{"bad from every vantage and provider", nil, func(f *fleet) {
			f.put(peerA, "DE", 64520, 64513, "", m, 40, 20)
			f.put(peerB, "JP", 64521, 64513, "", m, 100, 30)
			f.put(peerC, "BR", 64522, 64513, "", m, 25, 30)
		}, Attribution{PointsAt: PointsDestination, ViaReporting: 1, ViaDegraded: 1, ElsewhereReporting: 2, ElsewhereDegraded: 2}},
		{"no other member measures it", nil, func(*fleet) {}, Attribution{PointsAt: PointsUnknown}},
		{"rows disagree", nil, func(f *fleet) {
			f.put(peerA, "DE", 64520, 64513, "", m, 0, 20)
			f.put(peerB, "JP", 64521, 64513, "", m, 50, 30)
		}, Attribution{PointsAt: PointsUnknown, ViaReporting: 1, ElsewhereReporting: 1, ElsewhereDegraded: 1}},
		// A member through two other providers that sees loss through one
		// of them counts once, as degraded.
		{"one member through two other providers", nil, func(f *fleet) {
			f.put(peerA, "DE", 64520, 64513, "", m, 40, 20)
			f.put(peerB, "JP", 64521, 64513, "", m, 0, 30)
			f.put(peerB, "JP", 64522, 64513, "", m, 30, 30)
		}, Attribution{PointsAt: PointsDestination, ViaReporting: 1, ViaDegraded: 1, ElsewhereReporting: 1, ElsewhereDegraded: 1}},
		// A down-weighted member's loss is shown, not counted.
		{"down-weighted member", map[string]bool{peerA: true}, func(f *fleet) {
			f.put(peerA, "DE", 64520, 64513, "", m, 90, 20)
			f.put(peerB, "JP", 64521, 64513, "", m, 0, 30)
		}, Attribution{PointsAt: PointsThisEdge, ElsewhereReporting: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := attributionOf(t, tt.down, tt.rows)
			tt.want.ProviderASN = 64520
			if len(got) != 1 || got[0] != tt.want {
				t.Errorf("here = %+v, want [%+v]", got, tt.want)
			}
		})
	}
}

// A target this node measures without loss carries no attribution, and
// one it sees degraded through two provider ASNs carries one for each.
func TestAttributionOnlyForThisNodesDegradedProviders(t *testing.T) {
	f := newFleet(t)
	f.seed()
	ev, err := f.board().Events(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ev.Events {
		switch e.Value {
		case "64510":
			// This node sees AS64510 lose 40 % through AS64520; A through
			// AS64520 and B through AS64521 see loss, C through AS64521
			// and B through AS64520 do not.
			want := Attribution{ProviderASN: 64520, PointsAt: PointsUnknown, ViaReporting: 2, ViaDegraded: 1, ElsewhereReporting: 2, ElsewhereDegraded: 1}
			if len(e.Here) != 1 || e.Here[0] != want {
				t.Errorf("AS64510 here = %+v, want [%+v]", e.Here, want)
			}
		case "198.51.100.0/24":
			if len(e.Here) != 0 {
				t.Errorf("a route this node does not measure has here = %+v", e.Here)
			}
		}
	}
	got := attributionOf(t, nil, func(f *fleet) {
		f.put("", "US", 64521, 64513, "", time.Minute, 30, 90)
		f.put(peerA, "DE", 64521, 64513, "", time.Minute, 50, 20)
	})
	if len(got) != 2 || got[0].ProviderASN != 64520 || got[0].PointsAt != PointsDestination || got[1].ProviderASN != 64521 || got[1].PointsAt != PointsProvider {
		t.Errorf("here = %+v, want AS64520 destination and AS64521 provider", got)
	}
}

// A down-weighted member (#686) keeps its rows in every view, marked, and
// is left out of every count: the world view, the hints, and the members
// row says why.
func TestDownWeightedMemberIsShownAndNotCounted(t *testing.T) {
	f := newFleet(t)
	f.seed()
	b := f.board()
	b.Down = map[string]bool{peerA: true}
	ev, err := b.Events(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ev.Events {
		if e.Value != "64510" {
			continue
		}
		// Without A: this node and B see loss, C does not.
		if e.Reporting != 3 || e.Degraded != 2 || len(e.Vantages) != 5 {
			t.Errorf("AS64510 = %d of %d with %d rows, want 2 of 3 with all 5 rows", e.Degraded, e.Reporting, len(e.Vantages))
		}
		for _, v := range e.Vantages {
			if v.DownWeighted != (v.ASN == 64502) || v.Counted == v.DownWeighted {
				t.Errorf("vantage %+v: only A is down-weighted and uncounted", v)
			}
		}
		if hs := hintsFrom(Events{Events: []EventRow{e}}, hintRIB()); len(hs) != 1 || hs[0].Vantages != 1 {
			t.Errorf("hints = %+v, want one counting B only, not the down-weighted member", hs)
		}
	}
	v, err := BuildView(context.Background(), b, "origin_asn=64510")
	if err != nil {
		t.Fatal(err)
	}
	shown := false
	for _, x := range v.Vantages {
		shown = shown || (x.ASN == 64502 && x.DownWeighted && x.Records == 1)
	}
	if !shown {
		t.Errorf("the down-weighted member's vantage is not shown: %+v", v.Vantages)
	}
	o, err := b.Overview(context.Background(), NodeStatus{Peers: []PeerStatus{{KeyID: peerA, ASN: 64502}, {KeyID: peerB, ASN: 64503}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range o.Members {
		if m.DownWeighted != (m.Member == peerA) {
			t.Errorf("member %+v", m)
		}
	}
}

// The outage second opinion (#686) counts the other members that count,
// once per ASN, whose latest row names the ASN as origin, provider, or on
// its AS path, and those that see it degraded. This node's own rows and a
// down-weighted member's are left out.
func TestOpinionsCountOtherMembersThatNameTheASN(t *testing.T) {
	f := newFleet(t)
	f.seed()
	b := f.board()
	ops, err := b.opinions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint32]Opinion{
		// Origin of A's, B's (twice), and C's rows; A and B see loss.
		64510: {Reporting: 3, Degraded: 2},
		// Provider of A's rows and of one of B's, which sees no loss
		// through it.
		64520: {Reporting: 2, Degraded: 1},
		64521: {Reporting: 2, Degraded: 1},
		// Only on A's path (p1).
		64530: {Reporting: 2, Degraded: 1},
		// Origin of A's and C's route rows; A sees loss.
		64512: {Reporting: 2, Degraded: 1},
	}
	for asn, w := range want {
		if ops[asn] != w {
			t.Errorf("AS%d = %+v, want %+v", asn, ops[asn], w)
		}
	}
	if op, ok := ops[64599]; ok {
		t.Errorf("an ASN no row names has an opinion %+v", op)
	}
	b.Down = map[string]bool{peerA: true, peerB: true}
	ops, _ = b.opinions(context.Background())
	if got := ops[64510]; got != (Opinion{Reporting: 1, Degraded: 0}) {
		t.Errorf("AS64510 with A and B down-weighted = %+v, want none of 1", got)
	}
}

// herdWith builds a Herd for cfg whose key is node's, so served members can
// pin it before it starts.
func herdWith(t *testing.T, cfg *config.Herd, node *Node, asn uint32) *Herd {
	t.Helper()
	h, err := New(Options{Cfg: cfg, ASN: asn, Store: testStore(t), RIB: &fakeRIB{ready: true}, Rules: defaultRules(),
		Now: func() time.Time { return t0 }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if h.node.ID() != node.ID() {
		t.Fatal("herd did not load the given key")
	}
	t.Cleanup(h.pull.Close)
	return h
}

// A blocked member (#686), named by its ASN, key, or endpoint, is never
// asked for records and never shown; GET /api/herd lists it under blocked.
// A member blocked by ASN alone is asked for its status, which is how its
// ASN is learned. The block is this node's view only: a node without it
// pulls the same members.
func TestBlockedMembersAreNeitherPulledNorShown(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "x.key")
	xNode, err := LoadNode(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	other := newMember(t, 64505, nil)
	byASN, byKey, byURL, open := newMember(t, 64502, nil), newMember(t, 64503, nil), newMember(t, 64504, nil), newMember(t, 64506, nil)
	for _, m := range []*member{byASN, byKey, byURL, open} {
		m.cfg.Share.Discovery = config.HerdListing
		m.serve(xNode, other.node)
		m.seedN(3, 64510)
	}
	cfg := testCfg(t, func(h *config.Herd) {
		h.KeyFile = keyFile
		h.Peers = nil
		for _, m := range []*member{byASN, byKey, byURL, open} {
			h.Peers = append(h.Peers, config.HerdPeer{URL: m.url(), Key: m.node.PublicKey()})
		}
		h.Block = config.HerdMembers{ASNs: []uint32{64502}, Keys: []string{byKey.node.ID()}, Endpoints: []string{byURL.url()}}
	})
	x := herdWith(t, cfg, xNode, 64501)
	x.pull.Round(context.Background())

	for _, m := range []*member{byASN, byKey, byURL} {
		if n := len(pulledRows(t, &member{t: t, store: x.o.Store}, m.node)); n != 0 {
			t.Errorf("AS%d: %d rows pulled from a blocked member", m.asn, n)
		}
		for _, a := range m.auditLog() {
			t.Errorf("AS%d served a blocked puller: %+v", m.asn, a)
		}
	}
	if n := len(pulledRows(t, &member{t: t, store: x.o.Store}, open.node)); n != 3 {
		t.Errorf("pulled %d rows from the member nobody blocks, want 3", n)
	}
	st := x.Status(context.Background())
	if len(st.Peers) != 1 || st.Peers[0].KeyID != open.node.ID() {
		t.Errorf("peers = %+v, want only the unblocked member", st.Peers)
	}
	blocked := map[string]PeerStatus{}
	for _, p := range st.Blocked {
		blocked[p.KeyID] = p
	}
	if len(blocked) != 3 || blocked[byASN.node.ID()].ASN != 64502 || blocked[byKey.node.ID()].ASN != 0 || blocked[byURL.node.ID()].ASN != 0 {
		t.Errorf("blocked = %+v, want the three, with only the ASN-blocked one's status read", st.Blocked)
	}
	for _, p := range st.Blocked {
		if p.Pulled != 0 || p.Failures != 0 || !p.LastOK.IsZero() {
			t.Errorf("blocked peer %+v was pulled or counted as failing", p)
		}
	}
	v, err := x.Vantages(context.Background(), "origin_asn=64510")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Vantages) != 1 || v.Vantages[0].ASN != 64506 {
		t.Errorf("vantages = %+v, want only the unblocked member", v.Vantages)
	}

	// The outage opinions count only the member nobody blocks; before the
	// first refresh there are none.
	if op, ok := x.Opinion(64510); ok {
		t.Errorf("opinion before a refresh = %+v", op)
	}
	x.refreshOpinions(context.Background())
	if op, ok := x.Opinion(64510); !ok || op != (Opinion{Reporting: 1, Degraded: 1}) {
		t.Errorf("AS64510 opinion = %+v, %v; want 1 of 1 (the unblocked member sees 25 %% loss)", op, ok)
	}

	// Another node, with no block, pulls the member x blocks.
	p := other.puller(byKey)
	p.Round(context.Background())
	if n := len(pulledRows(t, other, byKey.node)); n != 3 {
		t.Errorf("a node without the block pulled %d rows, want 3", n)
	}
}
