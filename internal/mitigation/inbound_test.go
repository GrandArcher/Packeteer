package mitigation

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// speaker is the embedded GoBGP speaker as v3.37 treats local path-ID 0
// paths: one path per prefix, an add replaces whatever path is there, and
// a delete by path removes the prefix's path whoever added it. The gobgp
// lab test TestSharedPrefixImplicitReplaceAndDeleteByPath shows the same
// on a real speaker.
type speaker map[netip.Prefix]string

// inboundOnSpeaker is the inbound announcer on the shared speaker.
type inboundOnSpeaker struct {
	plugin.Base
	sp speaker
}

func (a *inboundOnSpeaker) Action(p string) (plugin.InboundAction, bool) {
	return plugin.InboundAction{Provider: p, Communities: []string{"64512:1102"}}, true
}

func (a *inboundOnSpeaker) Announce(_ context.Context, r plugin.InboundRoute) error {
	a.sp[r.Prefix] = "inbound"
	return nil
}

func (a *inboundOnSpeaker) Withdraw(_ context.Context, p netip.Prefix) error {
	delete(a.sp, p)
	return nil
}

func (a *inboundOnSpeaker) WithdrawAll(context.Context) error {
	for p, who := range a.sp {
		if who == "inbound" {
			delete(a.sp, p)
		}
	}
	return nil
}

// mitOnSpeaker is the mitigation announcer on the shared speaker.
type mitOnSpeaker struct {
	*fakeAnn
	sp speaker
}

func (a *mitOnSpeaker) Announce(ctx context.Context, r plugin.MitigationRoute) error {
	a.sp[r.Prefix] = "mitigation"
	return a.fakeAnn.Announce(ctx, r)
}

func (a *mitOnSpeaker) Withdraw(ctx context.Context, p netip.Prefix) error {
	delete(a.sp, p)
	return a.fakeAnn.Withdraw(ctx, p)
}

// TestRuleAddedMidRoundWaitsForInbound is SAFE-01 of #486: a rule for a
// prefix inbound steers is added between the inbound and the mitigation
// Sync of one round. Announcing it at once would replace the steer route
// on the speaker, and the steer's withdraw next round would then remove
// the mitigation route while the controller still counts it on the wire.
// With the inbound check the rule waits one round and the prefix carries
// exactly one Packeteer path throughout.
func TestRuleAddedMidRoundWaitsForInbound(t *testing.T) {
	ctx := context.Background()
	for _, check := range []bool{false, true} {
		sp := speaker{}
		mann := &mitOnSpeaker{fakeAnn: newFakeAnn(), sp: sp}
		mit, err := New(testConfig(config.ModeInject), mann, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := mit.SetRIB(&fakeRIB{ready: true, learned: map[netip.Prefix]bool{other: true}}); err != nil {
			t.Fatal(err)
		}
		inb, err := inbound.New(inbound.Config{
			Mode: config.ModeInject, Prefixes: []netip.Prefix{other}, Allowlist: []netip.Prefix{other},
			Community: "64512:666", LocalPref: 1, MaxImprovements: 5,
			HoldTime: 5 * time.Minute, TTL: time.Hour, MaxAge: 5 * time.Minute,
			Providers: []string{"transit-a", "transit-b"},
			Excluded:  mit.Holds,
		}, &inboundOnSpeaker{sp: sp}, inboundRIB{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if check {
			mit.SetInbound(inb.OnWire)
		}
		inb.Evaluate(t0, []plugin.Usage{
			{Provider: "transit-a", CommitMbps: 100, Samples: 10, InMbps95: 150, OutMbps95: 10, Updated: t0},
			{Provider: "transit-b", CommitMbps: 100, Samples: 10, InMbps95: 20, OutMbps95: 10, Updated: t0},
		})
		round := func(now time.Time) {
			t.Helper()
			if err := inb.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			if err := mit.Sync(ctx, now); err != nil {
				t.Fatal(err)
			}
		}

		if err := inb.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		if sp[other] != "inbound" || !inb.OnWire(other) {
			t.Fatalf("check %v: speaker %v; want the inbound steer", check, sp)
		}
		if _, err := mit.Add(Request{Prefix: other, Action: plugin.MitigationBlackhole, TTL: 10 * time.Minute}, t0); err != nil {
			t.Fatal(err)
		}
		if err := mit.Sync(ctx, t0); err != nil {
			t.Fatal(err)
		}
		if r := mit.Status().Rules[0]; check && (r.Announced || r.Pending != pendingInbound || len(sp) != 1 || sp[other] != "inbound") {
			t.Fatalf("mid-round rule = %+v, speaker %v; want it pending behind the steer", r, sp)
		}
		round(t0.Add(time.Second))
		round(t0.Add(2 * time.Second))

		if !check {
			// The hazard the check closes: the controller counts a route
			// the speaker no longer has.
			if len(sp) != 0 || mit.Active() != 1 {
				t.Fatalf("no check: speaker %v, mitigation active %d; want the route lost under a live count", sp, mit.Active())
			}
			continue
		}
		if len(sp) != 1 || sp[other] != "mitigation" || mit.Active() != 1 || inb.OnWire(other) {
			t.Fatalf("speaker %v, mitigation active %d, inbound on %v; want exactly the mitigation path", sp, mit.Active(), inb.OnWire(other))
		}
		if r := mit.Status().Rules[0]; !r.Announced || r.Pending != "" {
			t.Fatalf("rule = %+v", r)
		}
	}
}

type inboundRIB struct{}

func (inboundRIB) Ready() bool { return true }
func (inboundRIB) NextHop(netip.Prefix) (netip.Addr, bool) {
	return netip.MustParseAddr("192.0.2.1"), true
}
