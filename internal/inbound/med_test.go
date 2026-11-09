package inbound

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// medConfig has two links to one transit (AS 64496) and a second transit.
// Each link's catalog action is a MED on its session (#303).
func medConfig() (Config, *fakeAnn) {
	cfg := baseConfig(config.ModeInject)
	cfg.Providers = []string{"link-1", "link-2", "transit-b"}
	cfg.ASN = map[string]uint32{"link-1": 64496, "link-2": 64496, "transit-b": 64497}
	ann := newFakeAnn("transit-b")
	ann.actions["link-1"] = plugin.InboundAction{Provider: "link-1", MED: 100, Communities: []string{"64512:1301"}}
	ann.actions["link-2"] = plugin.InboundAction{Provider: "link-2", MED: 100, Communities: []string{"64512:1302"}}
	return cfg, ann
}

func TestMEDSteerMovesInboundToTheOtherLink(t *testing.T) {
	cfg, ann := medConfig()
	c := mustNew(t, cfg, ann, readyRIB())
	ch := c.Evaluate(start, usage(start, map[string]float64{"link-1": 150, "link-2": 20, "transit-b": 20}))
	if len(ch) != 1 || ch[0].Steer.Provider != "link-1" || ch[0].Steer.Action.MED != 100 {
		t.Fatalf("steer = %+v", ch)
	}
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := ann.routes[own]; !slices.Equal(r.Away, []string{"link-1"}) {
		t.Fatalf("route = %+v", r)
	}

	// link-2 over commit too: a MED on both links of AS 64496 would move
	// nothing, so it is blocked while link-1 is steered.
	now := start.Add(time.Minute)
	if ch := c.Evaluate(now, usage(now, map[string]float64{"link-1": 150, "link-2": 150, "transit-b": 20})); len(ch) != 0 {
		t.Fatalf("second MED steer = %+v", ch)
	}
	st := c.Status()
	if len(st.Blocked) != 1 || st.Blocked[0].Provider != "link-2" || st.Blocked[0].Reason != "med: every other link to AS64496 is steered, so a MED would move nothing" {
		t.Fatalf("blocked = %+v", st.Blocked)
	}
}
