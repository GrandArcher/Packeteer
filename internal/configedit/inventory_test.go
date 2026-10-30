package configedit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const inventoryBase = `# lab edge
mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  # primary transit
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
    local_pref: 200
    communities: ["64496:100"]
  - name: legacy
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
`

func provider(t *testing.T, cfg *config.Config, name string) config.Provider {
	t.Helper()
	for _, p := range cfg.Providers {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no provider %s", name)
	return config.Provider{}
}

func TestPlanInventoryUpdatesAddsAndKeepsTheRest(t *testing.T) {
	res := plugin.InventoryResult{
		Providers: []plugin.InventoryProvider{
			{Name: "peer-b", ASN: 64497, Type: "peer", SourceIP: "192.0.2.13", NextHop: "192.0.2.3", Communities: []string{"64497:1"}},
			{Name: "transit-a", ASN: 64496, Type: "transit", NextHop: "192.0.2.9", Communities: []string{"64496:100", "64496:200"}},
			{Name: "stub", ASN: 64498},
		},
		Skipped: []plugin.InventorySkip{{Name: "broken", Reason: "next_hop \"x\" is not a valid IP address"}},
	}
	plan, err := PlanInventory([]byte(inventoryBase), res)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 2 || plan.Changes[0].Name != "peer-b" || plan.Changes[0].Action != "add" || plan.Changes[1].Name != "transit-a" || plan.Changes[1].Action != "update" {
		t.Fatalf("changes %+v", plan.Changes)
	}
	got := map[string]FieldChange{}
	for _, f := range plan.Changes[1].Fields {
		got[f.Field] = f
	}
	if f := got["next_hop"]; f.Old != "192.0.2.1" || f.New != "192.0.2.9" {
		t.Fatalf("next_hop %+v", f)
	}
	if f := got["communities"]; f.Old != "64496:100" || f.New != "64496:100,64496:200" {
		t.Fatalf("communities %+v", f)
	}
	if f := got["asn"]; f.Old != "" || f.New != "64496" {
		t.Fatalf("asn %+v", f)
	}
	if _, touched := got["source_ip"]; touched {
		t.Fatal("source_ip is not in the inventory record and must not change")
	}
	if len(plan.Skipped) != 2 || plan.Skipped[0].Name != "broken" || plan.Skipped[1].Name != "stub" || !strings.Contains(plan.Skipped[1].Reason, "needs next_hop and source_ip") {
		t.Fatalf("skipped %+v", plan.Skipped)
	}
	if len(plan.NotInInventory) != 1 || plan.NotInInventory[0] != "legacy" {
		t.Fatalf("not in inventory %v", plan.NotInInventory)
	}

	cfg, err := config.Parse(plan.YAML)
	if err != nil {
		t.Fatal(err)
	}
	a := provider(t, cfg, "transit-a")
	if a.NextHop != "192.0.2.9" || a.SourceIP != "192.0.2.11" || a.ASN != 64496 || a.Type != "transit" || len(a.Communities) != 2 || a.LocalPref == nil || *a.LocalPref != 200 {
		t.Fatalf("transit-a %+v", a)
	}
	b := provider(t, cfg, "peer-b")
	if b.ASN != 64497 || b.Type != "peer" || b.NextHop != "192.0.2.3" || b.SourceIP != "192.0.2.13" {
		t.Fatalf("peer-b %+v", b)
	}
	if l := provider(t, cfg, "legacy"); l.NextHop != "192.0.2.2" {
		t.Fatalf("legacy changed: %+v", l)
	}
	if cfg.Mode != config.ModeObserve || len(cfg.Providers) != 3 {
		t.Fatalf("mode %s providers %d", cfg.Mode, len(cfg.Providers))
	}
	text := string(plan.YAML)
	for _, keep := range []string{"# lab edge", "# primary transit", `packeteer_community: "64512:666"`} {
		if !strings.Contains(text, keep) {
			t.Errorf("lost %q:\n%s", keep, text)
		}
	}
	if !strings.Contains(plan.Diff, "+") || !strings.Contains(plan.Diff, "192.0.2.9") || len(plan.ID) != 12 {
		t.Fatalf("diff %q id %q", plan.Diff, plan.ID)
	}
	var out bytes.Buffer
	plan.Format(&out)
	for _, want := range []string{"~ transit-a", "next_hop: 192.0.2.1 -> 192.0.2.9", "+ peer-b", "! stub: skipped", ". not in the inventory, left as they are: legacy", "plan id: " + plan.ID} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("format lacks %q:\n%s", want, out.String())
		}
	}
}

// Planning against the file the plan produced finds nothing left to do, so
// what the plan showed is exactly what apply changes.
func TestPlanInventoryIsIdempotent(t *testing.T) {
	res := plugin.InventoryResult{Providers: []plugin.InventoryProvider{
		{Name: "transit-a", ASN: 64496, NextHop: "192.0.2.9", Communities: []string{"64496:200"}},
		{Name: "peer-b", ASN: 64497, SourceIP: "192.0.2.13", NextHop: "192.0.2.3"},
	}}
	first, err := PlanInventory([]byte(inventoryBase), res)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanInventory(first.YAML, res)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed() || !bytes.Equal(second.YAML, first.YAML) || second.Diff != "" {
		t.Fatalf("second plan changes %+v", second.Changes)
	}
	if len(second.Unchanged) != 2 {
		t.Fatalf("unchanged %v", second.Unchanged)
	}
	var out bytes.Buffer
	second.Format(&out)
	if !strings.Contains(out.String(), "the config already matches the inventory") || strings.Contains(out.String(), "plan id") {
		t.Fatalf("format %q", out.String())
	}
}

func TestPlanInventoryLeavesAMatchingFileByteForByte(t *testing.T) {
	res := plugin.InventoryResult{Providers: []plugin.InventoryProvider{{Name: "transit-a", NextHop: "192.0.2.1"}}}
	plan, err := PlanInventory([]byte(inventoryBase), res)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Changed() || string(plan.YAML) != inventoryBase {
		t.Fatalf("changed %v", plan.Changed())
	}
}

func TestPlanInventoryRefusesAResultThatDoesNotValidate(t *testing.T) {
	// A next hop of the other address family fails the provider checks.
	res := plugin.InventoryResult{Providers: []plugin.InventoryProvider{{Name: "transit-a", NextHop: "2001:db8::1"}}}
	if _, err := PlanInventory([]byte(inventoryBase), res); err == nil || !strings.Contains(err.Error(), "does not fit the config") || !strings.Contains(err.Error(), "same address family") {
		t.Fatalf("err %v", err)
	}
	if _, err := PlanInventory([]byte("mode: observe\n"), plugin.InventoryResult{}); err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Fatalf("invalid current config: %v", err)
	}
	// The packeteer community may not be reused as a provider community.
	res = plugin.InventoryResult{Providers: []plugin.InventoryProvider{{Name: "transit-a", Communities: []string{"64512:666"}}}}
	if _, err := PlanInventory([]byte(inventoryBase), res); err == nil || !strings.Contains(err.Error(), "duplicates packeteer_community") {
		t.Fatalf("err %v", err)
	}
}
