package main

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
)

const offloadEditBase = `mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 200
hold_time: 15m
http:
  config_editor: true
thresholds:
  min_loss_delta_pct: 1.0
  min_rtt_delta_ms: 15
bgp:
  neighbors:
    - address: 192.0.2.1
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
allowlist:
  prefixes: [198.51.100.0/24]
announcer:
  type: gobgp
`

const offloadEditBlock = `offload_aware:
  enabled: true
  run: RUN
  routers:
    - neighbor: 192.0.2.1
      profile: mikrotik
      capacity: 1000
`

// The editor, and the federation push that goes through it, never turn
// offload_aware.run: enforce on; a file already at enforce can still be edited.
func TestConfigEditorRefusesOffloadEnforce(t *testing.T) {
	block := func(run string) string { return strings.Replace(offloadEditBlock, "RUN", run, 1) }
	ed, _ := editorFor(t, offloadEditBase)

	if res := ed.Check([]byte(offloadEditBase + block("dry_run"))); !res.Valid {
		t.Fatalf("dry_run refused: %+v", res)
	}
	enforce := offloadEditBase + block("enforce")
	res := ed.Check([]byte(enforce))
	if res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), "offload_aware.run: enforce cannot be set through the config editor") {
		t.Fatalf("enforce: %+v", res)
	}
	if _, _, err := ed.Save([]byte(enforce), configedit.Hash([]byte(offloadEditBase)), true); err == nil {
		t.Fatal("enforce saved")
	}

	cfg, err := config.Parse([]byte(enforce))
	if err != nil {
		t.Fatal(err)
	}
	ed.SetRunning(cfg)
	edited := strings.Replace(enforce, "hold_time: 15m", "hold_time: 20m", 1)
	if res := ed.Check([]byte(edited)); !res.Valid {
		t.Fatalf("an unrelated edit of a file already at enforce refused: %+v", res)
	}
}

func TestCheckOffloadEnforceUnchanged(t *testing.T) {
	enforcing := &config.Config{OffloadAware: &config.OffloadAware{Enabled: true, Run: config.OffloadRunEnforce}}
	dry := &config.Config{OffloadAware: &config.OffloadAware{Enabled: true, Run: config.OffloadRunDryRun}}
	off := &config.Config{}
	for name, tc := range map[string]struct {
		running, next *config.Config
		refused       bool
	}{
		"off to enforce":     {off, enforcing, true},
		"dry_run to enforce": {dry, enforcing, true},
		"enforce stays":      {enforcing, enforcing, false},
		"enforce to dry_run": {enforcing, dry, false},
		"off stays":          {off, off, false},
	} {
		if err := checkOffloadEnforceUnchanged(tc.running, tc.next); (err != nil) != tc.refused {
			t.Errorf("%s: err = %v, refused = %v", name, err, tc.refused)
		}
	}
}
