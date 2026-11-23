package main

import (
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// The settings editor, and the federation push that goes through it, never
// turn offload_aware.run: enforce on; a running config already at enforce
// can still be edited.
func TestCheckOffloadEnforceUnchanged(t *testing.T) {
	enforcing := &config.Config{OffloadAware: &config.OffloadAware{Enabled: true, Run: config.OffloadRunEnforce}}
	dry := &config.Config{OffloadAware: &config.OffloadAware{Enabled: true, Run: config.OffloadRunDryRun}}
	disabled := &config.Config{OffloadAware: &config.OffloadAware{Run: config.OffloadRunEnforce}}
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
		"disabled enforce":   {off, disabled, false},
	} {
		if err := checkOffloadEnforceUnchanged(tc.running, tc.next); (err != nil) != tc.refused {
			t.Errorf("%s: err = %v, refused = %v", name, err, tc.refused)
		}
	}
}
