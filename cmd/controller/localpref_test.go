package main

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestLocalPrefTables(t *testing.T) {
	n := uint32(300)
	st := uint32(400)
	cm := uint32(220)
	cost := uint32(210)
	pb := uint32(350)
	cfg := &config.Config{
		LocalPref: 250,
		LocalPrefCause: config.LocalPrefCauses{
			Performance: &n, Static: &st, Commit: &cm, Cost: &cost,
		},
		Providers: []config.Provider{
			{Name: "transit-a"},
			{Name: "transit-b", LocalPref: &pb},
		},
	}
	cause, provider := localPrefTables(cfg)
	if cause[plugin.CausePerformance] != 300 || cause[plugin.CauseStatic] != 400 ||
		cause[plugin.CauseCommit] != 220 || cause[plugin.CauseCost] != 210 || len(cause) != 4 {
		t.Fatalf("cause = %v", cause)
	}
	if len(provider) != 1 || provider["transit-b"] != 350 {
		t.Fatalf("provider = %v", provider)
	}
	if _, ok := provider["transit-a"]; ok {
		t.Fatal("unset provider local_pref was copied")
	}
	got := formatLocalPrefOverrides(cfg)
	want := " cause=performance:300,static:400,commit:220,cost:210 provider=transit-b:350"
	if got != want {
		t.Fatalf("check line %q, want %q", got, want)
	}
	if cause, provider = localPrefTables(&config.Config{LocalPref: 250}); cause != nil || provider != nil {
		t.Fatalf("no overrides: cause %v provider %v", cause, provider)
	}
	if s := formatLocalPrefOverrides(&config.Config{}); s != "" {
		t.Fatalf("empty overrides formatted %q", s)
	}
	// The -check line keeps the global value in front of any suffix.
	line := "announce: gobgp local_pref=250" + got
	if !strings.Contains(line, "announce: gobgp local_pref=250") || !strings.Contains(line, "provider=transit-b:350") {
		t.Fatalf("line = %s", line)
	}
}
