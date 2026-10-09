package main

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestCommunityTables(t *testing.T) {
	cfg := &config.Config{
		PacketeerCommunity: "64512:666",
		LocalPref:          250,
		CommunitiesCause: config.CommunityCauses{
			Performance: []string{"64512:100", "64512:1:1"},
			Static:      []string{"64512:200"},
			Commit:      []string{"64512:300"},
			Cost:        []string{"64512:1:40"},
		},
		Providers: []config.Provider{
			{Name: "transit-a"},
			{Name: "transit-b", Communities: []string{"64512:200", "64512:1:50"}},
		},
	}
	cause, provider := communityTables(cfg)
	if len(cause[plugin.CausePerformance]) != 2 || cause[plugin.CausePerformance][0] != "64512:100" ||
		cause[plugin.CauseStatic][0] != "64512:200" || cause[plugin.CauseCommit][0] != "64512:300" ||
		cause[plugin.CauseCost][0] != "64512:1:40" || len(cause) != 4 {
		t.Fatalf("cause = %v", cause)
	}
	if len(provider) != 1 || strings.Join(provider["transit-b"], "+") != "64512:200+64512:1:50" {
		t.Fatalf("provider = %v", provider)
	}
	got := formatCommunityOverrides(cfg)
	want := " communities=performance:64512:100+64512:1:1,static:64512:200,commit:64512:300,cost:64512:1:40 provider=transit-b:64512:200+64512:1:50"
	if got != want {
		t.Fatalf("check suffix %q, want %q", got, want)
	}
	if cause, provider = communityTables(&config.Config{}); cause != nil || provider != nil {
		t.Fatalf("no extras: cause %v provider %v", cause, provider)
	}
	if s := formatCommunityOverrides(&config.Config{}); s != "" {
		t.Fatalf("empty extras formatted %q", s)
	}
	line := "announce: gobgp local_pref=250" + formatLocalPrefOverrides(&config.Config{LocalPref: 250}) + got
	if !strings.Contains(line, "announce: gobgp local_pref=250") || !strings.Contains(line, "communities=performance:64512:100+64512:1:1") {
		t.Fatalf("line = %s", line)
	}
}
