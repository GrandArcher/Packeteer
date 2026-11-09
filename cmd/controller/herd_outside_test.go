package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/linkout"
	"github.com/GrandArcher/Packeteer/internal/rpki"
)

func outsideCfg(o config.HerdOutside) *config.Config {
	return &config.Config{Herd: &config.Herd{Enabled: true, Outside: o}}
}

func TestHerdOutsideSourcesAreIndependent(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	atlas := config.HerdAtlas{Enabled: true, Measurements: []int{1001}, Refresh: time.Hour}
	for name, tc := range map[string]struct {
		o     config.HerdOutside
		want  string
		atlas bool
	}{
		"none":  {config.HerdOutside{}, "", false},
		"atlas": {config.HerdOutside{Atlas: atlas}, "atlas", true},
		"ris":   {config.HerdOutside{RIS: true}, "ris", false},
		"rpki":  {config.HerdOutside{RPKI: true}, "rpki", false},
		"links": {config.HerdOutside{Links: true}, "links", false},
		"all":   {config.HerdOutside{Atlas: atlas, RIS: true, RPKI: true, Links: true}, "atlas,ris,rpki,links", true},
	} {
		t.Run(name, func(t *testing.T) {
			set, a := newHerdOutside(outsideCfg(tc.o), nil, rpki.NewSet(nil), linkout.New(linkout.Config{}), log)
			if got := strings.Join(set.IDs(), ","); got != tc.want {
				t.Errorf("sources = %q, want %q", got, tc.want)
			}
			if (a != nil) != tc.atlas {
				t.Errorf("atlas loop = %v, want %v", a != nil, tc.atlas)
			}
		})
	}
}
