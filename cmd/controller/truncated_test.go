package main

import (
	"context"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeTruncating struct {
	plugin.Base
	n map[string]uint64
}

func (f *fakeTruncating) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }
func (f *fakeTruncating) Truncated() map[string]uint64                     { return f.n }

func TestTruncatedSumsSources(t *testing.T) {
	set := withSources(&pluginhost.Set{},
		&fakeTruncating{n: map[string]uint64{"max_prefixes": 5}},
		&fakeTruncating{n: map[string]uint64{"max_prefixes": 2, "max_flows": 9}},
		&fakeClassifier{}, // a source with no caps
	)
	got := truncated(set)
	if len(got) != 2 || got["max_prefixes"] != 7 || got["max_flows"] != 9 {
		t.Fatalf("truncated = %v, want max_prefixes 7 and max_flows 9", got)
	}
	if got := truncated(nil); len(got) != 0 {
		t.Fatalf("nil set = %v", got)
	}
}
