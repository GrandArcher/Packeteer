package main

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/commit"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// volSrc counts volume reads. block waits on ctx so a detached timeout is visible.
type volSrc struct {
	plugin.Base
	calls int
	block bool
	mbps  float64
	pfx   netip.Prefix
}

func (v *volSrc) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }

func (v *volSrc) Volumes(ctx context.Context) ([]plugin.PrefixVolume, error) {
	v.calls++
	if v.block {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bytes := uint64(v.mbps * 1e6 / 8)
	return []plugin.PrefixVolume{{Prefix: v.pfx, Bytes: bytes, Window: time.Second}}, nil
}

func scorerSet(t *testing.T, kind string, sources ...*volSrc) *pluginhost.Set {
	t.Helper()
	var s plugin.Scorer
	var err error
	switch kind {
	case "weighted":
		s, err = weighted.New(plugin.Config{}, plugin.Env{})
	case "commit":
		s, err = commit.New(plugin.Config{}, plugin.Env{})
	default:
		t.Fatalf("scorer %s", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	set := &pluginhost.Set{Scorer: &pluginhost.Instance[plugin.Scorer]{Name: kind, Type: kind, Plugin: s}}
	for _, src := range sources {
		set.Sources = append(set.Sources, pluginhost.Instance[plugin.TargetSource]{Name: "vol", Type: "static", Plugin: src})
	}
	return set
}

func TestPlannerInputsSkipWeightedScorer(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	src := &volSrc{mbps: 80, pfx: p}
	var in policy.Input
	fillPlannerInputs(context.Background(), &in, scorerSet(t, "weighted", src))
	if src.calls != 0 || in.VolumeMbps != nil || in.Usage != nil {
		t.Fatalf("weighted scorer read volumes: calls %d in %+v", src.calls, in)
	}
}

func TestPlannerInputsReadCommitVolumes(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	low := &volSrc{mbps: 40, pfx: p}
	high := &volSrc{mbps: 80, pfx: p}
	var in policy.Input
	fillPlannerInputs(context.Background(), &in, scorerSet(t, "commit", low, high))
	if low.calls != 1 || high.calls != 1 {
		t.Fatalf("calls %d %d", low.calls, high.calls)
	}
	if in.VolumeMbps[p] != 80 {
		t.Fatalf("volume %v", in.VolumeMbps)
	}
}

func TestCollectVolumesHonorsCallerContext(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	src := &volSrc{block: true, pfx: p}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	got := collectVolumes(ctx, scorerSet(t, "commit", src))
	if time.Since(start) > time.Second {
		t.Fatalf("collectVolumes ignored a cancelled context (%s)", time.Since(start))
	}
	if len(got) != 0 || src.calls > 1 {
		t.Fatalf("got %v calls %d", got, src.calls)
	}
}
