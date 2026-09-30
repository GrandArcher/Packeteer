package main

import (
	"context"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fedState connects the decision loop to the federation plugin (#30).
// Every method is nil-safe: a nil *fedState is a standalone instance.
// It never announces; what it merges into a decision goes through the
// same allowlist, learned RIB, cap, hold time, and withdraw rules.
type fedState struct {
	cfg     federation.Config
	fed     plugin.Federation
	version string
	mode    string
	maxAge  time.Duration
	maxImps int

	// Set by the decision loop only.
	peers []plugin.PeerState
	usage []plugin.Usage

	mu      sync.Mutex
	local   *plugin.InstanceSnapshot
	commits []federation.CommitStatus
}

// federationConfig is the multi-POP view of cfg.
func federationConfig(cfg *config.Config) federation.Config {
	fc := federation.Config{
		Instance: cfg.Instance, Domain: cfg.Domain,
		InterDCRTT: map[string]time.Duration{}, Remote: map[string]string{},
	}
	for d, rtt := range cfg.InterDCRTT {
		fc.InterDCRTT[d] = rtt
	}
	for _, p := range cfg.Providers {
		if cfg.Remote(p) {
			fc.Remote[p.Name] = p.Domain
		} else {
			fc.Local = append(fc.Local, p.Name)
		}
	}
	for _, g := range cfg.GlobalCommits {
		fc.GlobalCommits = append(fc.GlobalCommits, federation.GlobalCommit{
			Name: g.Name, CommitMbps: g.CommitMbps, Providers: append([]string(nil), g.Providers...),
		})
	}
	return fc
}

func newFedState(cfg *config.Config, plugins *pluginhost.Set) *fedState {
	if plugins == nil || plugins.Federation == nil {
		return nil
	}
	return &fedState{
		cfg: federationConfig(cfg), fed: plugins.Federation.Plugin, version: version, mode: cfg.Mode,
		maxAge: maxResultAge(cfg), maxImps: *cfg.MaxImprovements,
	}
}

// merge reads the peers once for this evaluation and adds their paths
// through providers in other domains to in. Call it after Results,
// ProviderUp, and Native are filled.
func (f *fedState) merge(in *policy.Input, now time.Time) {
	if f == nil {
		return
	}
	f.peers = f.fed.Peers(now)
	f.usage = nil
	federation.Merge(in, f.cfg, f.peers)
}

// commit reads this instance's telemetry (published to peers as is) and,
// for a commit-planning scorer, replaces in.Usage with fresh peers' rows
// and the global commits applied. Call it after merge and after
// fillPlannerInputs.
func (f *fedState) commit(ctx context.Context, in *policy.Input, plugins *pluginhost.Set) {
	if f == nil {
		return
	}
	local := in.Usage
	if !scorerPlans(plugins) {
		local = collectTelemetry(ctx, plugins)
	}
	f.usage = local
	usage, commits := federation.ApplyGlobalCommit(local, f.cfg, f.peers)
	if scorerPlans(plugins) {
		in.Usage = usage
	}
	f.mu.Lock()
	f.commits = commits
	f.mu.Unlock()
}

// publish builds this instance's snapshot from the evaluation just run
// and hands it to the plugin.
func (f *fedState) publish(now time.Time, in policy.Input, imps []policy.Improvement) {
	if f == nil {
		return
	}
	s := federation.Snapshot(f.cfg, federation.SnapshotInput{
		Version: f.version, Mode: f.mode, Now: now, RIBReady: in.RIBReady,
		MaxImprovements: f.maxImps, MaxResultAge: f.maxAge,
		Input: in, Improvements: imps, Usage: f.usage,
	})
	f.fed.Publish(s)
	f.mu.Lock()
	f.local = &s
	f.mu.Unlock()
}

// publishDown tells peers, before the withdraw on shutdown, that this
// instance's providers are no longer usable, so they retire steers onto
// them at their next poll instead of waiting for max_age.
func (f *fedState) publishDown(now time.Time) {
	if f == nil {
		return
	}
	s := federation.Snapshot(f.cfg, federation.SnapshotInput{
		Version: f.version, Mode: f.mode, Now: now, MaxImprovements: f.maxImps,
	})
	f.fed.Publish(s)
	f.mu.Lock()
	f.local = &s
	f.mu.Unlock()
}

// status is the central view for the API.
func (f *fedState) status() federation.Status {
	if f == nil {
		return federation.Status{Peers: []federation.PeerView{}, GlobalCommit: []federation.CommitStatus{}}
	}
	peers := f.fed.Peers(time.Now())
	f.mu.Lock()
	local, commits := f.local, f.commits
	f.mu.Unlock()
	return federation.View(f.cfg, local, peers, commits)
}
