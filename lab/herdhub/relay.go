package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/herd"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// startRelay starts the seed node: the herd pull API of the node in cfgPath
// with no records, pinned to the node keys of the entries in dir that
// verify, and a peer list of every entry file in dir.
func startRelay(cfgPath, dir string, logger *log.Logger) (*herd.Server, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	if !cfg.HerdOn() {
		return nil, fmt.Errorf("%s: herd is not enabled", cfgPath)
	}
	node, err := herd.OpenNode(cfg.Herd.KeyFile)
	if err != nil {
		return nil, err
	}
	docs, err := readEntries(dir)
	if err != nil {
		return nil, err
	}
	peers := pinnedMembers(docs, time.Now())
	if len(peers) == 0 {
		return nil, fmt.Errorf("%s: no entry verifies, so no member could connect", dir)
	}
	slogger := slog.New(slog.NewTextHandler(logger.Writer(), nil))
	srv := herd.NewServer(herd.ServerOptions{
		Cfg: cfg.Herd, ASN: cfg.ASN, Node: node, Store: emptyStore{}, RIB: emptyRIB{}, Rules: herd.NewRules(cfg.Herd, nil),
		Peers: peers, Log: slogger, Trips: &herd.Trips{},
		Relay: func() []herd.Relayed {
			docs, err := readEntries(dir)
			if err != nil {
				logger.Printf("herdhub: relay: %v", err)
			}
			out := make([]herd.Relayed, len(docs))
			for i, d := range docs {
				out[i] = herd.Relayed{Entry: d}
			}
			return out
		},
	})
	if err := srv.Start(); err != nil {
		return nil, err
	}
	logger.Printf("herdhub: seed node %s (AS%d) relays %d entries, %d member keys pinned", node.ID(), cfg.ASN, len(docs), len(peers))
	return srv, nil
}

// readEntries reads every *.json file in dir, in name order. A file that is
// not JSON is skipped: a peer list carries JSON documents only.
func readEntries(dir string) ([]json.RawMessage, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var out []json.RawMessage
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			return out, err
		}
		if json.Valid(b) {
			out = append(out, b)
		}
	}
	return out, nil
}

// pinnedMembers is the node keys of the entries that verify at now.
func pinnedMembers(docs []json.RawMessage, now time.Time) map[string]ed25519.PublicKey {
	keys := map[string]ed25519.PublicKey{}
	for _, d := range docs {
		e, err := herd.CheckEntry(d, now)
		if err != nil {
			continue
		}
		for _, n := range e.Nodes {
			if k, err := config.ParseHerdKey(n.Key); err == nil {
				keys[herd.KeyID(k)] = k
			}
		}
	}
	return keys
}

// emptyStore holds no herd records: the seed node shares nothing.
type emptyStore struct{}

func (emptyStore) PutHerdRecords(context.Context, []plugin.HerdRecord) (int, error) { return 0, nil }
func (emptyStore) HerdRecords(context.Context, plugin.HerdQuery) ([]plugin.HerdRecord, error) {
	return nil, nil
}
func (emptyStore) DeleteHerdBefore(context.Context, time.Time) (int, error) { return 0, nil }
func (emptyStore) TrimHerd(context.Context, bool, int64) (int, error)       { return 0, nil }
func (emptyStore) HerdStats(context.Context) (plugin.HerdStats, error) {
	return plugin.HerdStats{}, nil
}

// emptyRIB has no routes, so nothing could be served even if stored.
type emptyRIB struct{}

func (emptyRIB) Ready() bool                                   { return false }
func (emptyRIB) Exact(netip.Prefix) (rib.Route, bool)          { return rib.Route{}, false }
func (emptyRIB) ProviderPaths(netip.Prefix, string) [][]uint32 { return nil }
func (emptyRIB) Routes() []rib.Route                           { return nil }
