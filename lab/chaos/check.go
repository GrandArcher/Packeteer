package main

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// Invariant names, as they appear in the report.
const (
	invLearnedRIB    = "learned-rib"
	invDocumentation = "documentation"
	invGR            = "graceful-restart"
	invHABoth        = "ha-both"
	invDownRoutes    = "down-session-routes"
	invSIGTERM       = "sigterm-withdraw"
	invSIGKILL       = "sigkill-hold"
	invConfig        = "config-mode"
)

// Violation is one broken safety invariant.
type Violation struct {
	At        time.Time `json:"at"`
	Invariant string    `json:"invariant"`
	Detail    string    `json:"detail"`
	// Count is the number of samples that showed it.
	Count int `json:"count"`
}

var docPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// isDocPrefix reports whether prefix s lies inside a documentation block.
func isDocPrefix(s string) bool {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return false
	}
	for _, d := range docPrefixes {
		if d.Bits() <= p.Bits() && d.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// isLabASN reports whether a is a documentation or private ASN.
func isLabASN(a uint32) bool {
	return a >= 64496 && a <= 64511 || a >= 65536 && a <= 65551 || a >= 64512 && a <= 65534
}

// checkSample checks the invariants one read of the edge must hold on its
// own. peers are the Packeteer instances' addresses.
func checkSample(s Sample, peers []string) []Violation {
	var out []Violation
	add := func(inv, format string, args ...any) {
		out = append(out, Violation{At: s.At, Invariant: inv, Detail: fmt.Sprintf(format, args...)})
	}
	for _, prefix := range sortedKeys(s.Routes) {
		if !isDocPrefix(prefix) {
			add(invDocumentation, "the edge holds %s, outside the documentation blocks", prefix)
		}
		paths := s.Routes[prefix]
		fromPacketeer := slices.ContainsFunc(paths, func(p string) bool { return slices.Contains(peers, p) })
		learned := slices.ContainsFunc(paths, func(p string) bool { return !slices.Contains(peers, p) })
		if fromPacketeer && !learned {
			add(invLearnedRIB, "Packeteer announces %s, which the edge has from no other source", prefix)
		}
	}
	for _, addr := range sortedKeys(s.Peers) {
		p := s.Peers[addr]
		if !isLabASN(p.RemoteAS) {
			add(invDocumentation, "neighbor %s has AS %d, not a documentation or private ASN", addr, p.RemoteAS)
		}
	}
	var holding []string
	for _, addr := range peers {
		p := s.Peers[addr]
		if p.Established() && p.GR {
			add(invGR, "the session with %s carries the graceful-restart capability", addr)
		}
		if s.Holds(addr) {
			holding = append(holding, addr)
		}
	}
	if len(holding) > 1 {
		add(invHABoth, "the edge holds Packeteer routes from %s at once", strings.Join(holding, " and "))
	}
	return out
}

// downGrace is how long the edge may still list a peer's routes after
// that session left Established: FRR clears them from a work queue, and
// the table and the neighbor state are two reads.
const downGrace = 3 * time.Second

// downTracker fails a session that is not Established while the edge
// keeps its routes for longer than downGrace, which is what graceful
// restart would do.
type downTracker struct {
	since map[string]time.Time
}

func (d *downTracker) check(s Sample, peers []string) []Violation {
	if d.since == nil {
		d.since = map[string]time.Time{}
	}
	var out []Violation
	for _, addr := range peers {
		if s.Peers[addr].Established() || !s.Holds(addr) {
			delete(d.since, addr)
			continue
		}
		first, ok := d.since[addr]
		if !ok {
			d.since[addr] = s.At
			continue
		}
		if s.At.Sub(first) > downGrace {
			out = append(out, Violation{At: s.At, Invariant: invDownRoutes,
				Detail: fmt.Sprintf("the session with %s is %s and the edge still holds its routes %v later", addr, s.Peers[addr].State, s.At.Sub(first).Round(time.Second))})
			delete(d.since, addr)
		}
	}
	return out
}

// checkConfigs loads each config under test and the shipped example. A
// config may announce only in an inject-lab profile, and then only
// documentation prefixes; the example must stay observe.
func checkConfigs(p Profile, example string, at time.Time) []Violation {
	var out []Violation
	add := func(format string, args ...any) {
		out = append(out, Violation{At: at, Invariant: invConfig, Detail: fmt.Sprintf(format, args...)})
	}
	for _, path := range p.Configs {
		cfg, err := config.Load(path)
		if err != nil {
			add("%v", err)
			continue
		}
		if !isLabASN(cfg.ASN) {
			add("%s: asn %d is not a documentation or private ASN", path, cfg.ASN)
		}
		// Outbound and inbound announce inside allowlist.prefixes;
		// mitigation has its own allowlist.
		lists := map[string][]string{}
		if cfg.Mode == config.ModeInject || cfg.InboundMode() == config.ModeInject {
			lists["allowlist.prefixes"] = cfg.Allowlist.Prefixes
		}
		if cfg.MitigationMode() == config.ModeInject {
			lists["mitigation.allowlist"] = cfg.Mitigation.Allowlist
		}
		if len(lists) == 0 {
			continue
		}
		if !p.InjectLab {
			add("%s: mode inject in profile %s, which is not an inject-lab profile", path, p.Name)
		}
		for _, name := range sortedKeys(lists) {
			if len(lists[name]) == 0 {
				add("%s: mode inject with an empty %s", path, name)
			}
			for _, a := range lists[name] {
				if !isDocPrefix(a) {
					add("%s: %s entry %s is not a documentation prefix", path, name, a)
				}
			}
		}
	}
	cfg, err := config.Load(example)
	switch {
	case err != nil:
		add("%v", err)
	case cfg.Mode != config.ModeObserve:
		add("%s: mode %s, the shipped example must stay observe", example, cfg.Mode)
	}
	return out
}

// checkLiveMode checks the mode an instance reports while it runs.
func checkLiveMode(p Profile, id, mode string, at time.Time) []Violation {
	if mode != config.ModeInject || p.InjectLab {
		return nil
	}
	return []Violation{{At: at, Invariant: invConfig, Detail: fmt.Sprintf("%s runs mode inject in profile %s, which is not an inject-lab profile", id, p.Name)}}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
