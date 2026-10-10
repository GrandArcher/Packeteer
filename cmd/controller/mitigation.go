package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/geoip"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// newMitigation returns nil when threat mitigation (#28) is not
// configured. It refuses a catalog whose next hop is a provider's next
// hop: a mitigation route must never look like an outbound improvement to
// the per-router export rules or to the edge.
func newMitigation(cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger) (*mitigation.Controller, error) {
	m := cfg.Mitigation
	if m == nil {
		return nil, nil
	}
	var ann plugin.MitigationAnnouncer
	if plugins.Mitigation != nil {
		ann = plugins.Mitigation.Plugin
		provNH := map[netip.Addr]string{}
		for _, p := range cfg.Providers {
			if nh, err := parseAddr(p.NextHop); err == nil {
				provNH[nh.Unmap()] = p.Name
			}
		}
		for _, nh := range ann.Catalog().NextHops() {
			if name, dup := provNH[nh.Unmap()]; dup {
				return nil, fmt.Errorf("mitigation.announcer: next hop %s is provider %s's next hop", nh, name)
			}
		}
	}
	var geo mitigation.GeoIP
	if m.GeoIPDB != "" {
		db, err := geoip.Open(m.GeoIPDB)
		if err != nil {
			return nil, fmt.Errorf("mitigation.geoip_db: %w", err)
		}
		geo = db
	}
	return mitigation.New(mitigation.Config{
		Geo:        geo,
		Mode:       m.Mode,
		Allowlist:  m.MitigationAllowlist(),
		MaxRules:   m.MaxRules,
		DefaultTTL: m.DefaultTTL,
		MaxTTL:     m.MaxTTL,
		LocalPref:  m.LocalPref,
		Community:  cfg.PacketeerCommunity,
		Leader:     haLeader(plugins),
	}, ann, log.With("component", "mitigation"))
}

// mitigationFlowSpec reports whether the iBGP sessions must carry the
// FlowSpec families: mitigation injects and its announcer has FlowSpec.
// observe never changes what the sessions negotiate.
func mitigationFlowSpec(cfg *config.Config, plugins *pluginhost.Set) bool {
	if cfg.MitigationMode() != config.ModeInject || plugins == nil || plugins.Mitigation == nil {
		return false
	}
	fs, ok := plugins.Mitigation.Plugin.(plugin.FlowSpecAnnouncer)
	return ok && fs.FlowSpecCatalog().Enabled
}

// setMitigationRIB gives the controller the RIB view once it exists.
func setMitigationRIB(mit *mitigation.Controller, view *rib.View) error {
	if mit == nil {
		return nil
	}
	if view == nil {
		return mit.SetRIB(nil)
	}
	return mit.SetRIB(ribGate{view})
}

// bindMitigation attaches the mitigation announcer to the speaker when
// mitigation injects, with its own allowlist and rule cap. It runs after
// the gobgp announcer has installed its export policy.
func bindMitigation(cfg *config.Config, plugins *pluginhost.Set, srv any) error {
	if cfg.MitigationMode() != config.ModeInject {
		return nil
	}
	if plugins.Mitigation == nil {
		return errors.New("mitigation: inject requires mitigation.announcer")
	}
	b, ok := plugins.Mitigation.Plugin.(interface {
		Bind(any, string, []netip.Prefix, int) error
	})
	if !ok {
		return fmt.Errorf("mitigation: announcer %T cannot publish on the embedded iBGP speaker", plugins.Mitigation.Plugin)
	}
	return b.Bind(srv, cfg.PacketeerCommunity, cfg.Mitigation.MitigationAllowlist(), cfg.Mitigation.MaxRules)
}

// runMitigation expires rules and syncs mitigation routes. It runs after
// the outbound and inbound syncs in the same round, so a prefix a new rule
// holds has already been released by them. It returns the rule changes
// since the last round, for events and history.
func runMitigation(now time.Time, mit *mitigation.Controller, log *slog.Logger) ([]mitigation.Change, error) {
	if mit == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := mit.Sync(ctx, now)
	if err != nil {
		log.Error("mitigation announce", "err", err)
	}
	return mit.Changes(), err
}

// mitigationRecorder is where mitigation history goes (*history.Recorder).
type mitigationRecorder interface {
	Mitigation(plugin.MitigationRecord)
}

// recordMitigations writes each change's rule state to history.
func recordMitigations(rec mitigationRecorder, changes []mitigation.Change) {
	for _, c := range changes {
		rec.Mitigation(mitigation.Record(c))
	}
}

// mitigationControl is the ops API's view of the controller. poke runs a
// round at once, so a new or removed rule reaches the edge without waiting
// for the probe interval.
type mitigationControl struct {
	mit  *mitigation.Controller
	poke func()
}

func (m mitigationControl) Status() mitigation.Status { return m.mit.Status() }

func (m mitigationControl) Add(r mitigation.Request) (mitigation.Rule, error) {
	rule, err := m.mit.Add(r, time.Now())
	if err == nil {
		m.poke()
	}
	return rule, err
}

func (m mitigationControl) Remove(id string) bool {
	ok := m.mit.Remove(id)
	if ok {
		m.poke()
	}
	return ok
}

// wireMitigationCandidates gives the Protection form's prefix picker the
// learned prefixes inside the mitigation allowlist (#131). It only reads
// the RIB view; the add call still checks the allowlist and the learned
// RIB, and only inject announces.
func wireMitigationCandidates(srv *httpapi.Server, mit *mitigation.Controller, view *rib.View) {
	if srv == nil || mit == nil {
		return
	}
	srv.SetMitigationCandidates(func(q string, limit int) ([]string, bool, bool) {
		if view == nil || !view.Ready() {
			return nil, false, false
		}
		var allow []netip.Prefix
		for _, s := range mit.Status().Allowlist {
			if p, err := netip.ParsePrefix(s); err == nil {
				allow = append(allow, p)
			}
		}
		var keep func(netip.Prefix) bool
		if q != "" {
			keep = func(p netip.Prefix) bool { return strings.Contains(p.String(), q) }
		}
		got, trunc := view.LearnedWithin(allow, keep, limit)
		out := make([]string, len(got))
		for i, p := range got {
			out[i] = p.String()
		}
		return out, trunc, true
	})
}
