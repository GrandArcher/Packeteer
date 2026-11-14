package policy

import (
	"errors"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// FromConfig is the decision config for cfg. A reload builds a fresh one
// and installs it with SetConfig; the next Decide uses it. Prefixes here
// were already validated by config.Load.
func FromConfig(cfg *config.Config) (Config, error) {
	if cfg == nil {
		return Config{}, errors.New("no config")
	}
	max := 0
	if cfg.MaxImprovements != nil {
		max = *cfg.MaxImprovements
	}
	pc := Config{
		Mode:            cfg.Mode,
		MinLossDeltaPct: cfg.Thresholds.MinLossDeltaPct,
		MinRTTDelta:     time.Duration(cfg.Thresholds.MinRTTDeltaMs * float64(time.Millisecond)),
		MinRTTDeltaPct:  cfg.Thresholds.MinRTTDeltaPct,
		ConfirmRounds:   cfg.Thresholds.ConfirmRounds,
		HoldTime:        cfg.HoldTime,
		MaxImprovements: max,
		// A result older than ~3 rounds is stale. The decision loop
		// re-checks this on a ticker even when no round completes.
		MaxResultAge:        cfg.MaxResultAge(),
		Excluded:            map[string]bool{},
		RPKIAvoidInvalid:    cfg.RPKIOn() && cfg.RPKI.AvoidInvalid,
		IRRPreferRegistered: cfg.IRROn() && cfg.IRR.PreferRegistered,
		RequireEvidence:     cfg.Thresholds.RequireEvidence,
		MEDTieBreak:         cfg.Thresholds.MEDOn(),
		MEDMargin:           cfg.Thresholds.MEDMarginOrDefault(),
	}
	if cfg.ImprovementTTL > 0 {
		pc.ImprovementTTL = cfg.ImprovementTTL
	}
	if f := cfg.FlapQuarantine; !f.Disabled {
		pc.Flap = FlapConfig{MaxFlips: f.MaxFlips, Window: f.Window, Cooldown: f.Cooldown, MaxCooldown: f.MaxCooldown}
	}
	ported := map[string]bool{}
	for _, ex := range cfg.Exchanges {
		if ex.Port != nil {
			ported[ex.Name] = true
			pc.Ports = append(pc.Ports, PortPolicy{Name: ex.Name, CapacityMbps: ex.Port.CapacityMbps, CommitMbps: ex.Port.CommitMbps})
		}
	}
	for _, p := range cfg.Providers {
		if p.Exclude {
			pc.Excluded[p.Name] = true
		}
		pp := ProviderPolicy{
			Name: p.Name, Group: p.Group, Precedence: p.Precedence, CCDisable: p.CCDisable,
			CapacityThresholdPct: p.InterfaceCapacityThresholdPct,
		}
		if ported[p.Exchange] {
			pp.Port = p.Exchange
		}
		if p.Cost != nil {
			pp.Cost, pp.HasCost = *p.Cost, true
		}
		pc.Providers = append(pc.Providers, pp)
	}
	for _, s := range cfg.Allowlist.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Config{}, err
		}
		pc.Allowlist = append(pc.Allowlist, p)
	}
	return pc, nil
}
