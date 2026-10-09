package gobgp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// MitigationFlowSpecCfg turns on FlowSpec (RFC 8955) on the mitigation
// announcer. `flowspec: {}` enables drop and rate-limit; Redirect adds
// named redirect-to-VRF targets.
type MitigationFlowSpecCfg struct {
	Redirect []FlowSpecRedirectCfg `yaml:"redirect"`
}

// FlowSpecRedirectCfg is one FlowSpec redirect target: a two-octet-AS
// route target ("asn:value") the edge imports into a VRF.
type FlowSpecRedirectCfg struct {
	Name        string `yaml:"name"`
	RouteTarget string `yaml:"route_target"`
}

// fsTarget is a parsed FlowSpec redirect target.
type fsTarget struct {
	rt       string
	asn      uint16
	localAdm uint32
}

// parseRouteTarget parses "asn:value" with a two-octet AS.
func parseRouteTarget(s string) (uint16, uint32, error) {
	hi, lo, ok := strings.Cut(s, ":")
	if !ok {
		return 0, 0, errors.New(`must be "asn:value"`)
	}
	a, err1 := strconv.ParseUint(hi, 10, 16)
	v, err2 := strconv.ParseUint(lo, 10, 32)
	if err1 != nil || err2 != nil || a == 0 {
		return 0, 0, errors.New("asn must be 1-65535 and value 0-4294967295")
	}
	return uint16(a), uint32(v), nil
}

func (a *MitigationAnnouncer) configureFlowSpec(cfg *MitigationFlowSpecCfg) error {
	if cfg == nil {
		return nil
	}
	a.flowspec = true
	if len(cfg.Redirect) > maxMitigationTargets {
		return fmt.Errorf("flowspec.redirect: at most %d targets", maxMitigationTargets)
	}
	seenRT := map[string]string{}
	for i, r := range cfg.Redirect {
		label := fmt.Sprintf("flowspec.redirect[%d]", i)
		if r.Name == "" || len(r.Name) > maxMitigationName || strings.ContainsAny(r.Name, " \t\r\n/") {
			return fmt.Errorf("%s: name is required, at most %d characters, with no spaces or slashes", label, maxMitigationName)
		}
		if _, dup := a.fsTargets[r.Name]; dup {
			return fmt.Errorf("%s: target %q is listed twice", label, r.Name)
		}
		asn, v, err := parseRouteTarget(r.RouteTarget)
		if err != nil {
			return fmt.Errorf("%s: route_target %q: %w", label, r.RouteTarget, err)
		}
		if prev, dup := seenRT[r.RouteTarget]; dup {
			return fmt.Errorf("%s: route_target %s is already used by %s", label, r.RouteTarget, prev)
		}
		seenRT[r.RouteTarget] = r.Name
		a.fsTargets[r.Name] = fsTarget{rt: r.RouteTarget, asn: asn, localAdm: v}
	}
	return nil
}

// FlowSpecCatalog implements plugin.FlowSpecAnnouncer.
func (a *MitigationAnnouncer) FlowSpecCatalog() plugin.FlowSpecCatalog {
	c := plugin.FlowSpecCatalog{Enabled: a.flowspec, Targets: []plugin.FlowSpecTarget{}}
	for n, t := range a.fsTargets {
		c.Targets = append(c.Targets, plugin.FlowSpecTarget{Name: n, RouteTarget: t.rt})
	}
	sortTargets(c.Targets)
	return c
}

// FlowSpecEnabled reports whether the iBGP sessions must negotiate the
// FlowSpec address families.
func (a *MitigationAnnouncer) FlowSpecEnabled() bool { return a.flowspec }

// AnnounceFlowSpec implements plugin.FlowSpecAnnouncer. It checks the
// allowlist, the shared route cap, the community, and the catalog itself.
func (a *MitigationAnnouncer) AnnounceFlowSpec(ctx context.Context, r plugin.FlowSpecRoute) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv == nil {
		return errors.New("mitigation announcer: not bound to the iBGP speaker")
	}
	path, err := a.flowSpecPath(r)
	if err != nil {
		return err
	}
	key := r.Key()
	if _, on := a.fsPaths[key]; !on && len(a.paths)+len(a.fsPaths) >= a.max {
		return fmt.Errorf("mitigation announcer: flowspec %s refused: max rules (%d) reached", key, a.max)
	}
	if _, err := a.srv.AddPath(ctx, &api.AddPathRequest{Path: path}); err != nil {
		return fmt.Errorf("mitigation announcer: announce flowspec %s: %w", key, err)
	}
	a.fsPaths[key] = path
	a.log.Info("mitigation flowspec announced", "rule", key, "action", r.Action, "target", r.Target, "rate_mbps", r.RateMbps)
	return nil
}

// WithdrawFlowSpec implements plugin.FlowSpecAnnouncer.
func (a *MitigationAnnouncer) WithdrawFlowSpec(ctx context.Context, key string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.withdrawFlowSpecLocked(ctx, key)
}

func (a *MitigationAnnouncer) withdrawFlowSpecLocked(ctx context.Context, key string) error {
	path, ok := a.fsPaths[key]
	if !ok {
		return nil
	}
	if a.srv == nil {
		return errors.New("mitigation announcer: not bound to the iBGP speaker")
	}
	if err := a.srv.DeletePath(ctx, &api.DeletePathRequest{Family: path.Family, Path: path}); err != nil {
		return fmt.Errorf("mitigation announcer: withdraw flowspec %s: %w", key, err)
	}
	delete(a.fsPaths, key)
	a.log.Info("mitigation flowspec withdrew", "rule", key)
	return nil
}

// flowSpecPath checks r and builds its path: the NLRI (destination, then
// source, protocols, ports), the action's extended community, the
// packeteer community, the marker, and NO_EXPORT.
func (a *MitigationAnnouncer) flowSpecPath(r plugin.FlowSpecRoute) (*api.Path, error) {
	if !a.flowspec {
		return nil, errors.New("mitigation announcer: flowspec is not configured")
	}
	dst := r.Destination
	if !dst.IsValid() || dst != dst.Masked() || dst.Bits() == 0 {
		return nil, fmt.Errorf("mitigation announcer: flowspec destination %s is not a valid masked prefix", dst)
	}
	if !covered(a.allow, dst) {
		return nil, fmt.Errorf("mitigation announcer: %s is not in the mitigation allowlist", dst)
	}
	if r.LocalPref == 0 {
		return nil, errors.New("mitigation announcer: local_pref is required")
	}
	if r.Community != a.community {
		return nil, fmt.Errorf("mitigation announcer: flowspec for %s is missing community %s", dst, a.community)
	}
	if err := r.Match.Validate(dst); err != nil {
		return nil, fmt.Errorf("mitigation announcer: flowspec for %s: %w", dst, err)
	}
	var ext bgp.ExtendedCommunityInterface
	switch r.Action {
	case plugin.MitigationFlowSpecDrop:
		if r.Target != "" || r.RateMbps != 0 {
			return nil, errors.New("mitigation announcer: flowspec drop takes no target or rate")
		}
		ext = bgp.NewTrafficRateExtended(0, 0)
	case plugin.MitigationFlowSpecRateLimit:
		if r.Target != "" {
			return nil, errors.New("mitigation announcer: flowspec rate-limit takes no target")
		}
		if !(r.RateMbps > 0 && r.RateMbps <= plugin.MaxFlowSpecRateMbps) {
			return nil, fmt.Errorf("mitigation announcer: rate %v Mbit/s must be above 0 and at most %d", r.RateMbps, plugin.MaxFlowSpecRateMbps)
		}
		// traffic-rate is bytes per second.
		ext = bgp.NewTrafficRateExtended(0, float32(r.RateMbps*1e6/8))
	case plugin.MitigationFlowSpecRedirect:
		t, ok := a.fsTargets[r.Target]
		if !ok {
			return nil, fmt.Errorf("mitigation announcer: unknown flowspec redirect target %q", r.Target)
		}
		if r.RateMbps != 0 {
			return nil, errors.New("mitigation announcer: flowspec redirect takes no rate")
		}
		ext = bgp.NewRedirectTwoOctetAsSpecificExtended(t.asn, t.localAdm)
	default:
		return nil, fmt.Errorf("mitigation announcer: unknown flowspec action %q", r.Action)
	}
	v4 := dst.Addr().Is4()
	prefix := func(p netip.Prefix, source bool) bgp.FlowSpecComponentInterface {
		if v4 {
			ip := bgp.NewIPAddrPrefix(uint8(p.Bits()), p.Addr().String())
			if source {
				return bgp.NewFlowSpecSourcePrefix(ip)
			}
			return bgp.NewFlowSpecDestinationPrefix(ip)
		}
		ip := bgp.NewIPv6AddrPrefix(uint8(p.Bits()), p.Addr().String())
		if source {
			return bgp.NewFlowSpecSourcePrefix6(ip, 0)
		}
		return bgp.NewFlowSpecDestinationPrefix6(ip, 0)
	}
	m := r.Match.Normalize()
	comps := []bgp.FlowSpecComponentInterface{prefix(dst, false)}
	if m.Source.IsValid() {
		comps = append(comps, prefix(m.Source, true))
	}
	if len(m.Protocols) > 0 {
		items := make([]*bgp.FlowSpecComponentItem, 0, len(m.Protocols))
		for _, p := range m.Protocols {
			items = append(items, bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ, uint64(p)))
		}
		comps = append(comps, bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_IP_PROTO, items))
	}
	ports := func(typ bgp.BGPFlowSpecType, rs []plugin.PortRange) {
		if len(rs) == 0 {
			return
		}
		var items []*bgp.FlowSpecComponentItem
		for _, pr := range rs {
			if pr.From == pr.To {
				items = append(items, bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ, uint64(pr.From)))
				continue
			}
			items = append(items,
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_GT_EQ, uint64(pr.From)),
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_AND|bgp.DEC_NUM_OP_LT_EQ, uint64(pr.To)))
		}
		comps = append(comps, bgp.NewFlowSpecComponent(typ, items))
	}
	ports(bgp.FLOW_SPEC_TYPE_DST_PORT, m.DestinationPorts)
	ports(bgp.FLOW_SPEC_TYPE_SRC_PORT, m.SourcePorts)

	var nlri bgp.AddrPrefixInterface
	nh := "0.0.0.0"
	if v4 {
		nlri = bgp.NewFlowSpecIPv4Unicast(comps)
	} else {
		nlri = bgp.NewFlowSpecIPv6Unicast(comps)
		nh = "::"
	}
	comms := []uint32{}
	var large []*bgp.LargeCommunity
	for _, c := range []string{a.community, a.marker} {
		pc, err := parseAnyCommunity(c)
		if err != nil {
			return nil, err
		}
		if pc.large {
			large = append(large, bgp.NewLargeCommunity(pc.ga, pc.d1, pc.d2))
			continue
		}
		comms = append(comms, pc.std)
	}
	comms = append(comms, noExport)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeMpReachNLRI(nh, []bgp.AddrPrefixInterface{nlri}),
		bgp.NewPathAttributeLocalPref(r.LocalPref),
		bgp.NewPathAttributeCommunities(comms),
	}
	if len(large) > 0 {
		attrs = append(attrs, bgp.NewPathAttributeLargeCommunities(large))
	}
	attrs = append(attrs, bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{ext}))
	path, err := apiutil.NewPath(nlri, false, attrs, time.Now())
	if err != nil {
		return nil, fmt.Errorf("mitigation announcer: flowspec for %s: %w", dst, err)
	}
	return path, nil
}
