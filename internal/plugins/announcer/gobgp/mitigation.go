package gobgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Mitigation catalog bounds.
const (
	maxMitigationTargets     = 32
	maxMitigationCommunities = 16
	maxMitigationName        = 64
)

// blackholeCommunity is the well-known BLACKHOLE community (RFC 7999).
const blackholeCommunity = "65535:666"

func init() { plugin.MitigationAnnouncers.Register(TypeName, NewMitigation) }

// MitigationConfig is the mitigation gobgp announcer's config block: a
// marker community, the blackhole next hop and communities, and the
// redirect targets.
type MitigationConfig struct {
	// Marker tags every mitigation route so the edge's import policy can
	// tell it from an outbound improvement. Required.
	Marker    string                  `yaml:"marker"`
	Blackhole *MitigationBlackholeCfg `yaml:"blackhole"`
	Redirect  []MitigationRedirectCfg `yaml:"redirect"`
}

// MitigationBlackholeCfg is the RTBH action. NextHop is the discard
// address the edge routes to null (IPv4); NextHopV6 is the same for IPv6
// prefixes and is optional. Communities default to 65535:666.
type MitigationBlackholeCfg struct {
	NextHop     string   `yaml:"next_hop"`
	NextHopV6   string   `yaml:"next_hop_v6"`
	Communities []string `yaml:"communities"`
}

// MitigationRedirectCfg is one redirect target.
type MitigationRedirectCfg struct {
	Name        string   `yaml:"name"`
	NextHop     string   `yaml:"next_hop"`
	Communities []string `yaml:"communities"`
}

// MitigationAnnouncer announces RTBH and redirect routes on the embedded
// speaker. It shares the speaker and the export policy of the gobgp
// announcer, never opens a session, and tracks only its own paths. It
// checks its allowlist and route cap on every announce, independently of
// the core.
type MitigationAnnouncer struct {
	plugin.Base
	log       *slog.Logger
	marker    string
	bh4, bh6  netip.Addr
	bhComms   []string
	blackhole bool
	targets   map[string]plugin.MitigationTarget

	mu        sync.Mutex
	srv       *server.BgpServer
	community string
	allow     []netip.Prefix
	max       int
	paths     map[netip.Prefix]*api.Path
}

// NewMitigation is the plugin factory. It validates the catalog and does
// not open a BGP session.
func NewMitigation(c plugin.Config, env plugin.Env) (plugin.MitigationAnnouncer, error) {
	var cfg MitigationConfig
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Marker == "" {
		return nil, errors.New("marker is required (the community that tags mitigation routes)")
	}
	if err := checkSteerCommunity(cfg.Marker); err != nil {
		return nil, fmt.Errorf("marker %q: %w", cfg.Marker, err)
	}
	if cfg.Blackhole == nil && len(cfg.Redirect) == 0 {
		return nil, errors.New("configure blackhole, redirect, or both")
	}
	log := env.Logger
	if log == nil {
		log = slog.Default()
	}
	a := &MitigationAnnouncer{log: log, marker: cfg.Marker, targets: map[string]plugin.MitigationTarget{}, paths: map[netip.Prefix]*api.Path{}}
	seenNH := map[netip.Addr]string{}
	useNH := func(label, s string, want4 bool) (netip.Addr, error) {
		nh, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%s: %q is not an IP address", label, s)
		}
		if nh.Is4() != want4 || nh.Is4In6() || nh.IsUnspecified() || nh.IsMulticast() || nh.IsLoopback() {
			return netip.Addr{}, fmt.Errorf("%s: %s is not a usable unicast IPv%d address", label, nh, map[bool]int{true: 4, false: 6}[want4])
		}
		if prev, dup := seenNH[nh]; dup {
			return netip.Addr{}, fmt.Errorf("%s: next hop %s is already used by %s", label, nh, prev)
		}
		seenNH[nh] = label
		return nh, nil
	}
	if b := cfg.Blackhole; b != nil {
		a.blackhole = true
		if b.NextHop == "" {
			return nil, errors.New("blackhole.next_hop is required (the discard address the edge routes to null)")
		}
		nh, err := useNH("blackhole.next_hop", b.NextHop, true)
		if err != nil {
			return nil, err
		}
		a.bh4 = nh
		if b.NextHopV6 != "" {
			if a.bh6, err = useNH("blackhole.next_hop_v6", b.NextHopV6, false); err != nil {
				return nil, err
			}
		}
		comms := b.Communities
		if len(comms) == 0 {
			comms = []string{blackholeCommunity}
		}
		if err := checkMitigationComms("blackhole", comms, cfg.Marker, true); err != nil {
			return nil, err
		}
		a.bhComms = slices.Clone(comms)
	}
	if len(cfg.Redirect) > maxMitigationTargets {
		return nil, fmt.Errorf("redirect: at most %d targets", maxMitigationTargets)
	}
	for i, r := range cfg.Redirect {
		label := fmt.Sprintf("redirect[%d]", i)
		if r.Name == "" || len(r.Name) > maxMitigationName || strings.ContainsAny(r.Name, " \t\r\n/") {
			return nil, fmt.Errorf("%s: name is required, at most %d characters, with no spaces or slashes", label, maxMitigationName)
		}
		if _, dup := a.targets[r.Name]; dup {
			return nil, fmt.Errorf("%s: target %q is listed twice", label, r.Name)
		}
		nh, err := netip.ParseAddr(r.NextHop)
		if err != nil {
			return nil, fmt.Errorf("%s: next_hop %q is not an IP address", label, r.NextHop)
		}
		if nh, err = useNH(label+".next_hop", r.NextHop, nh.Is4()); err != nil {
			return nil, err
		}
		if len(r.Communities) > 0 {
			if err := checkMitigationComms(label, r.Communities, cfg.Marker, false); err != nil {
				return nil, err
			}
		}
		a.targets[r.Name] = plugin.MitigationTarget{Name: r.Name, NextHop: nh, Communities: slices.Clone(r.Communities)}
	}
	return a, nil
}

// checkMitigationComms validates an action's communities. Reserved values
// (0:x, 65535:x) are refused, except BLACKHOLE on the blackhole action.
func checkMitigationComms(label string, comms []string, marker string, blackhole bool) error {
	if len(comms) > maxMitigationCommunities {
		return fmt.Errorf("%s: at most %d communities", label, maxMitigationCommunities)
	}
	seen := map[string]bool{}
	for _, c := range comms {
		if blackhole && c == blackholeCommunity {
			// Allowed: the whole point of RTBH.
		} else if err := checkSteerCommunity(c); err != nil {
			return fmt.Errorf("%s: community %q: %w", label, c, err)
		}
		if c == marker {
			return fmt.Errorf("%s: community %q is the marker", label, c)
		}
		if seen[c] {
			return fmt.Errorf("%s: duplicate community %q", label, c)
		}
		seen[c] = true
	}
	return nil
}

// Catalog implements plugin.MitigationAnnouncer.
func (a *MitigationAnnouncer) Catalog() plugin.MitigationCatalog {
	c := plugin.MitigationCatalog{Blackhole: a.blackhole, BlackholeCommunities: slices.Clone(a.bhComms), Targets: []plugin.MitigationTarget{}}
	for _, nh := range []netip.Addr{a.bh4, a.bh6} {
		if nh.IsValid() {
			c.BlackholeNextHops = append(c.BlackholeNextHops, nh)
		}
	}
	for _, t := range a.targets {
		t.Communities = slices.Clone(t.Communities)
		c.Targets = append(c.Targets, t)
	}
	slices.SortFunc(c.Targets, func(x, y plugin.MitigationTarget) int { return strings.Compare(x.Name, y.Name) })
	return c
}

// Bind attaches the announcer to the RIB view's speaker. The gobgp
// announcer must already be bound: its export policy is what lets tagged
// local routes out. allow and maxRules are the mitigation allowlist and rule
// cap; Announce refuses a prefix outside allow and a new route past
// maxRules.
func (a *MitigationAnnouncer) Bind(srv any, community string, allow []netip.Prefix, maxRules int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := parseCommunity(community); err != nil {
		return fmt.Errorf("mitigation announcer: community: %w", err)
	}
	if community == a.marker {
		return errors.New("mitigation announcer: marker must differ from packeteer_community")
	}
	if slices.Contains(a.bhComms, community) {
		return errors.New("mitigation announcer: blackhole communities list packeteer_community")
	}
	for n, t := range a.targets {
		if slices.Contains(t.Communities, community) {
			return fmt.Errorf("mitigation announcer: redirect target %q lists packeteer_community", n)
		}
	}
	if len(allow) == 0 {
		return errors.New("mitigation announcer: empty allowlist")
	}
	if maxRules < 1 {
		return errors.New("mitigation announcer: max rules must be at least 1")
	}
	s, ok := srv.(*server.BgpServer)
	if !ok || s == nil {
		return errors.New("mitigation announcer: embedded speaker is required")
	}
	if a.srv != nil {
		return errors.New("mitigation announcer: already bound")
	}
	if !hasPolicy(context.Background(), s, policyName) {
		return errors.New("mitigation announcer: the gobgp announcer's export policy is not installed (bind it first)")
	}
	a.srv, a.community, a.max = s, community, maxRules
	for _, p := range allow {
		a.allow = append(a.allow, p.Masked())
	}
	a.log.Info("mitigation announcer bound", "community", community, "marker", a.marker, "max_rules", maxRules,
		"blackhole", a.blackhole, "redirect_targets", len(a.targets))
	return nil
}

// Announce advertises r, replacing any mitigation route for the same
// prefix in place.
func (a *MitigationAnnouncer) Announce(ctx context.Context, r plugin.MitigationRoute) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv == nil {
		return errors.New("mitigation announcer: not bound to the iBGP speaker")
	}
	rt, err := a.route(r)
	if err != nil {
		return err
	}
	if _, on := a.paths[rt.Prefix]; !on && len(a.paths) >= a.max {
		return fmt.Errorf("mitigation announcer: %s refused: max rules (%d) reached", rt.Prefix, a.max)
	}
	path, err := buildPath(rt)
	if err != nil {
		return err
	}
	if _, err := a.srv.AddPath(ctx, &api.AddPathRequest{Path: path}); err != nil {
		return fmt.Errorf("mitigation announcer: announce %s: %w", r.Prefix, err)
	}
	a.paths[rt.Prefix] = path
	a.log.Info("mitigation announced", "prefix", rt.Prefix, "action", r.Action, "target", r.Target, "next_hop", rt.NextHop,
		"communities", strings.Join(rt.Communities, " "))
	return nil
}

// route checks r and builds the announced route: packeteer community,
// marker, then the action's communities. buildPath adds NO_EXPORT.
func (a *MitigationAnnouncer) route(r plugin.MitigationRoute) (plugin.Route, error) {
	if !r.Prefix.IsValid() || r.Prefix != r.Prefix.Masked() {
		return plugin.Route{}, fmt.Errorf("mitigation announcer: prefix %s is not a valid masked prefix", r.Prefix)
	}
	if !covered(a.allow, r.Prefix) {
		return plugin.Route{}, fmt.Errorf("mitigation announcer: %s is not in the mitigation allowlist", r.Prefix)
	}
	if r.LocalPref == 0 {
		return plugin.Route{}, errors.New("mitigation announcer: local_pref is required")
	}
	if r.Community != a.community {
		return plugin.Route{}, fmt.Errorf("mitigation announcer: route for %s is missing community %s", r.Prefix, a.community)
	}
	var nh netip.Addr
	var extra []string
	switch r.Action {
	case plugin.MitigationBlackhole:
		if !a.blackhole {
			return plugin.Route{}, errors.New("mitigation announcer: blackhole is not configured")
		}
		if r.Target != "" {
			return plugin.Route{}, errors.New("mitigation announcer: blackhole takes no target")
		}
		nh, extra = a.bh4, a.bhComms
		if r.Prefix.Addr().Is6() {
			nh = a.bh6
		}
	case plugin.MitigationRedirect:
		t, ok := a.targets[r.Target]
		if !ok {
			return plugin.Route{}, fmt.Errorf("mitigation announcer: unknown redirect target %q", r.Target)
		}
		nh, extra = t.NextHop, t.Communities
	default:
		return plugin.Route{}, fmt.Errorf("mitigation announcer: unknown action %q", r.Action)
	}
	if !nh.IsValid() || nh.Is4() != r.Prefix.Addr().Is4() {
		return plugin.Route{}, fmt.Errorf("mitigation announcer: no %s next hop for %s", r.Action, r.Prefix)
	}
	comms := []string{a.community, a.marker}
	for _, c := range extra {
		if !slices.Contains(comms, c) {
			comms = append(comms, c)
		}
	}
	return plugin.Route{Prefix: r.Prefix, NextHop: nh, LocalPref: r.LocalPref, Communities: comms}, nil
}

func covered(list []netip.Prefix, p netip.Prefix) bool {
	for _, a := range list {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Withdraw removes the mitigation route for p. Withdrawing a prefix that
// was not announced is a no-op.
func (a *MitigationAnnouncer) Withdraw(ctx context.Context, p netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.withdrawLocked(ctx, p.Masked())
}

func (a *MitigationAnnouncer) withdrawLocked(ctx context.Context, p netip.Prefix) error {
	path, ok := a.paths[p]
	if !ok {
		return nil
	}
	if a.srv == nil {
		return errors.New("mitigation announcer: not bound to the iBGP speaker")
	}
	// Delete by path, not UUID: the gobgp announcer's WithdrawAll may
	// already have removed every local path, and this must still succeed.
	if err := a.srv.DeletePath(ctx, &api.DeletePathRequest{Family: familyOf(p), Path: path}); err != nil {
		return fmt.Errorf("mitigation announcer: withdraw %s: %w", p, err)
	}
	delete(a.paths, p)
	a.log.Info("mitigation withdrew", "prefix", p)
	return nil
}

// WithdrawAll removes every mitigation route. Outbound improvements and
// inbound steer routes on the same speaker are left alone.
func (a *MitigationAnnouncer) WithdrawAll(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var errs []error
	for p := range a.paths {
		if err := a.withdrawLocked(ctx, p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Stop withdraws every mitigation route. Graceful restart is never
// enabled, so a process that dies without Stop loses them with the
// session.
func (a *MitigationAnnouncer) Stop(ctx context.Context) error { return a.WithdrawAll(ctx) }
