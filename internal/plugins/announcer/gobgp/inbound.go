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

// Inbound catalog bounds.
const (
	maxInboundPrepend     = 10
	maxInboundCommunities = 16
	maxInboundName        = 64
)

func init() { plugin.InboundAnnouncers.Register(TypeName, NewInbound) }

// InboundConfig is the inbound gobgp announcer's config block: a marker
// community and the per-provider action catalog.
type InboundConfig struct {
	// Marker tags every inbound steer route so the edge's import policy
	// can tell it from an outbound improvement. Required.
	Marker    string            `yaml:"marker"`
	Providers []InboundProvider `yaml:"providers"`
}

// InboundProvider is one catalog entry. See plugin.InboundAction.
type InboundProvider struct {
	Provider    string   `yaml:"provider"`
	Name        string   `yaml:"name"`
	Prepend     int      `yaml:"prepend"`
	Withhold    bool     `yaml:"withhold"`
	Communities []string `yaml:"communities"`
}

// InboundAnnouncer re-announces the operator's own prefixes on the embedded
// speaker with the catalog communities. It shares the speaker and the
// export policy of the gobgp announcer, never opens a session, and tracks
// only its own paths.
type InboundAnnouncer struct {
	plugin.Base
	log     *slog.Logger
	marker  string
	actions map[string]plugin.InboundAction

	mu        sync.Mutex
	srv       *server.BgpServer
	community string
	paths     map[netip.Prefix]*api.Path
}

// NewInbound is the plugin factory. It validates the catalog and does not
// open a BGP session.
func NewInbound(c plugin.Config, env plugin.Env) (plugin.InboundAnnouncer, error) {
	var cfg InboundConfig
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Marker == "" {
		return nil, errors.New("marker is required (the community that tags inbound steer routes)")
	}
	if err := checkSteerCommunity(cfg.Marker); err != nil {
		return nil, fmt.Errorf("marker %q: %w", cfg.Marker, err)
	}
	if len(cfg.Providers) == 0 {
		return nil, errors.New("providers: at least one catalog entry is required")
	}
	actions := map[string]plugin.InboundAction{}
	for i, p := range cfg.Providers {
		label := fmt.Sprintf("providers[%d]", i)
		if p.Provider == "" {
			return nil, fmt.Errorf("%s: provider is required", label)
		}
		if env.Providers != nil && !slices.Contains(env.Providers, p.Provider) {
			return nil, fmt.Errorf("%s: provider %q is not configured", label, p.Provider)
		}
		if _, dup := actions[p.Provider]; dup {
			return nil, fmt.Errorf("%s: provider %q is listed twice", label, p.Provider)
		}
		if len(p.Name) > maxInboundName {
			return nil, fmt.Errorf("%s: name is longer than %d characters", label, maxInboundName)
		}
		if p.Prepend < 0 || p.Prepend > maxInboundPrepend {
			return nil, fmt.Errorf("%s: prepend %d must be between 0 and %d", label, p.Prepend, maxInboundPrepend)
		}
		if p.Withhold && p.Prepend != 0 {
			return nil, fmt.Errorf("%s: withhold and prepend are exclusive (a withheld prefix is not sent to the provider at all)", label)
		}
		if len(p.Communities) == 0 || len(p.Communities) > maxInboundCommunities {
			return nil, fmt.Errorf("%s: communities must list 1 to %d communities", label, maxInboundCommunities)
		}
		seen := map[string]bool{}
		for _, c := range p.Communities {
			if err := checkSteerCommunity(c); err != nil {
				return nil, fmt.Errorf("%s: community %q: %w", label, c, err)
			}
			if c == cfg.Marker {
				return nil, fmt.Errorf("%s: community %q is the marker", label, c)
			}
			if seen[c] {
				return nil, fmt.Errorf("%s: duplicate community %q", label, c)
			}
			seen[c] = true
		}
		actions[p.Provider] = plugin.InboundAction{
			Provider: p.Provider, Name: p.Name, Prepend: p.Prepend, Withhold: p.Withhold,
			Communities: append([]string(nil), p.Communities...),
		}
	}
	log := env.Logger
	if log == nil {
		log = slog.Default()
	}
	return &InboundAnnouncer{log: log, marker: cfg.Marker, actions: actions, paths: map[netip.Prefix]*api.Path{}}, nil
}

// checkSteerCommunity accepts an "asn:value" community outside the
// reserved 0:x and 65535:x ranges, so a catalog cannot carry NO_EXPORT,
// NO_ADVERTISE, BLACKHOLE, or any other well-known value.
func checkSteerCommunity(s string) error {
	v, err := parseCommunity(s)
	if err != nil {
		return err
	}
	if hi := v >> 16; hi == 0 || hi == 0xFFFF {
		return errors.New("0:x and 65535:x are reserved")
	}
	return nil
}

// Action implements plugin.InboundAnnouncer.
func (a *InboundAnnouncer) Action(provider string) (plugin.InboundAction, bool) {
	act, ok := a.actions[provider]
	if ok {
		act.Communities = append([]string(nil), act.Communities...)
	}
	return act, ok
}

// Bind attaches the announcer to the RIB view's speaker. The gobgp
// announcer must already be bound to the same speaker with the same
// community: its export policy is what lets tagged local routes out, and
// without it Bind fails instead of announcing into a policy it cannot see.
//
// prefixes are the inbound prefixes. Bind installs an import policy that
// keeps the edge's own copies of exactly those prefixes out of the
// speaker's best-path table, so a low local-pref steer route is still the
// speaker's best and is exported. The RIB view reads the Adj-RIB-In before
// import policy, so learning is unchanged, and every other prefix is
// accepted as before.
func (a *InboundAnnouncer) Bind(srv any, community string, prefixes []netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	pc, err := parseAnyCommunity(community)
	if err != nil {
		return fmt.Errorf("inbound announcer: community: %w", err)
	}
	community = pc.text
	if community == a.marker {
		return errors.New("inbound announcer: marker must differ from packeteer_community")
	}
	for p, act := range a.actions {
		if slices.Contains(act.Communities, community) {
			return fmt.Errorf("inbound announcer: provider %q lists packeteer_community", p)
		}
	}
	s, ok := srv.(*server.BgpServer)
	if !ok || s == nil {
		return errors.New("inbound announcer: embedded speaker is required")
	}
	if a.srv != nil {
		if a.community != community || a.srv != s {
			return errors.New("inbound announcer: already bound")
		}
		return nil
	}
	found := false
	err = s.ListPolicy(context.Background(), &api.ListPolicyRequest{Name: policyName}, func(p *api.Policy) {
		if p.GetName() == policyName {
			found = true
		}
	})
	if err != nil || !found {
		return errors.New("inbound announcer: the gobgp announcer's export policy is not installed (bind it first)")
	}
	if len(prefixes) == 0 {
		return errors.New("inbound announcer: no inbound prefixes")
	}
	if err := installInboundImport(context.Background(), s, prefixes); err != nil {
		return err
	}
	// Steer routes keep their learned next hop and go to every router;
	// the per-router provider rules (#27) must not rewrite or drop them.
	// The set is filled even with no rules yet: a reload can add them.
	if err := s.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_COMMUNITY, Name: passSetName, List: []string{a.marker},
	}}); err != nil {
		return fmt.Errorf("inbound announcer: router pass set: %w", err)
	}
	a.srv, a.community = s, community
	a.log.Info("inbound announcer bound", "community", community, "marker", a.marker, "providers", len(a.actions))
	return nil
}

// Announce advertises r, replacing any steer route for the same prefix
// in place. A replace is one update, not a withdraw and re-announce, so the
// edge does not fall back to its own route between them.
func (a *InboundAnnouncer) Announce(ctx context.Context, r plugin.InboundRoute) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv == nil {
		return errors.New("inbound announcer: not bound to the iBGP speaker")
	}
	rt, err := a.route(r)
	if err != nil {
		return err
	}
	path, err := buildPath(rt)
	if err != nil {
		return err
	}
	if _, err := a.srv.AddPath(ctx, &api.AddPathRequest{Path: path}); err != nil {
		return fmt.Errorf("inbound announcer: announce %s: %w", r.Prefix, err)
	}
	a.paths[rt.Prefix] = path
	a.log.Info("inbound announced", "prefix", rt.Prefix, "next_hop", rt.NextHop, "away", strings.Join(r.Away, ","), "communities", strings.Join(rt.Communities, " "))
	return nil
}

// route checks r and builds the announced route: packeteer community,
// marker, then every action community of Away in order. buildPath adds
// NO_EXPORT.
func (a *InboundAnnouncer) route(r plugin.InboundRoute) (plugin.Route, error) {
	if !r.Prefix.IsValid() || r.Prefix != r.Prefix.Masked() {
		return plugin.Route{}, fmt.Errorf("inbound announcer: prefix %s is not a valid masked prefix", r.Prefix)
	}
	if !r.NextHop.IsValid() || r.NextHop.Is4() != r.Prefix.Addr().Is4() {
		return plugin.Route{}, fmt.Errorf("inbound announcer: next hop %s does not match %s", r.NextHop, r.Prefix)
	}
	if r.LocalPref == 0 {
		return plugin.Route{}, errors.New("inbound announcer: local_pref is required")
	}
	if r.Community != a.community {
		return plugin.Route{}, fmt.Errorf("inbound announcer: route for %s is missing community %s", r.Prefix, a.community)
	}
	if len(r.Away) == 0 {
		return plugin.Route{}, fmt.Errorf("inbound announcer: route for %s steers away from no provider", r.Prefix)
	}
	comms := []string{a.community, a.marker}
	seen := map[string]bool{a.community: true, a.marker: true}
	for _, p := range r.Away {
		act, ok := a.actions[p]
		if !ok {
			return plugin.Route{}, fmt.Errorf("inbound announcer: provider %q has no catalog action", p)
		}
		for _, c := range act.Communities {
			if !seen[c] {
				comms = append(comms, c)
				seen[c] = true
			}
		}
	}
	return plugin.Route{Prefix: r.Prefix, NextHop: r.NextHop, LocalPref: r.LocalPref, Communities: comms}, nil
}

// Withdraw removes the steer route for p. Withdrawing a prefix that was
// not announced is a no-op.
func (a *InboundAnnouncer) Withdraw(ctx context.Context, p netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.withdrawLocked(ctx, p.Masked())
}

func (a *InboundAnnouncer) withdrawLocked(ctx context.Context, p netip.Prefix) error {
	path, ok := a.paths[p]
	if !ok {
		return nil
	}
	if a.srv == nil {
		return errors.New("inbound announcer: not bound to the iBGP speaker")
	}
	// Delete by path, not UUID: the gobgp announcer's WithdrawAll may
	// already have removed every local path, and this must still succeed.
	if err := a.srv.DeletePath(ctx, &api.DeletePathRequest{Family: familyOf(p), Path: path}); err != nil {
		return fmt.Errorf("inbound announcer: withdraw %s: %w", p, err)
	}
	delete(a.paths, p)
	a.log.Info("inbound withdrew", "prefix", p)
	return nil
}

// WithdrawAll removes every inbound steer route. Outbound improvements on
// the same speaker are left alone.
func (a *InboundAnnouncer) WithdrawAll(ctx context.Context) error {
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

// Stop withdraws every steer route. Graceful restart is never enabled, so
// a process that dies without Stop loses them with the session.
func (a *InboundAnnouncer) Stop(ctx context.Context) error { return a.WithdrawAll(ctx) }

const (
	inboundSetName    = "packeteer-inbound-prefixes"
	inboundImportName = "packeteer-inbound-import"
)

// installInboundImport rejects learned (iBGP) paths for the exact inbound
// prefixes from the speaker's global RIB. Local paths and every other
// prefix are accepted.
func installInboundImport(ctx context.Context, srv *server.BgpServer, prefixes []netip.Prefix) error {
	var list []*api.Prefix
	for _, p := range prefixes {
		p = p.Masked()
		list = append(list, &api.Prefix{IpPrefix: p.String(), MaskLengthMin: uint32(p.Bits()), MaskLengthMax: uint32(p.Bits())})
	}
	if err := srv.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_PREFIX, Name: inboundSetName, Prefixes: list,
	}}); err != nil {
		return fmt.Errorf("inbound announcer: prefix set: %w", err)
	}
	pol := &api.Policy{
		Name: inboundImportName,
		Statements: []*api.Statement{{
			Name: "packeteer-inbound-learned",
			Conditions: &api.Conditions{
				PrefixSet: &api.MatchSet{Type: api.MatchSet_ANY, Name: inboundSetName},
				RouteType: api.Conditions_ROUTE_TYPE_INTERNAL,
			},
			Actions: &api.Actions{RouteAction: api.RouteAction_REJECT},
		}},
	}
	if err := srv.AddPolicy(ctx, &api.AddPolicyRequest{Policy: pol}); err != nil {
		return fmt.Errorf("inbound announcer: import policy: %w", err)
	}
	if err := srv.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name:          "global",
		Direction:     api.PolicyDirection_IMPORT,
		Policies:      []*api.Policy{{Name: inboundImportName}},
		DefaultAction: api.RouteAction_ACCEPT,
	}}); err != nil {
		return fmt.Errorf("inbound announcer: import assignment: %w", err)
	}
	return nil
}
