// Package gobgp is the in-process announcer. It publishes routes on the
// embedded GoBGP speaker owned by the RIB view (the same iBGP sessions), and
// it never opens a second session.
//
// Every announced route carries the configured community and the well-known
// NO_EXPORT community. The speaker's export policy accepts only local routes
// that have the configured community and rejects everything else, so learned
// routes are never reflected. Graceful restart is not enabled: Stop withdraws
// every Packeteer route, and a dead process drops the session.
package gobgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "gobgp"

// noExport is the well-known NO_EXPORT community (RFC 1997).
const noExport uint32 = 0xFFFFFF01

const (
	setName    = "packeteer-community"
	policyName = "packeteer-export"
)

func init() { plugin.Announcers.Register(TypeName, New) }

// Config is the gobgp announcer's config block. It is empty on purpose:
// local-pref and the community are controller settings (see docs/PLUGINS.md),
// and the plugin refuses routes that do not carry them. The announced
// prefix is the exact one the controller learned from the RIB.
type Config struct{}

// Announcer publishes routes on an existing GoBGP speaker.
type Announcer struct {
	plugin.Base
	log *slog.Logger

	mu        sync.Mutex
	srv       *server.BgpServer
	community string
	paths     map[netip.Prefix][]byte // announced prefix -> AddPath UUID
}

// New is the plugin factory. It does not open a BGP session.
func New(c plugin.Config, env plugin.Env) (plugin.Announcer, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	log := env.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Announcer{log: log, paths: map[netip.Prefix][]byte{}}, nil
}

// Bind attaches the announcer to the RIB view's speaker and installs an
// export policy that accepts only local routes tagged with community.
// community is the configured packeteer community ("asn:value").
func (a *Announcer) Bind(srv any, community string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := parseCommunity(community); err != nil {
		return fmt.Errorf("gobgp announcer: community: %w", err)
	}
	s, ok := srv.(*server.BgpServer)
	if !ok || s == nil {
		return errors.New("gobgp announcer: embedded speaker is required")
	}
	if a.srv != nil {
		if a.community != community || a.srv != s {
			return errors.New("gobgp announcer: already bound")
		}
		return nil
	}
	if err := installExportPolicy(context.Background(), s, community); err != nil {
		return err
	}
	a.srv = s
	a.community = community
	a.log.Info("announcer bound", "community", community)
	return nil
}

// Announce advertises r. It replaces any route already announced for the
// same prefix. The route must carry the bound community and a non-zero
// local preference; NO_EXPORT is always added.
func (a *Announcer) Announce(ctx context.Context, r plugin.Route) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv == nil {
		return errors.New("gobgp announcer: not bound to the iBGP speaker")
	}
	if err := a.validate(r); err != nil {
		return err
	}
	path, err := buildPath(r)
	if err != nil {
		return err
	}
	if uuid, ok := a.paths[r.Prefix]; ok {
		if err := a.srv.DeletePath(ctx, &api.DeletePathRequest{Uuid: uuid, Family: familyOf(r.Prefix)}); err != nil {
			return fmt.Errorf("gobgp announcer: replace %s: %w", r.Prefix, err)
		}
		delete(a.paths, r.Prefix)
	}
	resp, err := a.srv.AddPath(ctx, &api.AddPathRequest{Path: path})
	if err != nil {
		return fmt.Errorf("gobgp announcer: announce %s: %w", r.Prefix, err)
	}
	a.paths[r.Prefix] = resp.GetUuid()
	a.log.Info("announced", "prefix", r.Prefix, "next_hop", r.NextHop, "local_pref", r.LocalPref, "provider", r.Provider)
	return nil
}

// Withdraw removes one announced prefix. Withdrawing a prefix that was not
// announced is a no-op.
func (a *Announcer) Withdraw(ctx context.Context, p netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv == nil {
		return errors.New("gobgp announcer: not bound to the iBGP speaker")
	}
	p = p.Masked()
	uuid, ok := a.paths[p]
	if !ok {
		return nil
	}
	if err := a.srv.DeletePath(ctx, &api.DeletePathRequest{Uuid: uuid, Family: familyOf(p)}); err != nil {
		return fmt.Errorf("gobgp announcer: withdraw %s: %w", p, err)
	}
	delete(a.paths, p)
	a.log.Info("withdrew", "prefix", p)
	return nil
}

// WithdrawAll removes every locally originated path (v4 and v6). Learned
// routes are not local, so they stay.
func (a *Announcer) WithdrawAll(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv == nil {
		return nil
	}
	var errs []error
	for _, fam := range []*api.Family{v4Family, v6Family} {
		if err := a.srv.DeletePath(ctx, &api.DeletePathRequest{Family: fam}); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("gobgp announcer: withdraw all: %w", err)
	}
	n := len(a.paths)
	a.paths = map[netip.Prefix][]byte{}
	a.log.Info("withdrew all", "prefixes", n)
	return nil
}

// Stop withdraws every announced route. The BGP session itself belongs to
// the RIB view and is not shut down here. Graceful restart is never enabled.
func (a *Announcer) Stop(ctx context.Context) error { return a.WithdrawAll(ctx) }

func (a *Announcer) validate(r plugin.Route) error {
	if !r.Prefix.IsValid() || r.Prefix != r.Prefix.Masked() {
		return fmt.Errorf("gobgp announcer: prefix %s is not a valid masked prefix", r.Prefix)
	}
	if !r.NextHop.IsValid() || r.NextHop.Is4() != r.Prefix.Addr().Is4() {
		return fmt.Errorf("gobgp announcer: next hop %s does not match %s", r.NextHop, r.Prefix)
	}
	if r.LocalPref == 0 {
		return errors.New("gobgp announcer: local_pref is required")
	}
	if len(r.Communities) == 0 {
		return errors.New("gobgp announcer: refusing to announce a route with no community")
	}
	seen := false
	for _, c := range r.Communities {
		if _, err := parseCommunity(c); err != nil {
			return fmt.Errorf("gobgp announcer: community %q: %w", c, err)
		}
		if c == a.community {
			seen = true
		}
	}
	if !seen {
		return fmt.Errorf("gobgp announcer: route for %s is missing community %s", r.Prefix, a.community)
	}
	return nil
}

var (
	v4Family = &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}
	v6Family = &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}
)

func familyOf(p netip.Prefix) *api.Family {
	if p.Addr().Is4() {
		return v4Family
	}
	return v6Family
}

func buildPath(r plugin.Route) (*api.Path, error) {
	nlri, err := anypb.New(&api.IPAddressPrefix{Prefix: r.Prefix.Addr().String(), PrefixLen: uint32(r.Prefix.Bits())})
	if err != nil {
		return nil, err
	}
	origin, err := anypb.New(&api.OriginAttribute{Origin: 0}) // IGP
	if err != nil {
		return nil, err
	}
	lp, err := anypb.New(&api.LocalPrefAttribute{LocalPref: r.LocalPref})
	if err != nil {
		return nil, err
	}
	comms := []uint32{}
	seen := map[uint32]bool{}
	for _, c := range r.Communities {
		v, err := parseCommunity(c)
		if err != nil {
			return nil, err
		}
		if !seen[v] {
			comms = append(comms, v)
			seen[v] = true
		}
	}
	if !seen[noExport] {
		comms = append(comms, noExport)
	}
	cattr, err := anypb.New(&api.CommunitiesAttribute{Communities: comms})
	if err != nil {
		return nil, err
	}
	fam := familyOf(r.Prefix)
	var nh *anypb.Any
	if r.Prefix.Addr().Is4() {
		nh, err = anypb.New(&api.NextHopAttribute{NextHop: r.NextHop.String()})
	} else {
		// Nlris has to be non-empty or GoBGP rejects the attribute as invalid.
		// The path NLRI above is what is actually advertised.
		nh, err = anypb.New(&api.MpReachNLRIAttribute{Family: fam, NextHops: []string{r.NextHop.String()}, Nlris: []*anypb.Any{nlri}})
	}
	if err != nil {
		return nil, err
	}
	return &api.Path{Family: fam, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh, lp, cattr}}, nil
}

func parseCommunity(s string) (uint32, error) {
	hi, lo, ok := strings.Cut(s, ":")
	if !ok {
		return 0, errors.New(`must be "asn:value"`)
	}
	a, err1 := strconv.ParseUint(hi, 10, 16)
	b, err2 := strconv.ParseUint(lo, 10, 16)
	if err1 != nil || err2 != nil {
		return 0, errors.New("each half must be an integer 0-65535")
	}
	return uint32(a)<<16 | uint32(b), nil
}

// installExportPolicy accepts only routes we originated that carry community,
// and rejects everything else (including routes learned from the edge).
func installExportPolicy(ctx context.Context, srv *server.BgpServer, community string) error {
	if err := srv.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_COMMUNITY,
		Name:        setName,
		List:        []string{community},
	}}); err != nil {
		return fmt.Errorf("gobgp announcer: community set: %w", err)
	}
	pol := &api.Policy{
		Name: policyName,
		Statements: []*api.Statement{{
			Name: "packeteer-accept",
			Conditions: &api.Conditions{
				CommunitySet: &api.MatchSet{Type: api.MatchSet_ANY, Name: setName},
				RouteType:    api.Conditions_ROUTE_TYPE_LOCAL,
			},
			Actions: &api.Actions{RouteAction: api.RouteAction_ACCEPT},
		}},
	}
	if err := srv.AddPolicy(ctx, &api.AddPolicyRequest{Policy: pol}); err != nil {
		return fmt.Errorf("gobgp announcer: policy: %w", err)
	}
	// Replaces the learn-only assignment (default reject, no policies) with
	// the same default plus the one accept statement above.
	if err := srv.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name:          "global",
		Direction:     api.PolicyDirection_EXPORT,
		Policies:      []*api.Policy{{Name: policyName}},
		DefaultAction: api.RouteAction_REJECT,
	}}); err != nil {
		return fmt.Errorf("gobgp announcer: export policy: %w", err)
	}
	return nil
}
