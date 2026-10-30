package registry

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// registration is one prefix registered for one origin.
type registration struct {
	prefix netip.Prefix
	origin uint32
}

// scanIRR compares the announced prefixes with the route objects of the
// configured ASNs. It reports nothing when any source failed to answer: a
// partial view would call a prefix unregistered that another source holds.
func (s *Service) scanIRR(ctx context.Context, obs Observed) ([]plugin.RegistryFinding, Section) {
	sec := Section{Name: "irr", Status: "ok"}
	if len(s.deps.IRR) == 0 {
		return nil, Section{Name: "irr", Status: "skipped", Detail: "irr.sources is not configured"}
	}
	registered := map[registration]bool{}
	answered := 0
	for _, src := range s.deps.IRR {
		ok := true
		for _, asn := range s.cfg.ASNs {
			ps, _, err := src.Plugin.OriginPrefixes(ctx, asn)
			if errors.Is(err, plugin.ErrIRRUnsupported) {
				ok = false
				break
			}
			if err != nil {
				return nil, Section{Name: "irr", Status: "error", Detail: fmt.Sprintf("source %s did not answer: %v", src.Name, err)}
			}
			for _, p := range ps {
				registered[registration{p, asn}] = true
			}
		}
		if ok {
			answered++
		}
	}
	if answered == 0 {
		return nil, Section{Name: "irr", Status: "skipped", Detail: "no irr source lists route objects by origin"}
	}

	var out []plugin.RegistryFinding
	announced := netpfx.SortedKeys(obs.Announced)
	for _, p := range announced {
		origin := obs.Announced[p]
		if registered[registration{p, origin}] {
			continue
		}
		out = append(out, plugin.RegistryFinding{
			Kind: "irr_missing", Severity: plugin.RegistryWarning, Registry: "irr",
			Subject: fmt.Sprintf("%s AS%d", p, origin),
			Message: fmt.Sprintf("%s is announced with origin AS%d and no route object registers it", p, origin),
			Diff:    "+ " + strings.ReplaceAll(strings.TrimSpace(routeObject(p, origin, s.sourceName(), s.cfg.MntBy)), "\n", "\n+ "),
			Change:  s.irrChange("create_object", s.sourceName(), p, origin, routeObject(p, origin, s.sourceName(), s.cfg.MntBy)),
		})
	}
	var stale []registration
	for r := range registered {
		if !obs.Origins[r.prefix][r.origin] && obs.Announced[r.prefix] != r.origin {
			stale = append(stale, r)
		}
	}
	slices.SortFunc(stale, func(a, b registration) int {
		return cmp.Or(a.prefix.Addr().Compare(b.prefix.Addr()), cmp.Compare(a.prefix.Bits(), b.prefix.Bits()), cmp.Compare(a.origin, b.origin))
	})
	inspect := announced
	if len(stale) > maxInspect || len(inspect) > maxInspect {
		sec.Detail = fmt.Sprintf("per-prefix checks cover the first %d announced prefixes and the first %d stale objects", maxInspect, maxInspect)
		stale = stale[:min(len(stale), maxInspect)]
		inspect = inspect[:min(len(inspect), maxInspect)]
	}
	for _, r := range stale {
		out = append(out, s.staleFindings(ctx, r)...)
	}
	for _, p := range inspect {
		out = append(out, s.conflictFindings(ctx, p, obs.Announced[p])...)
	}
	return capKinds(out), sec
}

// sourceName is the RPSL source: attribute of generated objects.
func (s *Service) sourceName() string {
	if s.cfg.IRRSource == "" {
		return "RIPE"
	}
	return s.cfg.IRRSource
}

// irrChange is a push for an object in the database the ripe source writes
// to (RIPE or its TEST database); objects in any other registry are text to
// submit by hand. The plugin refuses a different database, so offering one
// would only fail.
func (s *Service) irrChange(op, db string, p netip.Prefix, origin uint32, object string) *plugin.RegistryChange {
	if db != s.cfg.PushDB {
		return nil
	}
	class := "route"
	if p.Addr().Is6() {
		class = "route6"
	}
	return &plugin.RegistryChange{Registry: "ripe", Op: op, Class: class, Key: routeKey(p, origin), Object: object}
}

// staleFindings names the databases that hold a route object for a prefix
// that is no longer announced with that origin.
func (s *Service) staleFindings(ctx context.Context, r registration) []plugin.RegistryFinding {
	var out []plugin.RegistryFinding
	var unread []string
	seen := map[string]bool{}
	for _, src := range s.deps.IRR {
		objs, err := storedRoutes(ctx, src, r.prefix)
		if err != nil {
			unread = append(unread, fmt.Sprintf("%s: %v", src.Name, err))
			continue
		}
		for _, o := range objs {
			db := dbName(o.IRRRoute, src.Name)
			if o.Origin != r.origin || seen[db] {
				continue
			}
			seen[db] = true
			out = append(out, s.storedObject(plugin.RegistryFinding{
				Kind: "irr_stale", Severity: plugin.RegistryInfo, Registry: "irr",
				Subject: fmt.Sprintf("%s AS%d %s", r.prefix, r.origin, db),
				Message: fmt.Sprintf("%s holds a route object for %s AS%d, which no learned route has", db, r.prefix, r.origin),
			}, o, src.Name, db, true))
		}
	}
	if len(out) == 0 && len(unread) > 0 {
		out = append(out, plugin.RegistryFinding{
			Kind: "irr_stale", Severity: plugin.RegistryInfo, Registry: "irr",
			Subject: fmt.Sprintf("%s AS%d", r.prefix, r.origin),
			Message: fmt.Sprintf("a route object for %s AS%d is registered and no learned route has it; the object could not be read (%s), so no delete is offered", r.prefix, r.origin, strings.Join(unread, "; ")),
		})
	}
	return out
}

// storedRoutes reads the route objects for p from src with their text. A
// source that keeps no text answers with the routes and empty Text.
func storedRoutes(ctx context.Context, src IRRSource, p netip.Prefix) ([]plugin.IRRObject, error) {
	objs, _, err := src.Plugin.RouteObjects(ctx, p)
	if !errors.Is(err, plugin.ErrIRRUnsupported) {
		return objs, err
	}
	routes, _, err := src.Plugin.Routes(ctx, p)
	out := make([]plugin.IRRObject, len(routes))
	for i, rt := range routes {
		out[i] = plugin.IRRObject{IRRRoute: rt}
	}
	return out, err
}

// storedObject gives a finding about an object in db the "-" diff of the
// object as the source returned it and, when deletable, the delete of that
// text. Without the text there is neither: an object rebuilt from our
// template would not be what the database holds.
func (s *Service) storedObject(f plugin.RegistryFinding, o plugin.IRRObject, source, db string, deletable bool) plugin.RegistryFinding {
	if o.Text == "" {
		f.Message += fmt.Sprintf("; source %s keeps no object text, so no diff or delete is offered", source)
		return f
	}
	f.Diff = "- " + strings.ReplaceAll(strings.TrimRight(o.Text, "\n"), "\n", "\n- ")
	if deletable {
		f.Change = s.irrChange("delete_object", db, o.Prefix, o.Origin, o.Text)
	}
	return f
}

// conflictFindings looks at every route object for an announced prefix:
// another origin registered for it, and our own object left in more than
// one database.
func (s *Service) conflictFindings(ctx context.Context, p netip.Prefix, origin uint32) []plugin.RegistryFinding {
	var out []plugin.RegistryFinding
	type stored struct {
		obj    plugin.IRRObject
		source string
	}
	ours := map[string]stored{}
	foreign := map[string]bool{}
	for _, src := range s.deps.IRR {
		objs, err := storedRoutes(ctx, src, p)
		if err != nil {
			continue
		}
		for _, o := range objs {
			db := dbName(o.IRRRoute, src.Name)
			switch {
			case o.Origin == origin:
				if _, ok := ours[db]; !ok {
					ours[db] = stored{o, src.Name}
				}
			case !s.asns[o.Origin]:
				if k := fmt.Sprintf("AS%d %s", o.Origin, db); !foreign[k] {
					foreign[k] = true
					out = append(out, plugin.RegistryFinding{
						Kind: "irr_conflict", Severity: plugin.RegistryWarning, Registry: "irr",
						Subject: fmt.Sprintf("%s %s", p, k),
						Message: fmt.Sprintf("%s is announced with origin AS%d, and %s also registers AS%d as an origin for it", p, origin, db, o.Origin),
					})
				}
			}
		}
	}
	// Only a copy beside the object in the configured home database is a
	// leftover; with no object there, deleting the others would delete every
	// registration of a live prefix.
	home := s.sourceName()
	if _, ok := ours[home]; len(ours) > 1 && ok {
		for _, db := range slices.Sorted(maps.Keys(ours)) {
			if db == home {
				continue
			}
			out = append(out, s.storedObject(plugin.RegistryFinding{
				Kind: "irr_duplicate", Severity: plugin.RegistryInfo, Registry: "irr",
				Subject: fmt.Sprintf("%s AS%d %s", p, origin, db),
				Message: fmt.Sprintf("%s AS%d is registered in %s and in %s (registry.irr.source); the copy in %s may be left over from a move", p, origin, db, home, db),
			}, ours[db].obj, ours[db].source, db, false))
		}
	}
	return out
}

func dbName(rt plugin.IRRRoute, source string) string {
	if rt.Database != "" {
		return strings.ToUpper(rt.Database)
	}
	return strings.ToUpper(source)
}

// scanRPKI reads the ROA state of every announced prefix from the RPKI
// cache. ROAs are suggest-only: they are created in an RIR portal.
func (s *Service) scanRPKI(obs Observed) ([]plugin.RegistryFinding, Section) {
	if s.deps.RPKI == nil || !s.deps.RPKI.Enabled() {
		return nil, Section{Name: "rpki", Status: "skipped", Detail: "rpki is not configured"}
	}
	var out []plugin.RegistryFinding
	known := false
	for _, p := range netpfx.SortedKeys(obs.Announced) {
		origin := obs.Announced[p]
		switch s.deps.RPKI.Lookup(p, origin).State {
		case plugin.RPKIUnknown:
		case plugin.RPKIValid:
			known = true
		case plugin.RPKINotFound:
			known = true
			out = append(out, plugin.RegistryFinding{
				Kind: "rpki_missing", Severity: plugin.RegistryWarning, Registry: "rpki",
				Subject: fmt.Sprintf("%s AS%d", p, origin),
				Message: fmt.Sprintf("no ROA covers %s, so AS%d is not valid for it", p, origin),
				Diff:    fmt.Sprintf("+ ROA prefix %s, origin AS%d, maxLength %d", p, origin, p.Bits()),
			})
		case plugin.RPKIInvalid:
			known = true
			out = append(out, s.invalidFinding(p, origin))
		}
	}
	if !known {
		return nil, Section{Name: "rpki", Status: "skipped", Detail: "no fresh RPKI data"}
	}
	return capKinds(out), Section{Name: "rpki", Status: "ok"}
}

// invalidFinding says why a prefix is RPKI invalid: a ROA for the origin
// whose maxLength is shorter than the announcement, or no ROA for the
// origin at all.
func (s *Service) invalidFinding(p netip.Prefix, origin uint32) plugin.RegistryFinding {
	f := plugin.RegistryFinding{
		Registry: "rpki", Severity: plugin.RegistryError,
		Subject: fmt.Sprintf("%s AS%d", p, origin),
	}
	for _, v := range s.deps.RPKI.Covering(p) {
		if v.ASN == origin && int(v.MaxLen) < p.Bits() {
			f.Kind = "rpki_maxlength"
			f.Message = fmt.Sprintf("the ROA for %s AS%d allows up to /%d and %s is announced", v.Prefix, origin, v.MaxLen, p)
			f.Diff = fmt.Sprintf("- ROA prefix %s, origin AS%d, maxLength %d\n+ ROA prefix %s, origin AS%d, maxLength %d", v.Prefix, origin, v.MaxLen, v.Prefix, origin, p.Bits())
			return f
		}
	}
	f.Kind = "rpki_origin"
	f.Message = fmt.Sprintf("ROAs cover %s but none authorizes AS%d", p, origin)
	f.Diff = fmt.Sprintf("+ ROA prefix %s, origin AS%d, maxLength %d", p, origin, p.Bits())
	return f
}

// scanASSet compares registry.as_set with the ASNs seen downstream of the
// configured ASNs in learned paths.
func (s *Service) scanASSet(ctx context.Context, obs Observed) ([]plugin.RegistryFinding, Section) {
	if s.cfg.ASSet == "" {
		return nil, Section{Name: "as-set", Status: "skipped", Detail: "registry.as_set is not set"}
	}
	if len(s.deps.IRR) == 0 {
		return nil, Section{Name: "as-set", Status: "skipped", Detail: "irr.sources is not configured"}
	}
	if obs.NoCone != "" {
		return nil, Section{Name: "as-set", Status: "skipped", Detail: obs.NoCone}
	}
	members := map[uint32]bool{}
	answered := 0
	for _, src := range s.deps.IRR {
		ms, _, err := src.Plugin.ASSetMembers(ctx, s.cfg.ASSet)
		if errors.Is(err, plugin.ErrIRRUnsupported) {
			continue
		}
		if err != nil {
			return nil, Section{Name: "as-set", Status: "error", Detail: fmt.Sprintf("source %s did not answer: %v", src.Name, err)}
		}
		answered++
		for _, m := range ms {
			members[m] = true
		}
	}
	if answered == 0 {
		return nil, Section{Name: "as-set", Status: "skipped", Detail: "no irr source serves as-set objects"}
	}
	var out []plugin.RegistryFinding
	for _, asn := range slices.Sorted(maps.Keys(obs.Downstream)) {
		if members[asn] || s.asns[asn] {
			continue
		}
		out = append(out, plugin.RegistryFinding{
			Kind: "asset_missing", Severity: plugin.RegistryWarning, Registry: "as-set",
			Subject: fmt.Sprintf("%s AS%d", s.cfg.ASSet, asn),
			Message: fmt.Sprintf("AS%d follows AS%d on learned paths and is not in %s", asn, s.cfg.ASNs[0], s.cfg.ASSet),
			Diff:    asSetMember(s.cfg.ASSet, asn, true),
		})
	}
	for _, asn := range slices.Sorted(maps.Keys(members)) {
		if obs.Downstream[asn] || s.asns[asn] {
			continue
		}
		out = append(out, plugin.RegistryFinding{
			Kind: "asset_unseen", Severity: plugin.RegistryInfo, Registry: "as-set",
			Subject: fmt.Sprintf("%s AS%d", s.cfg.ASSet, asn),
			Message: fmt.Sprintf("AS%d is in %s (possibly through a nested set) and follows no registry.asns AS on any learned path; it may be a customer with no routes", asn, s.cfg.ASSet),
			Diff:    asSetMember(s.cfg.ASSet, asn, false),
		})
	}
	return capKinds(out), Section{Name: "as-set", Status: "ok"}
}

// capKinds keeps the first maxPerKind findings of each kind, so one
// noisy kind cannot bury the rest.
func capKinds(fs []plugin.RegistryFinding) []plugin.RegistryFinding {
	n := map[string]int{}
	out := fs[:0]
	for _, f := range fs {
		if n[f.Kind]++; n[f.Kind] <= maxPerKind {
			out = append(out, f)
		}
	}
	return out
}
