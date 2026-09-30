package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Online reconfiguration (#27, IRP "Bgpd online reconfiguration"). On
// SIGHUP the controller reads the config file again. Only bgp.neighbors
// is applied while running: sessions are added and removed without
// touching the others, and the per-router table (providers, next_hops) is
// replaced. A change to any other key is refused, with the keys named,
// and the running config stays; those need a restart. An invalid file is
// refused the same way. If applying fails half way, the controller stops,
// which withdraws every Packeteer route (no stale intent).

// neighborView is the RIB surface a reload changes. *rib.View implements it.
type neighborView interface {
	RemoveNeighbors(context.Context, []netip.Addr) error
	AddNeighbors(context.Context, []rib.Neighbor) error
	SetEgress(map[string][]netip.Addr) error
}

// routerTable is the announce surface a reload changes.
// *announce.Controller implements it.
type routerTable interface {
	SetRouters(context.Context, []plugin.RouterExport) error
	Routers() []plugin.RouterExport
}

// reloadPlan is what a new config changes on the running speaker.
type reloadPlan struct {
	remove  []netip.Addr   // sessions to close (removed or changed)
	add     []rib.Neighbor // sessions to open (new or changed)
	egress  map[string][]netip.Addr
	routers []plugin.RouterExport
	// newTable is set when the per-router table differs from the one in use.
	newTable bool
}

func (p reloadPlan) empty() bool { return len(p.remove) == 0 && len(p.add) == 0 && !p.newTable }

// planReload compares a freshly loaded config with the running one. It
// fails, naming the keys, when anything outside bgp.neighbors changed.
func planReload(cur, next *config.Config, table []plugin.RouterExport) (reloadPlan, error) {
	var plan reloadPlan
	if keys := restartKeys(cur, next); len(keys) > 0 {
		return plan, fmt.Errorf("restart required: changed %s (only bgp.neighbors reloads online)", strings.Join(keys, ", "))
	}
	if len(next.BGP.Neighbors) == 0 {
		return plan, errors.New("restart required: bgp.neighbors cannot become empty while running")
	}
	old, _, err := ribNeighbors(cur)
	if err != nil {
		return plan, err
	}
	nbrs, egress, err := ribNeighbors(next)
	if err != nil {
		return plan, err
	}
	before := map[netip.Addr]rib.Neighbor{}
	for _, n := range old {
		before[n.Address] = n
	}
	after := map[netip.Addr]bool{}
	for _, n := range nbrs {
		after[n.Address] = true
		o, ok := before[n.Address]
		if ok && o == n {
			continue
		}
		if ok {
			// Session settings changed: that one session is reset.
			plan.remove = append(plan.remove, n.Address)
		}
		plan.add = append(plan.add, n)
	}
	for _, n := range old {
		if !after[n.Address] {
			plan.remove = append(plan.remove, n.Address)
		}
	}
	plan.egress = egress
	routers, err := routerExports(next)
	if err != nil {
		return plan, err
	}
	plan.routers = routers
	plan.newTable = !reflect.DeepEqual(normTable(routers), normTable(table))
	return plan, nil
}

// normTable makes two tables comparable: nil and empty are the same, and
// order does not matter.
func normTable(t []plugin.RouterExport) []plugin.RouterExport {
	out := make([]plugin.RouterExport, 0, len(t))
	for _, r := range t {
		c := plugin.RouterExport{Neighbor: r.Neighbor, Blocked: slices.Clone(r.Blocked)}
		if len(r.Via) > 0 {
			c.Via = r.Via
		}
		if len(c.Blocked) == 0 {
			c.Blocked = nil
		}
		slices.SortFunc(c.Blocked, netip.Addr.Compare)
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b plugin.RouterExport) int { return a.Neighbor.Compare(b.Neighbor) })
	return out
}

// restartKeys lists the top-level keys (bgp sub-keys for bgp) whose value
// differs, ignoring bgp.neighbors, comments, and YAML style.
func restartKeys(a, b *config.Config) []string {
	var keys []string
	av, bv := reflect.ValueOf(*a), reflect.ValueOf(*b)
	t := av.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}
		x, y := av.Field(i).Interface(), bv.Field(i).Interface()
		if name == "bgp" {
			ab, bb := x.(config.BGP), y.(config.BGP)
			ab.Neighbors, bb.Neighbors = nil, nil
			if !sameYAML(ab.ListenPort, bb.ListenPort) {
				keys = append(keys, "bgp.listen_port")
			}
			if !sameYAML(ab.ListenAddresses, bb.ListenAddresses) {
				keys = append(keys, "bgp.listen_addresses")
			}
			if !sameYAML(ab.ASPath, bb.ASPath) {
				keys = append(keys, "bgp.as_path")
			}
			if !sameYAML(ab, bb) && !slices.ContainsFunc(keys, func(k string) bool { return strings.HasPrefix(k, "bgp.") }) {
				keys = append(keys, "bgp")
			}
			continue
		}
		if !sameYAML(x, y) {
			keys = append(keys, name)
		}
	}
	return keys
}

// sameYAML compares two values by their YAML data: comments and flow or
// block style in plugin config nodes do not count.
func sameYAML(a, b any) bool {
	return reflect.DeepEqual(yamlData(a), yamlData(b))
}

func yamlData(v any) any {
	raw, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Sprintf("unmarshalable: %v", err)
	}
	var out any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return fmt.Sprintf("unparsable: %v", err)
	}
	return out
}

// reloader applies SIGHUP reloads. It is used from one goroutine.
type reloader struct {
	path   string
	getenv func(string) string
	log    *slog.Logger
	cur    *config.Config
	view   neighborView
	ctl    routerTable
	poke   func()
	// applied, when set, is told each config the reload now runs with
	// (the config editor diffs against it).
	applied func(*config.Config)
}

func (r *reloader) setCur(next *config.Config) {
	r.cur = next
	if r.applied != nil {
		r.applied(next)
	}
}

// reload reads the file and applies what can change online. refused is a
// config that was not applied (the running one stays). fatal is a failure
// after the speaker was changed: the caller must stop, which withdraws.
func (r *reloader) reload(ctx context.Context) (refused, fatal error) {
	next, err := config.Load(r.path)
	if err == nil {
		err = applyRuntimeEnv(next, r.getenv)
	}
	if err != nil {
		return err, nil
	}
	if r.view == nil {
		if len(restartKeys(r.cur, next)) > 0 || !sameYAML(r.cur.BGP.Neighbors, next.BGP.Neighbors) {
			return errors.New("restart required: bgp is off in the running config"), nil
		}
		return nil, nil
	}
	var table []plugin.RouterExport
	if r.ctl != nil {
		table = r.ctl.Routers()
	}
	plan, err := planReload(r.cur, next, table)
	if err != nil {
		return err, nil
	}
	if plan.empty() {
		r.log.Info("config reloaded: no change")
		r.setCur(next)
		return nil, nil
	}
	// Close removed sessions first, so a router leaving the table never
	// sees routes without it; then swap the table (the announcer withdraws
	// and the next sync announces again); then open new sessions, so a
	// new router's first routes already follow the new table.
	if err := r.view.RemoveNeighbors(ctx, plan.remove); err != nil {
		return nil, err
	}
	if plan.newTable && r.ctl != nil {
		if err := r.ctl.SetRouters(ctx, plan.routers); err != nil {
			return nil, err
		}
	}
	if err := r.view.AddNeighbors(ctx, plan.add); err != nil {
		return nil, err
	}
	if err := r.view.SetEgress(plan.egress); err != nil {
		return nil, err
	}
	r.setCur(next)
	added := make([]string, 0, len(plan.add))
	for _, n := range plan.add {
		added = append(added, n.Address.String())
	}
	removed := make([]string, 0, len(plan.remove))
	for _, a := range plan.remove {
		removed = append(removed, a.String())
	}
	r.log.Info("config reloaded", "neighbors_added", strings.Join(added, ","), "neighbors_removed", strings.Join(removed, ","),
		"router_table_replaced", plan.newTable)
	if r.poke != nil {
		r.poke()
	}
	return nil, nil
}
