package routeros

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/readonly"
)

// ErrAuth is returned when RouterOS refuses the login or the account may
// not read a path the reader needs.
var ErrAuth = errors.New("RouterOS refused the login or the account may not read this path")

// l3hwGet is every path ReadL3HW may GET, below /rest. The two route paths
// carry the fixed query that selects the default route.
var l3hwGet = readonly.NewAllowlist(
	`/system/resource`,
	`/interface/ethernet/switch`,
	`/interface/ethernet/switch/port`,
	`/interface/ethernet/switch/l3hw-settings`,
	`/interface/ethernet/switch/l3hw-settings/advanced`,
	`/interface/bridge`,
	`/interface/vlan`,
	`/interface/bonding`,
	`/interface/vrrp`,
	`/routing/rule`,
	`/ip/vrf`,
	`/ip/firewall/mangle`,
	`/ip/firewall/filter`,
	`/ip/firewall/nat`,
	`/ip/route\?dst-address=0\.0\.0\.0/0`,
	`/ipv6/route\?dst-address=::/0`,
)

// l3hwPost is the only POST the reader sends: a monitor read with once, so
// the router answers once instead of streaming.
var l3hwPost = readonly.NewAllowlist(
	`/interface/ethernet/switch/l3hw-settings/monitor`,
	`/interface/ethernet/switch/l3hw-settings/advanced/monitor`,
)

var onceBody = []byte(`{"once":""}`)

// L3HW is what the reader found about RouterOS hardware routing. It
// carries no credentials.
type L3HW struct {
	// Version is the RouterOS version, for example 7.24.2.
	Version string `json:"version"`
	// Applicable is false when the router exposes no L3HW monitor (a CHR,
	// or a device with no switch chip). Nothing else is read then.
	Applicable bool `json:"applicable"`

	Monitor  Monitor          `json:"monitor"`
	Advanced *AdvancedMonitor `json:"advanced,omitempty"`
	Settings Settings         `json:"settings"`
	Tuning   *Tuning          `json:"tuning,omitempty"`

	Ports   []Port  `json:"ports,omitempty"`
	Bridges []Iface `json:"bridges,omitempty"`
	VLANs   []Iface `json:"vlans,omitempty"`
	Bonds   []Iface `json:"bonds,omitempty"`

	RoutingRules       int `json:"routing_rules"`
	VRFs               int `json:"vrfs"`
	MarkRoutingRules   int `json:"mark_routing_rules"`
	MangleRules        int `json:"mangle_rules"`
	ForwardFilterRules int `json:"forward_filter_rules"`
	NATRules           int `json:"nat_rules"`
	VRRPInterfaces     int `json:"vrrp_interfaces"`

	// DefaultRoutes lists every 0.0.0.0/0 and ::/0 route, active or not.
	DefaultRoutes []DefaultRoute `json:"default_routes,omitempty"`

	// Unread names what the account or this RouterOS version did not
	// give, with the reason.
	Unread []string `json:"unread,omitempty"`
}

// Monitor is the basic l3hw-settings monitor (RouterOS 7.10 and later).
// Hardware route counts come from here, never from the H flag on a route.
type Monitor struct {
	State                string `json:"state"`
	IPv4RoutesTotal      int64  `json:"ipv4_routes_total"`
	IPv4RoutesHW         int64  `json:"ipv4_routes_hw"`
	IPv4RoutesCPU        int64  `json:"ipv4_routes_cpu"`
	IPv4ShortestHWPrefix int64  `json:"ipv4_shortest_hw_prefix"`
	IPv4Hosts            int64  `json:"ipv4_hosts"`
	IPv6RoutesTotal      int64  `json:"ipv6_routes_total"`
	IPv6RoutesHW         int64  `json:"ipv6_routes_hw"`
	IPv6RoutesCPU        int64  `json:"ipv6_routes_cpu"`
	NexthopCap           int64  `json:"nexthop_cap"`
	NexthopUsage         int64  `json:"nexthop_usage"`
}

// Partial reports an offload that is not complete: a shortest hardware
// prefix above 0, or routes handled by the CPU. It is true for a table
// that is almost entirely in hardware too; compare the counts.
func (m Monitor) Partial() bool {
	return m.IPv4ShortestHWPrefix > 0 || m.IPv4RoutesCPU > 0 || m.IPv6RoutesCPU > 0
}

// NexthopExhausted reports that every next-hop entry of the chip is used,
// which collapsed offload in a field report.
func (m Monitor) NexthopExhausted() bool {
	return m.NexthopCap > 0 && m.NexthopUsage >= m.NexthopCap
}

// AdvancedMonitor is what the advanced monitor adds. RouterOS 7.17.2's
// basic monitor has no LPM fields, so these are the only source.
type AdvancedMonitor struct {
	ErrorCode string `json:"error_code,omitempty"`
	// HasLPM is false when the chip reports no LPM fields.
	HasLPM   bool  `json:"has_lpm"`
	LPMCap   int64 `json:"lpm_cap"`
	LPMUsage int64 `json:"lpm_usage"`
}

// Settings is l3hw-settings.
type Settings struct {
	IPv6HW      bool `json:"ipv6_hw"`
	FasttrackHW bool `json:"fasttrack_hw"`
	Autorestart bool `json:"autorestart"`
}

// Tuning is the l3hw-settings advanced menu, which MikroTik says to leave
// alone unless support asks for a change.
type Tuning struct {
	SHWPResetCounter    int64  `json:"shwp_reset_counter"`
	RouteIndexDelayMin  string `json:"route_index_delay_min"`
	RouteIndexDelayMax  string `json:"route_index_delay_max"`
	RouteQueueLimitHigh int64  `json:"route_queue_limit_high"`
	RouteQueueLimitLow  int64  `json:"route_queue_limit_low"`
}

// Port is a switch port with its l3-hw-offloading flag.
type Port struct {
	Name string `json:"name"`
	L3HW bool   `json:"l3_hw_offloading"`
}

// Iface is a bridge, VLAN interface, or bond. L3HW is the per-interface
// l3-hw-offloading flag, where RouterOS has one.
type Iface struct {
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
	L3HW     bool   `json:"l3_hw_offloading"`
	// Parent is the interface a VLAN interface sits on.
	Parent string `json:"parent,omitempty"`
	// Mode is the bonding mode of a bond.
	Mode string `json:"mode,omitempty"`
}

// DefaultRoute is one 0.0.0.0/0 or ::/0 route.
type DefaultRoute struct {
	Family   string `json:"family"` // ipv4 or ipv6
	Gateway  string `json:"gateway"`
	Distance int64  `json:"distance"`
	// Protocol is RouterOS's belongs-to: BGP, Static route, and so on.
	Protocol  string `json:"protocol"`
	LocalPref int64  `json:"local_pref"`
	Active    bool   `json:"active"`
	Inactive  bool   `json:"inactive"`
	// HFlag is the H flag. It means the route is eligible for hardware,
	// never that it is in hardware: use Monitor for that.
	HFlag             bool `json:"h_flag"`
	SuppressHWOffload bool `json:"suppress_hw_offload"`
}

// ReadL3HW reads the router's hardware routing state: GET requests to a
// fixed list of paths and the monitor reads with once. It changes nothing
// on the router. ErrAuth means the login was refused.
func (r *Reader) ReadL3HW(ctx context.Context) (L3HW, error) {
	var out L3HW
	var res row
	if err := r.getRow(ctx, "/system/resource", &res); err != nil {
		return out, authErr(err)
	}
	out.Version, _, _ = strings.Cut(res["version"], " ")

	var sw []row
	if err := r.l3get(ctx, "/interface/ethernet/switch", &sw); err != nil {
		if missing(err) {
			return out, nil
		}
		return out, authErr(err)
	}
	if len(sw) == 0 {
		return out, nil
	}

	var set row
	if err := r.getRow(ctx, "/interface/ethernet/switch/l3hw-settings", &set); err != nil {
		if missing(err) {
			return out, nil
		}
		return out, authErr(err)
	}

	mon, err := r.monitor(ctx, "/interface/ethernet/switch/l3hw-settings/monitor")
	if err != nil {
		if missing(err) {
			return out, nil
		}
		return out, authErr(err)
	}
	if out.Monitor, err = parseMonitor(mon); err != nil {
		return out, err
	}
	out.Applicable = true
	out.Settings = Settings{IPv6HW: yes(set["ipv6-hw"]), FasttrackHW: yes(set["fasttrack-hw"]), Autorestart: yes(set["autorestart"])}

	if adv, err := r.monitor(ctx, "/interface/ethernet/switch/l3hw-settings/advanced/monitor"); err != nil {
		if !optional(err) {
			return out, authErr(err)
		}
		out.Unread = append(out.Unread, "advanced monitor: "+reason(err))
	} else if out.Advanced, err = parseAdvanced(adv); err != nil {
		return out, err
	}

	var tune row
	if err := r.getRow(ctx, "/interface/ethernet/switch/l3hw-settings/advanced", &tune); err != nil {
		if !optional(err) {
			return out, authErr(err)
		}
		out.Unread = append(out.Unread, "l3hw advanced settings: "+reason(err))
	} else if out.Tuning, err = parseTuning(tune); err != nil {
		return out, err
	}

	if err := r.readTopology(ctx, &out); err != nil {
		return out, err
	}
	for _, d := range []struct{ family, path, dst string }{
		{"ipv4", "/ip/route?dst-address=0.0.0.0/0", "0.0.0.0/0"},
		{"ipv6", "/ipv6/route?dst-address=::/0", "::/0"},
	} {
		var routes []row
		if err := r.l3get(ctx, d.path, &routes); err != nil {
			return out, authErr(err)
		}
		for _, rt := range routes {
			if rt["dst-address"] != d.dst {
				continue
			}
			dr, err := parseRoute(d.family, rt)
			if err != nil {
				return out, err
			}
			out.DefaultRoutes = append(out.DefaultRoutes, dr)
		}
	}
	return out, nil
}

// readTopology reads the switch ports, interfaces, and the policy routing
// that decides whether traffic can stay in hardware.
func (r *Reader) readTopology(ctx context.Context, out *L3HW) error {
	var ports []row
	if err := r.l3get(ctx, "/interface/ethernet/switch/port", &ports); err != nil {
		if !optional(err) {
			return authErr(err)
		}
		out.Unread = append(out.Unread, "switch ports: "+reason(err))
	}
	for _, p := range ports {
		out.Ports = append(out.Ports, Port{Name: p["name"], L3HW: yes(p["l3-hw-offloading"])})
	}
	for _, l := range []struct {
		path string
		dst  *[]Iface
	}{
		{"/interface/bridge", &out.Bridges},
		{"/interface/vlan", &out.VLANs},
		{"/interface/bonding", &out.Bonds},
	} {
		var rows []row
		if err := r.l3get(ctx, l.path, &rows); err != nil {
			return authErr(err)
		}
		for _, x := range rows {
			*l.dst = append(*l.dst, Iface{Name: x["name"], Disabled: yes(x["disabled"]), L3HW: yes(x["l3-hw-offloading"]), Parent: x["interface"], Mode: x["mode"]})
		}
	}
	var rules, vrfs, mangle, filter, nat, vrrp []row
	for _, l := range []struct {
		path string
		dst  *[]row
	}{
		{"/routing/rule", &rules},
		{"/ip/vrf", &vrfs},
		{"/ip/firewall/mangle", &mangle},
		{"/ip/firewall/filter", &filter},
		{"/ip/firewall/nat", &nat},
		{"/interface/vrrp", &vrrp},
	} {
		if err := r.l3get(ctx, l.path, l.dst); err != nil {
			return authErr(err)
		}
	}
	out.RoutingRules, out.VRFs, out.VRRPInterfaces = enabled(rules, nil), len(vrfs), len(vrrp)
	out.MangleRules, out.NATRules = enabled(mangle, nil), enabled(nat, nil)
	out.MarkRoutingRules = enabled(mangle, func(x row) bool { return x["action"] == "mark-routing" })
	out.ForwardFilterRules = enabled(filter, func(x row) bool { return x["chain"] == "forward" })
	return nil
}

// enabled counts the rows that are not disabled and pass keep.
func enabled(rows []row, keep func(row) bool) int {
	n := 0
	for _, x := range rows {
		if !yes(x["disabled"]) && (keep == nil || keep(x)) {
			n++
		}
	}
	return n
}

// getRow reads a path that is one object on a single-item menu, or a list
// of one on others.
func (r *Reader) getRow(ctx context.Context, path string, out *row) error {
	var raw json.RawMessage
	if err := r.l3get(ctx, path, &raw); err != nil {
		return err
	}
	return oneRow(path, raw, out)
}

func (r *Reader) monitor(ctx context.Context, path string) (row, error) {
	var raw json.RawMessage
	if err := r.do(ctx, http.MethodPost, path, onceBody, l3hwPost, &raw); err != nil {
		return nil, err
	}
	var out row
	return out, oneRow(path, raw, &out)
}

func oneRow(path string, raw json.RawMessage, out *row) error {
	raw = bytes.TrimSpace(raw)
	if bytes.HasPrefix(raw, []byte("[")) {
		var list []row
		if err := json.Unmarshal(raw, &list); err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if len(list) == 0 {
			return fmt.Errorf("read %s: empty reply", path)
		}
		*out = list[0]
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

func (r *Reader) l3get(ctx context.Context, path string, out any) error {
	return r.do(ctx, http.MethodGet, path, nil, l3hwGet, out)
}

func statusOf(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

// missing is a menu or command this RouterOS does not have: 400 or 404.
func missing(err error) bool {
	c := statusOf(err)
	return c == http.StatusBadRequest || c == http.StatusNotFound
}

// optional is a read the account or the version may lack.
func optional(err error) bool {
	return missing(err) || statusOf(err) == http.StatusForbidden
}

func reason(err error) string {
	switch c := statusOf(err); {
	case c == http.StatusForbidden:
		return "the account may not read it"
	case c != 0:
		return "RouterOS has no such menu or command"
	}
	return err.Error()
}

// authErr turns a refused login into ErrAuth.
func authErr(err error) error {
	if c := statusOf(err); c == http.StatusUnauthorized || c == http.StatusForbidden {
		return fmt.Errorf("%w: %w", ErrAuth, err)
	}
	return err
}

// yes reads a RouterOS boolean.
func yes(s string) bool { return s == "true" || s == "yes" }

// num reads an integer field. An absent field is 0: older RouterOS
// versions and other chips lack some of them.
func num(x row, key string) (int64, error) {
	s := x[key]
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is not a number", key)
	}
	return n, nil
}

// nums reads several integer fields and returns the first error.
func nums(x row, keys []string, dst []*int64) error {
	for i, k := range keys {
		n, err := num(x, k)
		if err != nil {
			return err
		}
		*dst[i] = n
	}
	return nil
}

func parseMonitor(x row) (Monitor, error) {
	m := Monitor{State: x["state"]}
	err := nums(x,
		[]string{"ipv4-routes-total", "ipv4-routes-hw", "ipv4-routes-cpu", "ipv4-shortest-hw-prefix", "ipv4-hosts", "ipv6-routes-total", "ipv6-routes-hw", "ipv6-routes-cpu", "nexthop-cap", "nexthop-usage"},
		[]*int64{&m.IPv4RoutesTotal, &m.IPv4RoutesHW, &m.IPv4RoutesCPU, &m.IPv4ShortestHWPrefix, &m.IPv4Hosts, &m.IPv6RoutesTotal, &m.IPv6RoutesHW, &m.IPv6RoutesCPU, &m.NexthopCap, &m.NexthopUsage})
	if err != nil {
		return Monitor{}, fmt.Errorf("l3hw monitor: %w", err)
	}
	return m, nil
}

func parseAdvanced(x row) (*AdvancedMonitor, error) {
	a := &AdvancedMonitor{ErrorCode: x["error-code"]}
	_, a.HasLPM = x["lpm-cap"]
	if err := nums(x, []string{"lpm-cap", "lpm-usage"}, []*int64{&a.LPMCap, &a.LPMUsage}); err != nil {
		return nil, fmt.Errorf("l3hw advanced monitor: %w", err)
	}
	return a, nil
}

func parseTuning(x row) (*Tuning, error) {
	t := &Tuning{RouteIndexDelayMin: x["route-index-delay-min"], RouteIndexDelayMax: x["route-index-delay-max"]}
	err := nums(x,
		[]string{"shwp-reset-counter", "route-queue-limit-high", "route-queue-limit-low"},
		[]*int64{&t.SHWPResetCounter, &t.RouteQueueLimitHigh, &t.RouteQueueLimitLow})
	if err != nil {
		return nil, fmt.Errorf("l3hw advanced settings: %w", err)
	}
	return t, nil
}

func parseRoute(family string, x row) (DefaultRoute, error) {
	d := DefaultRoute{
		Family: family, Gateway: x["gateway"], Protocol: x["belongs-to"],
		Active: yes(x["active"]), Inactive: yes(x["inactive"]),
		HFlag: yes(x["hw-offloaded"]), SuppressHWOffload: yes(x["suppress-hw-offload"]),
	}
	if err := nums(x, []string{"distance", "bgp-local-pref"}, []*int64{&d.Distance, &d.LocalPref}); err != nil {
		return DefaultRoute{}, fmt.Errorf("%s default route: %w", family, err)
	}
	return d, nil
}
