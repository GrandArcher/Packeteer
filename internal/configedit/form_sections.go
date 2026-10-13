package configedit

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Form sections: the flow, vip, and outage sources and the rules
// policies (#130, every instance in #226). Each is a list on Form. A nil
// list in a request means "leave it alone", so an older client that does
// not know the section cannot remove it; an empty list removes every
// entry of that type. ParseForm always fills them. Applying a section edits
// the YAML text only; Save runs the same checks as a start, and nothing
// here can turn inject on or announce.

// Section limits. A larger edit belongs in the YAML.
const (
	MaxFormRules      = 1000
	MaxFormListValues = 4096
	MaxFormEntries    = 64
)

// Every row has a Name, the entry's instance name. It is empty for a
// single entry of a type (the type is the name). A second entry of the
// same type needs its own name: config.Load refuses duplicates.

// FormFlow is one `flow` source. Key is the source's position in `sources`
// when the form was loaded; empty means a new source. Dropping a row
// removes the source, including its problems, transit, and subranges
// blocks. Those three blocks are kept as they are while the source stays.
// TopN is the priority tier, MaxTargets the larger capped set, and
// TailInterval the interval for the rest. AggregateV4 and AggregateV6 are
// the lengths a destination with no covering learned prefix is grouped to.
type FormFlow struct {
	Key          string   `json:"key"`
	Name         string   `json:"name"`
	Listen       []string `json:"listen"`
	Window       string   `json:"window"`
	TopN         string   `json:"top_n"`
	MaxTargets   string   `json:"max_targets"`
	TailInterval string   `json:"tail_interval"`
	MinBytes     string   `json:"min_bytes"`
	MinPct       string   `json:"min_pct"`
	AggregateV4  string   `json:"aggregate_v4"`
	AggregateV6  string   `json:"aggregate_v6"`
	Exclude      []string `json:"exclude"`
}

// FormPolicy is one `rules` policy. Key is its position in `policies`
// when the form was loaded; empty means a new policy. Policies are asked
// in file order, so the list order is the chain order. GeoIPDB is the
// absolute path of a country database mounted into the container; a rule
// with countries needs it.
type FormPolicy struct {
	Key     string     `json:"key"`
	Name    string     `json:"name"`
	GeoIPDB string     `json:"geoip_db"`
	Rules   []FormRule `json:"rules"`
}

// FormRule is one rule. Key is the rule's position in its policy when the
// form was loaded; empty means a new rule. Rule order is the file order.
type FormRule struct {
	Key        string   `json:"key"`
	Name       string   `json:"name"`
	Action     string   `json:"action"`
	Providers  []string `json:"providers"`
	Prefixes   []string `json:"prefixes"`
	ASNs       []string `json:"asns"`
	Countries  []string `json:"countries"`
	Traffic    string   `json:"traffic"`
	MaxLossPct string   `json:"max_loss_pct"`
	MaxRTT     string   `json:"max_rtt"`
}

// FormVIP is one `vip` source. Dropping the row removes it.
type FormVIP struct {
	Key        string       `json:"key"`
	Name       string       `json:"name"`
	Interval   string       `json:"interval"`
	MaxTargets string       `json:"max_targets"`
	Prefixes   []FormTarget `json:"prefixes"`
	ASNs       []string     `json:"asns"`
}

// FormOutage is one `outage` source. Dropping the row removes it.
type FormOutage struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	MinPrefixes string   `json:"min_prefixes"`
	Window      string   `json:"window"`
	LossPct     string   `json:"loss_pct"`
	RTTMs       string   `json:"rtt_ms"`
	Interval    string   `json:"interval"`
	MaxTargets  string   `json:"max_targets"`
	IgnoreASNs  []string `json:"ignore_asns"`
}

// ---- reading ----

func readSections(root *yaml.Node, f *Form) error {
	f.Flows = []FormFlow{}
	for _, e := range typedEntries(root, "sources", "flow") {
		fl := FormFlow{Key: e.key, Name: scalar(e.node, "name"), Listen: []string{}, Exclude: []string{}}
		if cfg, ok := mappingChild(e.node, "config"); ok {
			fl.Listen = listOrScalar(cfg, "listen")
			fl.Window = scalar(cfg, "window")
			fl.TopN = scalar(cfg, "top_n")
			fl.MaxTargets = scalar(cfg, "max_targets")
			fl.TailInterval = scalar(cfg, "tail_interval")
			fl.MinBytes = scalar(cfg, "min_bytes")
			fl.MinPct = scalar(cfg, "min_pct")
			fl.AggregateV4 = scalar(cfg, "aggregate_v4")
			fl.AggregateV6 = scalar(cfg, "aggregate_v6")
			fl.Exclude = scalarList(cfg, "exclude")
		}
		f.Flows = append(f.Flows, fl)
	}

	f.Policies = []FormPolicy{}
	for _, e := range typedEntries(root, "policies", "rules") {
		pol := FormPolicy{Key: e.key, Name: scalar(e.node, "name"), Rules: []FormRule{}}
		if cfg, ok := mappingChild(e.node, "config"); ok {
			pol.GeoIPDB = scalar(cfg, "geoip_db")
			if seq, ok := sequenceChild(cfg, "rules"); ok {
				for i, item := range seq.Content {
					if item.Kind != yaml.MappingNode {
						return fmt.Errorf("%w: policies rules must be a list of mappings", ErrForm)
					}
					pol.Rules = append(pol.Rules, FormRule{
						Key: strconv.Itoa(i), Name: scalar(item, "name"), Action: scalar(item, "action"),
						Providers: scalarList(item, "providers"), Prefixes: scalarList(item, "prefixes"),
						ASNs: scalarList(item, "asns"), Countries: scalarList(item, "countries"),
						Traffic: scalar(item, "traffic"), MaxLossPct: scalar(item, "max_loss_pct"),
						MaxRTT: scalar(item, "max_rtt"),
					})
				}
			}
		}
		f.Policies = append(f.Policies, pol)
	}

	f.VIPs = []FormVIP{}
	for _, e := range typedEntries(root, "sources", "vip") {
		vip := FormVIP{Key: e.key, Name: scalar(e.node, "name"), Prefixes: []FormTarget{}, ASNs: []string{}}
		if cfg, ok := mappingChild(e.node, "config"); ok {
			vip.Interval = scalar(cfg, "interval")
			vip.MaxTargets = scalar(cfg, "max_targets")
			vip.ASNs = scalarList(cfg, "asns")
			if seq, ok := sequenceChild(cfg, "prefixes"); ok {
				for _, item := range seq.Content {
					if item.Kind != yaml.MappingNode {
						return fmt.Errorf("%w: vip prefixes must be a list of mappings", ErrForm)
					}
					p := scalar(item, "prefix")
					vip.Prefixes = append(vip.Prefixes, FormTarget{Key: p, Prefix: p, Host: scalar(item, "host")})
				}
			}
		}
		f.VIPs = append(f.VIPs, vip)
	}

	f.Outages = []FormOutage{}
	for _, e := range typedEntries(root, "sources", "outage") {
		out := FormOutage{Key: e.key, Name: scalar(e.node, "name"), IgnoreASNs: []string{}}
		if cfg, ok := mappingChild(e.node, "config"); ok {
			out.MinPrefixes = scalar(cfg, "min_prefixes")
			out.Window = scalar(cfg, "window")
			out.LossPct = scalar(cfg, "loss_pct")
			out.RTTMs = scalar(cfg, "rtt_ms")
			out.Interval = scalar(cfg, "interval")
			out.MaxTargets = scalar(cfg, "max_targets")
			out.IgnoreASNs = scalarList(cfg, "ignore_asns")
		}
		f.Outages = append(f.Outages, out)
	}
	return readProtection(root, f)
}

// typedEntry is one plugin entry of a type. key is its index in the list.
type typedEntry struct {
	key  string
	node *yaml.Node
}

// typedEntries lists the entries of one plugin type in a top-level list
// (`sources` or `policies`), in file order.
func typedEntries(root *yaml.Node, listKey, typ string) []typedEntry {
	seq, ok := sequenceChild(root, listKey)
	if !ok {
		return nil
	}
	var out []typedEntry
	for i, item := range seq.Content {
		if item.Kind == yaml.MappingNode && scalar(item, "type") == typ {
			out = append(out, typedEntry{strconv.Itoa(i), item})
		}
	}
	return out
}

// listOrScalar reads a key that is one string or a list of them.
func listOrScalar(m *yaml.Node, key string) []string {
	if n, _ := child(m, key); n != nil && n.Kind == yaml.ScalarNode && n.Tag != "!!null" {
		return []string{n.Value}
	}
	return scalarList(m, key)
}

// ---- normalize, equal, validate ----

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.TrimSpace(s))
	}
	return out
}

func (f *Form) normalizeSections() {
	f.normalizeProtection()
	for i := range f.Flows {
		fl := &f.Flows[i]
		fl.Key = strings.TrimSpace(fl.Key)
		fl.Name = strings.TrimSpace(fl.Name)
		fl.Listen = trimAll(fl.Listen)
		fl.Exclude = trimAll(fl.Exclude)
		for _, p := range []*string{&fl.Window, &fl.TopN, &fl.MaxTargets, &fl.TailInterval, &fl.MinBytes, &fl.MinPct, &fl.AggregateV4, &fl.AggregateV6} {
			*p = strings.TrimSpace(*p)
		}
	}
	for i := range f.Policies {
		p := &f.Policies[i]
		p.Key = strings.TrimSpace(p.Key)
		p.Name = strings.TrimSpace(p.Name)
		p.GeoIPDB = strings.TrimSpace(p.GeoIPDB)
		if p.Rules == nil {
			p.Rules = []FormRule{}
		}
		for j := range p.Rules {
			r := &p.Rules[j]
			r.Key = strings.TrimSpace(r.Key)
			r.Name = strings.TrimSpace(r.Name)
			r.Action = strings.TrimSpace(r.Action)
			r.Traffic = strings.TrimSpace(r.Traffic)
			r.MaxLossPct = strings.TrimSpace(r.MaxLossPct)
			r.MaxRTT = strings.TrimSpace(r.MaxRTT)
			r.Providers = trimAll(r.Providers)
			r.Prefixes = trimAll(r.Prefixes)
			r.ASNs = trimAll(r.ASNs)
			r.Countries = trimAll(r.Countries)
		}
	}
	for i := range f.VIPs {
		v := &f.VIPs[i]
		v.Key = strings.TrimSpace(v.Key)
		v.Name = strings.TrimSpace(v.Name)
		v.Interval = strings.TrimSpace(v.Interval)
		v.MaxTargets = strings.TrimSpace(v.MaxTargets)
		v.ASNs = trimAll(v.ASNs)
		if v.Prefixes == nil {
			v.Prefixes = []FormTarget{}
		}
		for j := range v.Prefixes {
			t := &v.Prefixes[j]
			t.Key = strings.TrimSpace(t.Key)
			t.Prefix = strings.TrimSpace(t.Prefix)
			t.Host = strings.TrimSpace(t.Host)
		}
	}
	for i := range f.Outages {
		o := &f.Outages[i]
		o.Key = strings.TrimSpace(o.Key)
		o.Name = strings.TrimSpace(o.Name)
		for _, p := range []*string{&o.MinPrefixes, &o.Window, &o.LossPct, &o.RTTMs, &o.Interval, &o.MaxTargets} {
			*p = strings.TrimSpace(*p)
		}
		o.IgnoreASNs = trimAll(o.IgnoreASNs)
	}
}

// fillSections gives a nil list the file's current value, so a request
// that omits it changes nothing. Every inner list becomes non-nil so a
// round trip compares equal.
func (f *Form) fillSections(cur Form) {
	f.fillProtection(cur)
	f.fillExchanges(cur)
	if f.Flows == nil {
		f.Flows = cur.Flows
	}
	if f.Policies == nil {
		f.Policies = cur.Policies
	}
	if f.VIPs == nil {
		f.VIPs = cur.VIPs
	}
	if f.Outages == nil {
		f.Outages = cur.Outages
	}
	for i := range f.Flows {
		fl := &f.Flows[i]
		if fl.Listen == nil {
			fl.Listen = []string{}
		}
		if fl.Exclude == nil {
			fl.Exclude = []string{}
		}
	}
	for i := range f.VIPs {
		if f.VIPs[i].ASNs == nil {
			f.VIPs[i].ASNs = []string{}
		}
	}
	for i := range f.Outages {
		if f.Outages[i].IgnoreASNs == nil {
			f.Outages[i].IgnoreASNs = []string{}
		}
	}
	for i := range f.Policies {
		for j := range f.Policies[i].Rules {
			r := &f.Policies[i].Rules[j]
			for _, l := range []*[]string{&r.Providers, &r.Prefixes, &r.ASNs, &r.Countries} {
				if *l == nil {
					*l = []string{}
				}
			}
		}
	}
}

// withoutUnchangedSections drops the sections the operator did not edit,
// so a file the form does not fully model still lets the other fields be
// applied. Save runs the full checks either way.
func (f Form) withoutUnchangedSections(cur Form) Form {
	if reflect.DeepEqual(f.Flows, cur.Flows) {
		f.Flows = nil
	}
	if reflect.DeepEqual(f.Policies, cur.Policies) {
		f.Policies = nil
	}
	if reflect.DeepEqual(f.VIPs, cur.VIPs) {
		f.VIPs = nil
	}
	if reflect.DeepEqual(f.Outages, cur.Outages) {
		f.Outages = nil
	}
	if reflect.DeepEqual(f.Exchanges, cur.Exchanges) {
		f.Exchanges = nil
	}
	if reflect.DeepEqual(f.Inbound, cur.Inbound) {
		f.Inbound = nil
	}
	if reflect.DeepEqual(f.Anomaly, cur.Anomaly) {
		f.Anomaly = nil
	}
	return f
}

func sectionsEqual(f, g Form) bool {
	return reflect.DeepEqual(f.Flows, g.Flows) && reflect.DeepEqual(f.Policies, g.Policies) &&
		reflect.DeepEqual(f.VIPs, g.VIPs) && reflect.DeepEqual(f.Outages, g.Outages) &&
		reflect.DeepEqual(f.Exchanges, g.Exchanges) && protectionEqual(f, g)
}

func validateListLen(name string, n int) error {
	if n > MaxFormListValues {
		return fmt.Errorf("%w: %s: at most %d values in the form", ErrForm, name, MaxFormListValues)
	}
	return nil
}

func validDuration(name, v string, min, max time.Duration) error {
	if v == "" {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < min || d > max {
		return fmt.Errorf("%w: %s %q must be a duration from %s to %s (for example 5m)", ErrForm, name, v, min, max)
	}
	return nil
}

func validInt(name, v string, min, max int) error {
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return fmt.Errorf("%w: %s %q must be a whole number from %d to %d", ErrForm, name, v, min, max)
	}
	return nil
}

func validASNs(name string, list []string) error {
	if err := validateListLen(name, len(list)); err != nil {
		return err
	}
	seen := map[uint64]bool{}
	for _, s := range list {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 {
			return fmt.Errorf("%w: %s: %q must be a non-zero AS number", ErrForm, name, s)
		}
		if seen[n] {
			return fmt.Errorf("%w: %s: duplicate AS %d", ErrForm, name, n)
		}
		seen[n] = true
	}
	return nil
}

func validPrefixList(name string, list []string) error {
	if err := validateListLen(name, len(list)); err != nil {
		return err
	}
	seen := map[netip.Prefix]bool{}
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() {
			return fmt.Errorf("%w: %s: %q must be a prefix without host bits", ErrForm, name, s)
		}
		if seen[p] {
			return fmt.Errorf("%w: %s: duplicate prefix %s", ErrForm, name, p)
		}
		seen[p] = true
	}
	return nil
}

func (f Form) validateNames() error {
	sources := map[string]bool{}
	var names []string
	for _, e := range f.Flows {
		names = append(names, e.Name)
	}
	if err := checkNames("flow", names, sources); err != nil {
		return err
	}
	names = nil
	for _, e := range f.VIPs {
		names = append(names, e.Name)
	}
	if err := checkNames("vip", names, sources); err != nil {
		return err
	}
	names = nil
	for _, e := range f.Outages {
		names = append(names, e.Name)
	}
	if err := checkNames("outage", names, sources); err != nil {
		return err
	}
	names = nil
	for _, e := range f.Policies {
		names = append(names, e.Name)
	}
	return checkNames("rules", names, map[string]bool{})
}

func (f Form) validateSections() error {
	if err := f.validateNames(); err != nil {
		return err
	}
	if err := f.validateFlow(); err != nil {
		return err
	}
	if err := f.validatePolicies(); err != nil {
		return err
	}
	if err := f.validateVIP(); err != nil {
		return err
	}
	if err := f.validateOutage(); err != nil {
		return err
	}
	if err := f.validateExchanges(); err != nil {
		return err
	}
	return f.validateProtection()
}

// checkKeys refuses a list that names one existing entry twice.
func checkKeys(noun string, keys []string) error {
	seen := map[string]bool{}
	for _, k := range keys {
		if k == "" {
			continue
		}
		if seen[k] {
			return fmt.Errorf("%w: %s %s is listed twice", ErrForm, noun, k)
		}
		seen[k] = true
	}
	return nil
}

var instanceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// checkNames refuses a bad or repeated instance name. A blank name is the
// type, so two blanks of one type collide too.
func checkNames(typ string, names []string, seen map[string]bool) error {
	for _, n := range names {
		if n != "" && !instanceName.MatchString(n) {
			return fmt.Errorf("%w: %s name %q must be 1 to 64 letters, digits, dot, dash, or underscore", ErrForm, typ, n)
		}
		eff := n
		if eff == "" {
			eff = typ
		}
		if seen[eff] {
			return fmt.Errorf("%w: two %s entries are named %q; give each its own name", ErrForm, typ, eff)
		}
		seen[eff] = true
	}
	return nil
}

func validateEntryCount(noun string, n int) error {
	if n > MaxFormEntries {
		return fmt.Errorf("%w: at most %d %s in the form", ErrForm, MaxFormEntries, noun)
	}
	return nil
}

func (f Form) validateFlow() error {
	if err := validateEntryCount("flow sources", len(f.Flows)); err != nil {
		return err
	}
	var keys []string
	// Two collectors cannot bind the same UDP address.
	bound := map[string]bool{}
	for _, fl := range f.Flows {
		keys = append(keys, fl.Key)
		if err := validateOneFlow(fl, bound); err != nil {
			return err
		}
	}
	return checkKeys("flow source", keys)
}

func validateOneFlow(fl FormFlow, bound map[string]bool) error {
	if len(fl.Listen) == 0 {
		return fmt.Errorf("%w: flow: at least one listen address (host:port) is required; remove the source instead", ErrForm)
	}
	if err := validateListLen("flow.listen", len(fl.Listen)); err != nil {
		return err
	}
	for _, l := range fl.Listen {
		host, port, err := net.SplitHostPort(l)
		if err != nil {
			return fmt.Errorf("%w: flow.listen %q is not host:port", ErrForm, l)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("%w: flow.listen %q: port must be 0 to 65535", ErrForm, l)
		}
		if host != "" {
			a, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("%w: flow.listen %q: host must be an IP address or empty", ErrForm, l)
			}
			host = a.String()
		}
		key := net.JoinHostPort(host, port)
		if bound[key] {
			return fmt.Errorf("%w: flow.listen: duplicate %s", ErrForm, l)
		}
		bound[key] = true
	}
	if err := validDuration("flow.window", fl.Window, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt("flow.top_n", fl.TopN, 1, 10000); err != nil {
		return err
	}
	if err := validInt("flow.max_targets", fl.MaxTargets, 0, 10000); err != nil {
		return err
	}
	if err := validDuration("flow.tail_interval", fl.TailInterval, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt("flow.aggregate_v4", fl.AggregateV4, 1, 32); err != nil {
		return err
	}
	if err := validInt("flow.aggregate_v6", fl.AggregateV6, 1, 128); err != nil {
		return err
	}
	if fl.MinBytes != "" {
		if _, err := strconv.ParseUint(fl.MinBytes, 10, 64); err != nil {
			return fmt.Errorf("%w: flow.min_bytes %q must be a whole number of bytes, zero or more", ErrForm, fl.MinBytes)
		}
	}
	if err := numberField("flow.min_pct", fl.MinPct, 0, 100); err != nil {
		return err
	}
	return validPrefixList("flow.exclude", fl.Exclude)
}

var ruleActions = map[string]bool{"ignore": true, "allow": true, "deny": true, "static": true, "vip": true}

func (f Form) validatePolicies() error {
	if err := validateEntryCount("rules policies", len(f.Policies)); err != nil {
		return err
	}
	provs := map[string]bool{}
	for _, pr := range f.Providers {
		provs[pr.Name] = true
	}
	var keys []string
	total := 0
	for i, p := range f.Policies {
		keys = append(keys, p.Key)
		total += len(p.Rules)
		if total > MaxFormRules {
			return fmt.Errorf("%w: at most %d rules in the form", ErrForm, MaxFormRules)
		}
		if err := validateOnePolicy(i, p, provs); err != nil {
			return err
		}
	}
	return checkKeys("rules policy", keys)
}

func validateOnePolicy(n int, p FormPolicy, provs map[string]bool) error {
	if len(p.Rules) == 0 {
		return fmt.Errorf("%w: policies[%d]: a rules policy needs at least one rule; remove the policy instead", ErrForm, n)
	}
	if p.GeoIPDB != "" && (!strings.HasPrefix(p.GeoIPDB, "/") || strings.ContainsAny(p.GeoIPDB, "\r\n")) {
		return fmt.Errorf("%w: policies[%d]: geoip_db %q must be an absolute path (mount the file into the container)", ErrForm, n, p.GeoIPDB)
	}
	names := map[string]bool{}
	keys := map[string]bool{}
	for i, r := range p.Rules {
		at := fmt.Sprintf("policies[%d] rules[%d]", n, i)
		if r.Name != "" {
			if strings.ContainsAny(r.Name, "\r\n") {
				return fmt.Errorf("%w: %s: name must be one line", ErrForm, at)
			}
			if names[r.Name] {
				return fmt.Errorf("%w: %s: duplicate name %s", ErrForm, at, r.Name)
			}
			names[r.Name] = true
			at = fmt.Sprintf("policies[%d] rules[%d] (%s)", n, i, r.Name)
		}
		if r.Key != "" {
			if keys[r.Key] {
				return fmt.Errorf("%w: %s: row listed twice", ErrForm, at)
			}
			keys[r.Key] = true
		}
		if !ruleActions[r.Action] {
			return fmt.Errorf("%w: %s: action %q is invalid (want ignore, allow, deny, static, or vip)", ErrForm, at, r.Action)
		}
		for _, name := range r.Providers {
			if !provs[name] {
				return fmt.Errorf("%w: %s: provider %q is not a provider in this form", ErrForm, at, name)
			}
		}
		switch r.Action {
		case "allow", "deny":
			if len(r.Providers) < 1 {
				return fmt.Errorf("%w: %s: %s needs at least one provider", ErrForm, at, r.Action)
			}
		case "static":
			if len(r.Providers) != 1 {
				return fmt.Errorf("%w: %s: static pins exactly one provider", ErrForm, at)
			}
			if r.MaxLossPct == "" {
				return fmt.Errorf("%w: %s: static needs max_loss_pct (the highest loss the pinned path may show)", ErrForm, at)
			}
		default:
			if len(r.Providers) != 0 {
				return fmt.Errorf("%w: %s: %s takes no providers", ErrForm, at, r.Action)
			}
		}
		if r.Action != "static" && (r.MaxLossPct != "" || r.MaxRTT != "") {
			return fmt.Errorf("%w: %s: max_loss_pct and max_rtt are only for static", ErrForm, at)
		}
		if err := numberField(at+" max_loss_pct", r.MaxLossPct, 0, 100); err != nil {
			return err
		}
		if err := validDuration(at+" max_rtt", r.MaxRTT, 0, 24*time.Hour); err != nil {
			return err
		}
		if err := validPrefixList(at+" prefixes", r.Prefixes); err != nil {
			return err
		}
		if err := validASNs(at+" asns", r.ASNs); err != nil {
			return err
		}
		if err := validateListLen(at+" countries", len(r.Countries)); err != nil {
			return err
		}
		for _, c := range r.Countries {
			if len(c) != 2 || strings.Trim(c, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") != "" {
				return fmt.Errorf("%w: %s: country %q must be a two-letter ISO 3166-1 code", ErrForm, at, c)
			}
		}
		switch r.Traffic {
		case "", "transit", "local":
		default:
			return fmt.Errorf("%w: %s: traffic %q is invalid (want transit or local)", ErrForm, at, r.Traffic)
		}
		if len(r.Countries) > 0 && p.GeoIPDB == "" {
			return fmt.Errorf("%w: %s: countries need a geoip_db on the policy", ErrForm, at)
		}
		if len(r.Prefixes) == 0 && len(r.ASNs) == 0 && len(r.Countries) == 0 && r.Traffic == "" {
			return fmt.Errorf("%w: %s: a rule needs at least one of prefixes, asns, countries, or traffic", ErrForm, at)
		}
	}
	return nil
}

func (f Form) validateVIP() error {
	if err := validateEntryCount("vip sources", len(f.VIPs)); err != nil {
		return err
	}
	var keys []string
	for _, v := range f.VIPs {
		keys = append(keys, v.Key)
		if err := validateOneVIP(v); err != nil {
			return err
		}
	}
	return checkKeys("vip source", keys)
}

func validateOneVIP(v FormVIP) error {
	if v.Interval == "" {
		return fmt.Errorf("%w: vip.interval is required (for example 10s)", ErrForm)
	}
	if err := validDuration("vip.interval", v.Interval, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt("vip.max_targets", v.MaxTargets, 1, 100000); err != nil {
		return err
	}
	if len(v.Prefixes) == 0 && len(v.ASNs) == 0 {
		return fmt.Errorf("%w: vip needs at least one prefix or ASN", ErrForm)
	}
	if err := validateListLen("vip.prefixes", len(v.Prefixes)); err != nil {
		return err
	}
	seen := map[netip.Prefix]bool{}
	for i, t := range v.Prefixes {
		p, err := netip.ParsePrefix(t.Prefix)
		if err != nil || p != p.Masked() {
			return fmt.Errorf("%w: vip.prefixes[%d]: prefix %q must be a prefix without host bits", ErrForm, i, t.Prefix)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("%w: vip.prefixes[%d]: a default route is not a VIP prefix", ErrForm, i)
		}
		if seen[p] {
			return fmt.Errorf("%w: vip.prefixes[%d]: duplicate prefix %s", ErrForm, i, p)
		}
		seen[p] = true
		if t.Host != "" {
			h, err := netip.ParseAddr(t.Host)
			if err != nil || !p.Contains(h) {
				return fmt.Errorf("%w: vip.prefixes[%d]: host %q must be an address inside %s", ErrForm, i, t.Host, p)
			}
		}
	}
	return validASNs("vip.asns", v.ASNs)
}

func (f Form) validateOutage() error {
	if err := validateEntryCount("outage sources", len(f.Outages)); err != nil {
		return err
	}
	var keys []string
	for _, o := range f.Outages {
		keys = append(keys, o.Key)
		if err := validateOneOutage(o); err != nil {
			return err
		}
	}
	return checkKeys("outage source", keys)
}

func validateOneOutage(o FormOutage) error {
	if err := validInt("outage.min_prefixes", o.MinPrefixes, 0, 100000); err != nil {
		return err
	}
	if o.MinPrefixes == "1" {
		return fmt.Errorf("%w: outage.min_prefixes cannot be below 2 (one noisy prefix is not an incident)", ErrForm)
	}
	if err := validDuration("outage.window", o.Window, 0, 24*time.Hour); err != nil {
		return err
	}
	if err := numberField("outage.loss_pct", o.LossPct, 0, 100); err != nil {
		return err
	}
	if o.RTTMs != "" {
		v, err := strconv.ParseFloat(o.RTTMs, 64)
		if err != nil || v < 0 {
			return fmt.Errorf("%w: outage.rtt_ms %q must be zero or positive", ErrForm, o.RTTMs)
		}
	}
	if err := validDuration("outage.interval", o.Interval, 0, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt("outage.max_targets", o.MaxTargets, 0, 100000); err != nil {
		return err
	}
	return validASNs("outage.ignore_asns", o.IgnoreASNs)
}

// ---- applying ----

func applySections(root *yaml.Node, cur, next Form) error {
	err := rewriteSection(root, "sources", "flow", cur.Flows, next.Flows, func(n *yaml.Node, e FormFlow) error { applyFlow(n, e); return nil })
	if err == nil {
		err = rewriteSection(root, "sources", "vip", cur.VIPs, next.VIPs, func(n *yaml.Node, e FormVIP) error { applyVIP(n, e); return nil })
	}
	if err == nil {
		err = rewriteSection(root, "sources", "outage", cur.Outages, next.Outages, func(n *yaml.Node, e FormOutage) error { applyOutage(n, e); return nil })
	}
	if err == nil {
		err = applyExchanges(root, cur, next)
	}
	if err == nil {
		err = applyProtection(root, cur, next)
	}
	if err == nil {
		err = rewriteSection(root, "policies", "rules", cur.Policies, next.Policies, applyRules)
	}
	return err
}

// entry is a form row that maps to one plugin entry in the file.
type entry interface{ entryKey() string }

func (e FormFlow) entryKey() string   { return e.Key }
func (e FormVIP) entryKey() string    { return e.Key }
func (e FormOutage) entryKey() string { return e.Key }
func (e FormPolicy) entryKey() string { return e.Key }

// rewriteSection applies a changed list. Entries that are the same as in
// the file are not rewritten, so one edited source leaves its siblings
// byte for byte alone.
func rewriteSection[T entry](root *yaml.Node, listKey, typ string, cur, next []T, apply func(*yaml.Node, T) error) error {
	if reflect.DeepEqual(cur, next) {
		return nil
	}
	keys := make([]string, len(next))
	for i, e := range next {
		keys[i] = e.entryKey()
	}
	var applyErr error
	err := rewriteTyped(root, listKey, typ, keys, func(i int, n *yaml.Node, isNew bool) {
		e := next[i]
		if !isNew {
			for _, c := range cur {
				if c.entryKey() == e.entryKey() && reflect.DeepEqual(c, e) {
					return
				}
			}
		}
		if applyErr == nil {
			applyErr = apply(n, e)
		}
	})
	if err != nil {
		return err
	}
	return applyErr
}

// keepsOrder reports that the form kept the file's entries in file order
// and put every new entry after them. Then each kept entry stays in its
// own slot and a dropped one just leaves, so removing a policy does not
// move the ones after it past a policy of another type.
func keepsOrder(keys []string, slots []int) bool {
	pos := map[string]int{}
	for n, i := range slots {
		pos[strconv.Itoa(i)] = n
	}
	prev, newSeen := -1, false
	for _, k := range keys {
		if k == "" {
			newSeen = true
			continue
		}
		if newSeen || pos[k] <= prev {
			return false
		}
		prev = pos[k]
	}
	return true
}

// placeTyped returns content with the typed entries replaced by next. In
// order mode the kept entries keep their slots; otherwise next fills the
// slots in form order. Entries beyond the slots go after the last slot.
func placeTyped(content []*yaml.Node, slots []int, next []*yaml.Node, inOrder bool) []*yaml.Node {
	isSlot := map[int]bool{}
	for _, i := range slots {
		isSlot[i] = true
	}
	kept := map[*yaml.Node]bool{}
	for _, n := range next {
		kept[n] = true
	}
	last := slots[len(slots)-1]
	var out []*yaml.Node
	j := 0
	for i, item := range content {
		switch {
		case !isSlot[i]:
			out = append(out, item)
		case inOrder:
			if kept[item] {
				out = append(out, item)
			}
		case j < len(next):
			out = append(out, next[j])
			j++
		}
		if i != last {
			continue
		}
		if inOrder {
			for _, n := range next {
				if !isOld(n, content, slots) {
					out = append(out, n)
				}
			}
		} else {
			out = append(out, next[j:]...)
		}
	}
	return out
}

func isOld(n *yaml.Node, content []*yaml.Node, slots []int) bool {
	for _, i := range slots {
		if content[i] == n {
			return true
		}
	}
	return false
}

// rewriteTyped rewrites the entries of one plugin type in a top-level
// list. An entry with a key is the file's entry at that index and keeps
// the keys the form does not show; an entry with no key is new. The
// entries fill the slots the type already holds, in form order, so
// entries of other types keep their place. Extra entries go after the
// last slot, and entries the form dropped are removed. edit is called for
// each entry.
func rewriteTyped(root *yaml.Node, listKey, typ string, keys []string, edit func(i int, n *yaml.Node, isNew bool)) error {
	seq, has := sequenceChild(root, listKey)
	var slots []int
	if has {
		for i, item := range seq.Content {
			if item.Kind == yaml.MappingNode && scalar(item, "type") == typ {
				slots = append(slots, i)
			}
		}
	}
	old := map[string]*yaml.Node{}
	for _, i := range slots {
		old[strconv.Itoa(i)] = seq.Content[i]
	}
	next := make([]*yaml.Node, 0, len(keys))
	used := map[*yaml.Node]bool{}
	for i, k := range keys {
		var n *yaml.Node
		isNew := k == ""
		if isNew {
			n = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			setOrDelete(n, "type", typ, "!!str")
		} else {
			n = old[k]
			if n == nil {
				return fmt.Errorf("%w: %s entry %s is not in the file anymore; reload the form", ErrForm, typ, k)
			}
			if used[n] {
				return fmt.Errorf("%w: %s entry %s is listed twice", ErrForm, typ, k)
			}
		}
		used[n] = true
		edit(i, n, isNew)
		next = append(next, n)
	}
	if len(next) == 0 && !has {
		return nil
	}
	if !has {
		seq = ensureSequence(root, listKey)
	}
	if len(slots) == 0 {
		seq.Content = append(seq.Content, next...)
	} else {
		seq.Content = placeTyped(seq.Content, slots, next, keepsOrder(keys, slots))
	}
	if len(seq.Content) == 0 {
		deleteKey(root, listKey)
	}
	return nil
}

// configOf is the source's config mapping. It is created when needed and
// dropped by trimConfig when it ends up empty.
func configOf(src *yaml.Node) *yaml.Node { return ensureMapping(src, "config") }

func trimConfig(src *yaml.Node) {
	if cfg, ok := mappingChild(src, "config"); ok && len(cfg.Content) == 0 {
		deleteKey(src, "config")
	}
}

// setStringList writes a list of strings. Empty deletes the key. An
// existing sequence keeps its style; a new one is a flow list.
func setStringList(m *yaml.Node, key string, vals []string, tag string) {
	if len(vals) == 0 {
		deleteKey(m, key)
		return
	}
	seq, ok := sequenceChild(m, key)
	if !ok {
		deleteKey(m, key)
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, seq)
	}
	seq.Content = nil
	for _, v := range vals {
		t := tag
		if t == "!!int" {
			t = plainTag(v, t)
		}
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: t, Value: v})
	}
}

func applyFlow(src *yaml.Node, fl FormFlow) {
	setOrDelete(src, "name", fl.Name, "!!str")
	cfg := configOf(src)
	// One address is written as a plain string, several as a list.
	if len(fl.Listen) == 1 {
		if n, _ := child(cfg, "listen"); n != nil && n.Kind == yaml.SequenceNode {
			setStringList(cfg, "listen", fl.Listen, "!!str")
		} else {
			setOrDelete(cfg, "listen", fl.Listen[0], "!!str")
		}
	} else {
		setStringList(cfg, "listen", fl.Listen, "!!str")
	}
	setOrDelete(cfg, "window", fl.Window, "!!str")
	setOrDelete(cfg, "top_n", fl.TopN, "!!int")
	setOrDelete(cfg, "max_targets", fl.MaxTargets, "!!int")
	setOrDelete(cfg, "tail_interval", fl.TailInterval, "!!str")
	setOrDelete(cfg, "min_bytes", fl.MinBytes, "!!int")
	setOrDelete(cfg, "min_pct", fl.MinPct, "!!float")
	setOrDelete(cfg, "aggregate_v4", fl.AggregateV4, "!!int")
	setOrDelete(cfg, "aggregate_v6", fl.AggregateV6, "!!int")
	setStringList(cfg, "exclude", fl.Exclude, "!!str")
}

func applyVIP(src *yaml.Node, v FormVIP) {
	setOrDelete(src, "name", v.Name, "!!str")
	cfg := configOf(src)
	setOrDelete(cfg, "interval", v.Interval, "!!str")
	setOrDelete(cfg, "max_targets", v.MaxTargets, "!!int")
	seq := ensureSequence(cfg, "prefixes")
	old := map[string]*yaml.Node{}
	for _, item := range seq.Content {
		if item.Kind == yaml.MappingNode {
			if p := scalar(item, "prefix"); p != "" {
				old[p] = item
			}
		}
	}
	var next []*yaml.Node
	used := map[*yaml.Node]bool{}
	for _, t := range v.Prefixes {
		node := old[t.Key]
		if t.Key == "" || node == nil || used[node] {
			node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		used[node] = true
		setOrDelete(node, "prefix", t.Prefix, "!!str")
		setOrDelete(node, "host", t.Host, "!!str")
		next = append(next, node)
	}
	if len(next) == 0 {
		deleteKey(cfg, "prefixes")
	} else {
		seq.Content = next
	}
	setStringList(cfg, "asns", v.ASNs, "!!int")
}

func applyOutage(src *yaml.Node, o FormOutage) {
	setOrDelete(src, "name", o.Name, "!!str")
	cfg := configOf(src)
	setOrDelete(cfg, "min_prefixes", o.MinPrefixes, "!!int")
	setOrDelete(cfg, "window", o.Window, "!!str")
	setOrDelete(cfg, "loss_pct", o.LossPct, "!!float")
	setOrDelete(cfg, "rtt_ms", o.RTTMs, "!!float")
	setOrDelete(cfg, "interval", o.Interval, "!!str")
	setOrDelete(cfg, "max_targets", o.MaxTargets, "!!int")
	setStringList(cfg, "ignore_asns", o.IgnoreASNs, "!!int")
	trimConfig(src)
}

func applyRules(node *yaml.Node, p FormPolicy) error {
	setOrDelete(node, "name", p.Name, "!!str")
	cfg := ensureMapping(node, "config")
	setOrDelete(cfg, "geoip_db", p.GeoIPDB, "!!str")
	rules := ensureSequence(cfg, "rules")
	old := map[string]*yaml.Node{}
	for i, item := range rules.Content {
		if item.Kind == yaml.MappingNode {
			old[strconv.Itoa(i)] = item
		}
	}
	var next []*yaml.Node
	used := map[*yaml.Node]bool{}
	for _, r := range p.Rules {
		var n *yaml.Node
		if r.Key != "" {
			n = old[r.Key]
			if n == nil {
				return fmt.Errorf("%w: rule %s is not in the file anymore; reload the form", ErrForm, r.Key)
			}
			if used[n] {
				return fmt.Errorf("%w: rule %s is listed twice", ErrForm, r.Key)
			}
		} else {
			n = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		used[n] = true
		setOrDelete(n, "name", r.Name, "!!str")
		setOrDelete(n, "action", r.Action, "!!str")
		setStringList(n, "providers", r.Providers, "!!str")
		setStringList(n, "prefixes", r.Prefixes, "!!str")
		setStringList(n, "asns", r.ASNs, "!!int")
		setStringList(n, "countries", r.Countries, "!!str")
		setOrDelete(n, "traffic", r.Traffic, "!!str")
		setOrDelete(n, "max_loss_pct", r.MaxLossPct, "!!float")
		setOrDelete(n, "max_rtt", r.MaxRTT, "!!str")
		next = append(next, n)
	}
	rules.Content = next
	return nil
}
