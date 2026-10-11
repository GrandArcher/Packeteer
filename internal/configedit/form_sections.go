package configedit

import (
	"fmt"
	"net"
	"net/netip"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Form sections added in #130 and made multi-instance in #226: the flow,
// vip, and outage sources and the rules policy. Each is a list with one
// entry per instance in the file. A nil list in a request means "leave it
// alone", so an older client that does not know the section cannot remove
// it; an empty list removes every instance. ParseForm always fills them.
// An entry's Key is its position among the instances of its type when the
// form was loaded, and empty means a new instance. The order of the list
// is the order of the instances in the file. Applying a section edits the
// YAML text only; Save runs the same checks as a start, and nothing here
// can turn inject on or announce.

// Section limits. A larger edit belongs in the YAML.
const (
	MaxFormRules      = 1000
	MaxFormListValues = 4096
	MaxFormInstances  = 32
)

// FormFlow is one `flow` source. The problems, transit, and subranges
// blocks are kept as they are while the source stays. TopN is the priority
// tier, MaxTargets the larger capped set, and TailInterval the interval
// for the rest. AggregateV4 and AggregateV6 are the prefix lengths used
// for a destination no learned route covers.
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

// FormRulePolicy is one `rules` policy. Policies of other types in the
// chain stay in the YAML. GeoIPDB is the absolute path of the country
// database a rule with countries reads; Packeteer does not fetch it.
type FormRulePolicy struct {
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

// FormVIP is one `vip` source.
type FormVIP struct {
	Key        string       `json:"key"`
	Name       string       `json:"name"`
	Interval   string       `json:"interval"`
	MaxTargets string       `json:"max_targets"`
	Prefixes   []FormTarget `json:"prefixes"`
	ASNs       []string     `json:"asns"`
}

// FormOutage is one `outage` source.
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
	for i, src := range entriesOf(root, "sources", "flow") {
		fl := FormFlow{Key: strconv.Itoa(i), Name: scalar(src, "name"), Listen: []string{}, Exclude: []string{}}
		if cfg, ok := mappingChild(src, "config"); ok {
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

	f.RulePolicies = []FormRulePolicy{}
	for i, node := range entriesOf(root, "policies", "rules") {
		pol := FormRulePolicy{Key: strconv.Itoa(i), Name: scalar(node, "name"), Rules: []FormRule{}}
		if cfg, ok := mappingChild(node, "config"); ok {
			pol.GeoIPDB = scalar(cfg, "geoip_db")
			if seq, ok := sequenceChild(cfg, "rules"); ok {
				for j, item := range seq.Content {
					if item.Kind != yaml.MappingNode {
						return fmt.Errorf("%w: policies rules must be a list of mappings", ErrForm)
					}
					pol.Rules = append(pol.Rules, FormRule{
						Key: strconv.Itoa(j), Name: scalar(item, "name"), Action: scalar(item, "action"),
						Providers: scalarList(item, "providers"), Prefixes: scalarList(item, "prefixes"),
						ASNs: scalarList(item, "asns"), Countries: scalarList(item, "countries"),
						Traffic: scalar(item, "traffic"), MaxLossPct: scalar(item, "max_loss_pct"),
						MaxRTT: scalar(item, "max_rtt"),
					})
				}
			}
		}
		f.RulePolicies = append(f.RulePolicies, pol)
	}

	f.VIPs = []FormVIP{}
	for i, src := range entriesOf(root, "sources", "vip") {
		vip := FormVIP{Key: strconv.Itoa(i), Name: scalar(src, "name"), Prefixes: []FormTarget{}, ASNs: []string{}}
		if cfg, ok := mappingChild(src, "config"); ok {
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
	for i, src := range entriesOf(root, "sources", "outage") {
		out := FormOutage{Key: strconv.Itoa(i), Name: scalar(src, "name"), IgnoreASNs: []string{}}
		if cfg, ok := mappingChild(src, "config"); ok {
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

// entriesOf lists the mappings of one type in a top-level list (sources or
// policies), in file order.
func entriesOf(root *yaml.Node, listKey, typ string) []*yaml.Node {
	seq, ok := sequenceChild(root, listKey)
	if !ok {
		return nil
	}
	var out []*yaml.Node
	for _, item := range seq.Content {
		if item.Kind == yaml.MappingNode && scalar(item, "type") == typ {
			out = append(out, item)
		}
	}
	return out
}

// resolveEntries maps the keys of a submitted list to nodes: an existing
// instance for a key, a new one for an empty key.
func resolveEntries(root *yaml.Node, listKey, typ string, keys []string) ([]*yaml.Node, error) {
	have := entriesOf(root, listKey, typ)
	used := map[int]bool{}
	out := make([]*yaml.Node, 0, len(keys))
	for _, k := range keys {
		if k == "" {
			n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			setOrDelete(n, "type", typ, "!!str")
			out = append(out, n)
			continue
		}
		i, err := strconv.Atoi(k)
		if err != nil || i < 0 || i >= len(have) {
			return nil, fmt.Errorf("%w: %s %s is not in the file anymore; reload the form", ErrForm, typ, k)
		}
		if used[i] {
			return nil, fmt.Errorf("%w: %s %s is listed twice", ErrForm, typ, k)
		}
		used[i] = true
		out = append(out, have[i])
	}
	return out, nil
}

// placeEntries rewrites the instances of one type in a top-level list. The
// wanted nodes take the file positions the old instances had, in order, so
// entries of other types do not move; extra nodes go at the end and
// surplus positions are removed. An emptied list is deleted.
func placeEntries(root *yaml.Node, listKey, typ string, want []*yaml.Node) {
	seq, ok := sequenceChild(root, listKey)
	if !ok {
		if len(want) == 0 {
			return
		}
		seq = ensureSequence(root, listKey)
	}
	var out []*yaml.Node
	w := 0
	for _, item := range seq.Content {
		if item.Kind == yaml.MappingNode && scalar(item, "type") == typ {
			if w < len(want) {
				out = append(out, want[w])
				w++
			}
			continue
		}
		out = append(out, item)
	}
	out = append(out, want[w:]...)
	seq.Content = out
	if len(out) == 0 {
		deleteKey(root, listKey)
	}
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
		fl.Listen = trimAll(fl.Listen)
		fl.Exclude = trimAll(fl.Exclude)
		for _, p := range []*string{&fl.Key, &fl.Name, &fl.Window, &fl.TopN, &fl.MaxTargets, &fl.TailInterval, &fl.MinBytes, &fl.MinPct, &fl.AggregateV4, &fl.AggregateV6} {
			*p = strings.TrimSpace(*p)
		}
	}
	for i := range f.RulePolicies {
		p := &f.RulePolicies[i]
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
		for _, p := range []*string{&o.Key, &o.Name, &o.MinPrefixes, &o.Window, &o.LossPct, &o.RTTMs, &o.Interval, &o.MaxTargets} {
			*p = strings.TrimSpace(*p)
		}
		o.IgnoreASNs = trimAll(o.IgnoreASNs)
	}
}

// fillSections gives a nil section the file's current value, so a request
// that omits it changes nothing. Every list becomes non-nil.
func (f *Form) fillSections(cur Form) {
	f.fillProtection(cur)
	if f.Flows == nil {
		f.Flows = cur.Flows
	}
	if f.RulePolicies == nil {
		f.RulePolicies = cur.RulePolicies
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
	for i := range f.RulePolicies {
		for j := range f.RulePolicies[i].Rules {
			r := &f.RulePolicies[i].Rules[j]
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
	if reflect.DeepEqual(f.RulePolicies, cur.RulePolicies) {
		f.RulePolicies = nil
	}
	if reflect.DeepEqual(f.VIPs, cur.VIPs) {
		f.VIPs = nil
	}
	if reflect.DeepEqual(f.Outages, cur.Outages) {
		f.Outages = nil
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
	return reflect.DeepEqual(f.Flows, g.Flows) && reflect.DeepEqual(f.RulePolicies, g.RulePolicies) &&
		reflect.DeepEqual(f.VIPs, g.VIPs) && reflect.DeepEqual(f.Outages, g.Outages) && protectionEqual(f, g)
}

// validateInstanceNames checks the names of the instances of one type. The
// loader keys instances by name, or by type when there is none, and
// refuses two with the same key.
func validateInstanceNames(typ string, names []string) error {
	seen := map[string]bool{}
	for i, n := range names {
		if strings.ContainsAny(n, "\r\n") {
			return fmt.Errorf("%w: %s[%d]: name must be one line", ErrForm, typ, i)
		}
		if n == "" {
			n = typ
		}
		if seen[n] {
			return fmt.Errorf("%w: %s[%d]: duplicate instance name %q (set a unique name)", ErrForm, typ, i, n)
		}
		seen[n] = true
	}
	return nil
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

func (f Form) validateSections() error {
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
	return f.validateProtection()
}

func (f Form) validateFlow() error {
	if len(f.Flows) > MaxFormInstances {
		return fmt.Errorf("%w: at most %d flow sources in the form", ErrForm, MaxFormInstances)
	}
	names := make([]string, len(f.Flows))
	for i, fl := range f.Flows {
		names[i] = fl.Name
	}
	if err := validateInstanceNames("flow", names); err != nil {
		return err
	}
	// Two collectors cannot bind the same UDP address.
	seen := map[string]bool{}
	for i := range f.Flows {
		if err := validateFlowAt(fmt.Sprintf("flow[%d]", i), f.Flows[i], seen); err != nil {
			return err
		}
	}
	return nil
}

func validateFlowAt(at string, fl FormFlow, seen map[string]bool) error {
	if len(fl.Listen) == 0 {
		return fmt.Errorf("%w: %s: at least one listen address (host:port) is required; remove the source to drop it", ErrForm, at)
	}
	if err := validateListLen(at+".listen", len(fl.Listen)); err != nil {
		return err
	}
	for _, l := range fl.Listen {
		host, port, err := net.SplitHostPort(l)
		if err != nil {
			return fmt.Errorf("%w: %s.listen %q is not host:port", ErrForm, at, l)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("%w: %s.listen %q: port must be 0 to 65535", ErrForm, at, l)
		}
		if host != "" {
			a, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("%w: %s.listen %q: host must be an IP address or empty", ErrForm, at, l)
			}
			host = a.String()
		}
		key := net.JoinHostPort(host, port)
		if seen[key] {
			return fmt.Errorf("%w: %s.listen: duplicate %s", ErrForm, at, l)
		}
		seen[key] = true
	}
	if err := validDuration(at+".window", fl.Window, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt(at+".top_n", fl.TopN, 1, 10000); err != nil {
		return err
	}
	if err := validInt(at+".max_targets", fl.MaxTargets, 0, 10000); err != nil {
		return err
	}
	if err := validDuration(at+".tail_interval", fl.TailInterval, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if fl.MinBytes != "" {
		if _, err := strconv.ParseUint(fl.MinBytes, 10, 64); err != nil {
			return fmt.Errorf("%w: %s.min_bytes %q must be a whole number of bytes, zero or more", ErrForm, at, fl.MinBytes)
		}
	}
	if err := numberField(at+".min_pct", fl.MinPct, 0, 100); err != nil {
		return err
	}
	if err := validInt(at+".aggregate_v4", fl.AggregateV4, 1, 32); err != nil {
		return err
	}
	if err := validInt(at+".aggregate_v6", fl.AggregateV6, 1, 128); err != nil {
		return err
	}
	return validPrefixList(at+".exclude", fl.Exclude)
}

var ruleActions = map[string]bool{"ignore": true, "allow": true, "deny": true, "static": true, "vip": true}

func (f Form) validatePolicies() error {
	if len(f.RulePolicies) > MaxFormInstances {
		return fmt.Errorf("%w: at most %d rules policies in the form", ErrForm, MaxFormInstances)
	}
	names := make([]string, len(f.RulePolicies))
	for i, p := range f.RulePolicies {
		names[i] = p.Name
	}
	if err := validateInstanceNames("rules", names); err != nil {
		return err
	}
	provs := map[string]bool{}
	for _, pr := range f.Providers {
		provs[pr.Name] = true
	}
	for i, p := range f.RulePolicies {
		if err := validateRulePolicy(fmt.Sprintf("policy[%d] ", i), p, provs); err != nil {
			return err
		}
	}
	return nil
}

func validateRulePolicy(prefix string, p FormRulePolicy, provs map[string]bool) error {
	if len(p.Rules) == 0 {
		return fmt.Errorf("%w: %sneeds at least one rule; remove the policy to drop it", ErrForm, prefix)
	}
	if len(p.Rules) > MaxFormRules {
		return fmt.Errorf("%w: %sat most %d rules in the form", ErrForm, prefix, MaxFormRules)
	}
	if p.GeoIPDB != "" && (!path.IsAbs(p.GeoIPDB) || strings.ContainsAny(p.GeoIPDB, "\r\n")) {
		return fmt.Errorf("%w: %sgeoip_db %q must be an absolute path (mount the file into the container)", ErrForm, prefix, p.GeoIPDB)
	}
	names := map[string]bool{}
	keys := map[string]bool{}
	for i, r := range p.Rules {
		at := fmt.Sprintf("%srules[%d]", prefix, i)
		if r.Name != "" {
			if strings.ContainsAny(r.Name, "\r\n") {
				return fmt.Errorf("%w: %s: name must be one line", ErrForm, at)
			}
			if names[r.Name] {
				return fmt.Errorf("%w: %s: duplicate name %s", ErrForm, at, r.Name)
			}
			names[r.Name] = true
			at = fmt.Sprintf("%srules[%d] (%s)", prefix, i, r.Name)
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
		if len(r.Prefixes) == 0 && len(r.ASNs) == 0 && len(r.Countries) == 0 && r.Traffic == "" {
			return fmt.Errorf("%w: %s: a rule needs at least one of prefixes, asns, countries, or traffic", ErrForm, at)
		}
		if len(r.Countries) > 0 && p.GeoIPDB == "" {
			return fmt.Errorf("%w: %s: countries need geoip_db on this policy", ErrForm, at)
		}
	}
	return nil
}

func (f Form) validateVIP() error {
	if len(f.VIPs) > MaxFormInstances {
		return fmt.Errorf("%w: at most %d vip sources in the form", ErrForm, MaxFormInstances)
	}
	names := make([]string, len(f.VIPs))
	for i, v := range f.VIPs {
		names[i] = v.Name
	}
	if err := validateInstanceNames("vip", names); err != nil {
		return err
	}
	for i, v := range f.VIPs {
		if err := validateVIPAt(fmt.Sprintf("vip[%d]", i), v); err != nil {
			return err
		}
	}
	return nil
}

func validateVIPAt(at string, v FormVIP) error {
	if v.Interval == "" {
		return fmt.Errorf("%w: %s.interval is required (for example 10s)", ErrForm, at)
	}
	if err := validDuration(at+".interval", v.Interval, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt(at+".max_targets", v.MaxTargets, 1, 10000); err != nil {
		return err
	}
	if len(v.Prefixes) == 0 && len(v.ASNs) == 0 {
		return fmt.Errorf("%w: %s needs at least one prefix or ASN", ErrForm, at)
	}
	if err := validateListLen(at+".prefixes", len(v.Prefixes)); err != nil {
		return err
	}
	seen := map[netip.Prefix]bool{}
	for i, t := range v.Prefixes {
		p, err := netip.ParsePrefix(t.Prefix)
		if err != nil || p != p.Masked() {
			return fmt.Errorf("%w: %s.prefixes[%d]: prefix %q must be a prefix without host bits", ErrForm, at, i, t.Prefix)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("%w: %s.prefixes[%d]: a default route is not a VIP prefix", ErrForm, at, i)
		}
		if seen[p] {
			return fmt.Errorf("%w: %s.prefixes[%d]: duplicate prefix %s", ErrForm, at, i, p)
		}
		seen[p] = true
		if t.Host != "" {
			h, err := netip.ParseAddr(t.Host)
			if err != nil || !p.Contains(h) {
				return fmt.Errorf("%w: %s.prefixes[%d]: host %q must be an address inside %s", ErrForm, at, i, t.Host, p)
			}
		}
	}
	return validASNs(at+".asns", v.ASNs)
}

func (f Form) validateOutage() error {
	if len(f.Outages) > MaxFormInstances {
		return fmt.Errorf("%w: at most %d outage sources in the form", ErrForm, MaxFormInstances)
	}
	names := make([]string, len(f.Outages))
	for i, o := range f.Outages {
		names[i] = o.Name
	}
	if err := validateInstanceNames("outage", names); err != nil {
		return err
	}
	for i, o := range f.Outages {
		if err := validateOutageAt(fmt.Sprintf("outage[%d]", i), o); err != nil {
			return err
		}
	}
	return nil
}

func validateOutageAt(at string, o FormOutage) error {
	if err := validInt(at+".min_prefixes", o.MinPrefixes, 0, 10000); err != nil {
		return err
	}
	if o.MinPrefixes == "1" {
		return fmt.Errorf("%w: %s.min_prefixes cannot be below 2 (one noisy prefix is not an incident)", ErrForm, at)
	}
	if err := validDuration(at+".window", o.Window, 0, 24*time.Hour); err != nil {
		return err
	}
	if err := numberField(at+".loss_pct", o.LossPct, 0, 100); err != nil {
		return err
	}
	if o.RTTMs != "" {
		v, err := strconv.ParseFloat(o.RTTMs, 64)
		if err != nil || v < 0 {
			return fmt.Errorf("%w: %s.rtt_ms %q must be zero or positive", ErrForm, at, o.RTTMs)
		}
	}
	if err := validDuration(at+".interval", o.Interval, 0, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt(at+".max_targets", o.MaxTargets, 0, 10000); err != nil {
		return err
	}
	return validASNs(at+".ignore_asns", o.IgnoreASNs)
}

// ---- applying ----

func applySections(root *yaml.Node, cur, next Form) error {
	if !reflect.DeepEqual(cur.Flows, next.Flows) {
		if err := applyFlows(root, next.Flows); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(cur.VIPs, next.VIPs) {
		if err := applyVIPs(root, next.VIPs); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(cur.Outages, next.Outages) {
		if err := applyOutages(root, next.Outages); err != nil {
			return err
		}
	}
	if err := applyProtection(root, cur, next); err != nil {
		return err
	}
	if !reflect.DeepEqual(cur.RulePolicies, next.RulePolicies) {
		return applyRulePolicies(root, next.RulePolicies)
	}
	return nil
}

// configOf is the instance's config mapping. It is created when needed
// and dropped by trimConfig when it ends up empty.
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

func applyFlows(root *yaml.Node, flows []FormFlow) error {
	keys := make([]string, len(flows))
	for i, fl := range flows {
		keys[i] = fl.Key
	}
	nodes, err := resolveEntries(root, "sources", "flow", keys)
	if err != nil {
		return err
	}
	for i, fl := range flows {
		setOrDelete(nodes[i], "name", fl.Name, "!!str")
		cfg := configOf(nodes[i])
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
	placeEntries(root, "sources", "flow", nodes)
	return nil
}

func applyVIPs(root *yaml.Node, vips []FormVIP) error {
	keys := make([]string, len(vips))
	for i, v := range vips {
		keys[i] = v.Key
	}
	nodes, err := resolveEntries(root, "sources", "vip", keys)
	if err != nil {
		return err
	}
	for i, v := range vips {
		setOrDelete(nodes[i], "name", v.Name, "!!str")
		cfg := configOf(nodes[i])
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
	placeEntries(root, "sources", "vip", nodes)
	return nil
}

func applyOutages(root *yaml.Node, outages []FormOutage) error {
	keys := make([]string, len(outages))
	for i, o := range outages {
		keys[i] = o.Key
	}
	nodes, err := resolveEntries(root, "sources", "outage", keys)
	if err != nil {
		return err
	}
	for i, o := range outages {
		setOrDelete(nodes[i], "name", o.Name, "!!str")
		cfg := configOf(nodes[i])
		setOrDelete(cfg, "min_prefixes", o.MinPrefixes, "!!int")
		setOrDelete(cfg, "window", o.Window, "!!str")
		setOrDelete(cfg, "loss_pct", o.LossPct, "!!float")
		setOrDelete(cfg, "rtt_ms", o.RTTMs, "!!float")
		setOrDelete(cfg, "interval", o.Interval, "!!str")
		setOrDelete(cfg, "max_targets", o.MaxTargets, "!!int")
		setStringList(cfg, "ignore_asns", o.IgnoreASNs, "!!int")
		trimConfig(nodes[i])
	}
	placeEntries(root, "sources", "outage", nodes)
	return nil
}

func applyRulePolicies(root *yaml.Node, policies []FormRulePolicy) error {
	keys := make([]string, len(policies))
	for i, p := range policies {
		keys[i] = p.Key
	}
	nodes, err := resolveEntries(root, "policies", "rules", keys)
	if err != nil {
		return err
	}
	for i, p := range policies {
		setOrDelete(nodes[i], "name", p.Name, "!!str")
		cfg := ensureMapping(nodes[i], "config")
		setOrDelete(cfg, "geoip_db", p.GeoIPDB, "!!str")
		if err := applyRules(cfg, p.Rules); err != nil {
			return err
		}
	}
	placeEntries(root, "policies", "rules", nodes)
	return nil
}

func applyRules(cfg *yaml.Node, in []FormRule) error {
	rules := ensureSequence(cfg, "rules")
	old := map[string]*yaml.Node{}
	for i, item := range rules.Content {
		if item.Kind == yaml.MappingNode {
			old[strconv.Itoa(i)] = item
		}
	}
	var next []*yaml.Node
	used := map[*yaml.Node]bool{}
	for _, r := range in {
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
