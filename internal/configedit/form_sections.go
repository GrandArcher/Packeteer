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

// Form sections added in #130 and extended in #226: every flow, vip, and
// outage source and every rules policy. Each section is a list on Form. A
// nil list in a request means "leave it alone", so an older client that
// does not know the section cannot remove it. ParseForm always fills them.
// Applying a section edits the YAML text only; Save runs the same checks
// as a start, and nothing here can turn inject on or announce.

// Section limits. A larger edit belongs in the YAML.
const (
	MaxFormRules      = 1000
	MaxFormSources    = 64
	MaxFormListValues = 4096
)

// FormFlow is one `flow` source. Key is the source's position among the
// file's flow sources when the form was loaded; empty means a new source.
// Name is the instance name; several sources of one type each need a
// unique one (empty means the type name).
// problems, transit, and subranges blocks are kept as they are while the
// source stays. TopN is the priority tier, MaxTargets the larger capped
// set, and TailInterval the interval for the rest. AggregateV4 and
// AggregateV6 are the lengths a destination with no covering learned
// prefix is aggregated to.
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

// FormRulesPolicy is one `rules` policy. Key is its position among the
// file's rules policies when the form was loaded; empty means a new one.
// Policies are evaluated in file order, so list order is chain order
// among the rules policies; other policy types keep their slots. A
// policy needs at least one rule; drop the entry to remove it. GeoIPDB is
// the absolute path of a database you mount; a country rule needs it.
type FormRulesPolicy struct {
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

// FormVIP is one `vip` source. Key works as in FormFlow.
type FormVIP struct {
	Key        string       `json:"key"`
	Name       string       `json:"name"`
	Interval   string       `json:"interval"`
	MaxTargets string       `json:"max_targets"`
	Prefixes   []FormTarget `json:"prefixes"`
	ASNs       []string     `json:"asns"`
}

// FormOutage is one `outage` source. Key works as in FormFlow.
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
	for i, src := range typedNodes(root, "sources", "flow") {
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

	f.Policies = []FormRulesPolicy{}
	for i, node := range typedNodes(root, "policies", "rules") {
		pol := FormRulesPolicy{Key: strconv.Itoa(i), Name: scalar(node, "name"), Rules: []FormRule{}}
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
		f.Policies = append(f.Policies, pol)
	}

	f.VIPs = []FormVIP{}
	for i, src := range typedNodes(root, "sources", "vip") {
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
	for i, src := range typedNodes(root, "sources", "outage") {
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

// typedNodes are the mapping entries of the sequence at key whose type is
// typ, in file order. A form Key is an index into this list.
func typedNodes(root *yaml.Node, key, typ string) []*yaml.Node {
	seq, ok := sequenceChild(root, key)
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

// fillSections gives a nil section the file's current value, so a request
// that omits it changes nothing. Every list inside an entry becomes
// non-nil, so equality with the parsed file does not depend on null
// versus empty.
func (f *Form) fillSections(cur Form) {
	f.fillProtection(cur)
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
		p := &f.Policies[i]
		if p.Rules == nil {
			p.Rules = []FormRule{}
		}
		for j := range p.Rules {
			r := &p.Rules[j]
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
		reflect.DeepEqual(f.VIPs, g.VIPs) && reflect.DeepEqual(f.Outages, g.Outages) && protectionEqual(f, g)
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

// checkEntries rejects a key listed twice and an instance name used
// twice among entries of one type. The loader requires unique instance
// names within sources and within policies, and an unnamed entry is named
// after its type.
func checkEntries(section, typ string, keys, names []string) error {
	seenKey := map[string]bool{}
	for _, k := range keys {
		if k == "" {
			continue
		}
		if seenKey[k] {
			return fmt.Errorf("%w: %s: row %s listed twice", ErrForm, section, k)
		}
		seenKey[k] = true
	}
	seenName := map[string]bool{}
	for _, n := range names {
		if strings.ContainsAny(n, "\r\n") {
			return fmt.Errorf("%w: %s: name must be one line", ErrForm, section)
		}
		if n == "" {
			n = typ
		}
		if seenName[n] {
			return fmt.Errorf("%w: %s: more than one %s entry is called %q; give each a unique name", ErrForm, section, typ, n)
		}
		seenName[n] = true
	}
	return nil
}

func (f Form) validateFlow() error {
	if len(f.Flows) > MaxFormSources {
		return fmt.Errorf("%w: at most %d flow sources in the form", ErrForm, MaxFormSources)
	}
	var keys, names []string
	for _, fl := range f.Flows {
		keys = append(keys, fl.Key)
		names = append(names, fl.Name)
	}
	if err := checkEntries("flow", "flow", keys, names); err != nil {
		return err
	}
	listens := map[string]bool{}
	for i, fl := range f.Flows {
		if err := validateFlowSource(fmt.Sprintf("flow[%d]", i), fl, listens); err != nil {
			return err
		}
	}
	return nil
}

// validateFlowSource also rejects a listen address another flow source
// already uses: two collectors cannot bind the same UDP port.
func validateFlowSource(at string, fl FormFlow, listens map[string]bool) error {
	if len(fl.Listen) == 0 {
		return fmt.Errorf("%w: %s: at least one listen address (host:port) is required; remove the source instead", ErrForm, at)
	}
	if err := validateListLen(at+".listen", len(fl.Listen)); err != nil {
		return err
	}
	seen := map[string]bool{}
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
		if port != "0" {
			if listens[key] {
				return fmt.Errorf("%w: %s.listen %s is already used by another flow source", ErrForm, at, l)
			}
			listens[key] = true
		}
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
	if len(f.Policies) > MaxFormSources {
		return fmt.Errorf("%w: at most %d rules policies in the form", ErrForm, MaxFormSources)
	}
	var keys, names []string
	total := 0
	provs := map[string]bool{}
	for _, pr := range f.Providers {
		provs[pr.Name] = true
	}
	for i, p := range f.Policies {
		keys = append(keys, p.Key)
		names = append(names, p.Name)
		total += len(p.Rules)
		if err := validRulesPolicy(fmt.Sprintf("policies[%d]", i), p, provs); err != nil {
			return err
		}
	}
	if total > MaxFormRules {
		return fmt.Errorf("%w: at most %d rules in the form", ErrForm, MaxFormRules)
	}
	return checkEntries("policies", "rules", keys, names)
}

func validRulesPolicy(pat string, p FormRulesPolicy, provs map[string]bool) error {
	if len(p.Rules) == 0 {
		return fmt.Errorf("%w: %s: a rules policy needs at least one rule; remove the policy instead", ErrForm, pat)
	}
	if strings.ContainsAny(p.GeoIPDB, "\r\n") || (p.GeoIPDB != "" && !path.IsAbs(p.GeoIPDB)) {
		return fmt.Errorf("%w: %s: geoip_db %q must be an absolute path (mount the file into the container)", ErrForm, pat, p.GeoIPDB)
	}
	names := map[string]bool{}
	keys := map[string]bool{}
	needGeo := false
	for i, r := range p.Rules {
		at := fmt.Sprintf("%s.rules[%d]", pat, i)
		if r.Name != "" {
			if strings.ContainsAny(r.Name, "\r\n") {
				return fmt.Errorf("%w: %s: name must be one line", ErrForm, at)
			}
			if names[r.Name] {
				return fmt.Errorf("%w: %s: duplicate name %s", ErrForm, at, r.Name)
			}
			names[r.Name] = true
			at = fmt.Sprintf("%s.rules[%d] (%s)", pat, i, r.Name)
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
		needGeo = needGeo || len(r.Countries) > 0
		switch r.Traffic {
		case "", "transit", "local":
		default:
			return fmt.Errorf("%w: %s: traffic %q is invalid (want transit or local)", ErrForm, at, r.Traffic)
		}
		if len(r.Prefixes) == 0 && len(r.ASNs) == 0 && len(r.Countries) == 0 && r.Traffic == "" {
			return fmt.Errorf("%w: %s: a rule needs at least one of prefixes, asns, countries, or traffic", ErrForm, at)
		}
	}
	if needGeo && p.GeoIPDB == "" {
		return fmt.Errorf("%w: %s: a rule lists countries, so geoip_db is required", ErrForm, pat)
	}
	return nil
}

func (f Form) validateVIP() error {
	if len(f.VIPs) > MaxFormSources {
		return fmt.Errorf("%w: at most %d vip sources in the form", ErrForm, MaxFormSources)
	}
	var keys, names []string
	for i, v := range f.VIPs {
		keys = append(keys, v.Key)
		names = append(names, v.Name)
		if err := validateVIPSource(fmt.Sprintf("vip[%d]", i), v); err != nil {
			return err
		}
	}
	return checkEntries("vip", "vip", keys, names)
}

func validateVIPSource(at string, v FormVIP) error {
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
	if len(f.Outages) > MaxFormSources {
		return fmt.Errorf("%w: at most %d outage sources in the form", ErrForm, MaxFormSources)
	}
	var keys, names []string
	for i, o := range f.Outages {
		keys = append(keys, o.Key)
		names = append(names, o.Name)
		if err := validateOutageSource(fmt.Sprintf("outage[%d]", i), o); err != nil {
			return err
		}
	}
	return checkEntries("outage", "outage", keys, names)
}

func validateOutageSource(at string, o FormOutage) error {
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
		keys := make([]string, len(next.Flows))
		for i, fl := range next.Flows {
			keys[i] = fl.Key
		}
		if err := replaceTyped(root, "sources", "flow", keys, func(i int, n *yaml.Node) error {
			applyFlow(n, next.Flows[i])
			return nil
		}); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(cur.VIPs, next.VIPs) {
		keys := make([]string, len(next.VIPs))
		for i, v := range next.VIPs {
			keys[i] = v.Key
		}
		if err := replaceTyped(root, "sources", "vip", keys, func(i int, n *yaml.Node) error {
			applyVIP(n, next.VIPs[i])
			return nil
		}); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(cur.Outages, next.Outages) {
		keys := make([]string, len(next.Outages))
		for i, o := range next.Outages {
			keys[i] = o.Key
		}
		if err := replaceTyped(root, "sources", "outage", keys, func(i int, n *yaml.Node) error {
			applyOutage(n, next.Outages[i])
			return nil
		}); err != nil {
			return err
		}
	}
	if err := applyProtection(root, cur, next); err != nil {
		return err
	}
	if !reflect.DeepEqual(cur.Policies, next.Policies) {
		keys := make([]string, len(next.Policies))
		for i, p := range next.Policies {
			keys[i] = p.Key
		}
		return replaceTyped(root, "policies", "rules", keys, func(i int, n *yaml.Node) error {
			return applyRules(n, next.Policies[i])
		})
	}
	return nil
}

// replaceTyped makes the entries of type typ in the sequence at seqKey
// match keys, in order. A key is an index into the entries of that type
// as the form loaded them; empty is a new entry. Kept entries are edited
// in place by fill. The new list fills the slots the old entries held, so
// entries of other types do not move; extra new entries go at the end,
// and a sequence left empty is removed.
func replaceTyped(root *yaml.Node, seqKey, typ string, keys []string, fill func(i int, n *yaml.Node) error) error {
	old := typedNodes(root, seqKey, typ)
	used := map[int]bool{}
	next := make([]*yaml.Node, len(keys))
	for i, k := range keys {
		if k == "" {
			n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			setOrDelete(n, "type", typ, "!!str")
			next[i] = n
			continue
		}
		idx, err := strconv.Atoi(k)
		if err != nil || idx < 0 || idx >= len(old) {
			return fmt.Errorf("%w: %s %s is not in the file anymore; reload the form", ErrForm, typ, k)
		}
		if used[idx] {
			return fmt.Errorf("%w: %s %s is listed twice", ErrForm, typ, k)
		}
		used[idx] = true
		next[i] = old[idx]
	}
	for i, n := range next {
		if err := fill(i, n); err != nil {
			return err
		}
	}
	seq, ok := sequenceChild(root, seqKey)
	if !ok {
		if len(next) == 0 {
			return nil
		}
		seq = ensureSequence(root, seqKey)
	}
	var out []*yaml.Node
	j := 0
	for _, item := range seq.Content {
		if item.Kind == yaml.MappingNode && scalar(item, "type") == typ {
			if j < len(next) {
				out = append(out, next[j])
				j++
			}
			continue
		}
		out = append(out, item)
	}
	seq.Content = append(out, next[j:]...)
	if len(seq.Content) == 0 {
		deleteKey(root, seqKey)
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

func applyRules(node *yaml.Node, p FormRulesPolicy) error {
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
