package configedit

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Form sections added in #130: the flow source, the rules policy, the vip
// source, and the outage source. Each section is a pointer on Form. A nil
// section in a request means "leave it alone", so an older client that
// does not know the section cannot remove it. ParseForm always fills them.
// Applying a section edits the YAML text only; Save runs the same checks
// as a start, and nothing here can turn inject on or announce.

// Section limits. A larger edit belongs in the YAML.
const (
	MaxFormRules      = 1000
	MaxFormListValues = 4096
)

// FormFlow is the first `flow` source. Enabled false removes that source
// from the file, including its problems, transit, and subranges blocks.
// Those three blocks, and aggregate_v4/aggregate_v6, are kept as they are
// while the source stays. TopN is the priority tier, MaxTargets the larger
// capped set, and TailInterval the interval for the rest.
type FormFlow struct {
	Enabled      bool     `json:"enabled"`
	Listen       []string `json:"listen"`
	Window       string   `json:"window"`
	TopN         string   `json:"top_n"`
	MaxTargets   string   `json:"max_targets"`
	TailInterval string   `json:"tail_interval"`
	MinBytes     string   `json:"min_bytes"`
	MinPct       string   `json:"min_pct"`
	Exclude      []string `json:"exclude"`
}

// FormPolicies is the first `rules` policy. An empty Rules list removes
// that policy (the loader requires at least one rule). `geoip_db` and
// every other policy in the chain stay in the YAML.
type FormPolicies struct {
	Rules []FormRule `json:"rules"`
}

// FormRule is one rule. Key is the rule's position in the file when the
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

// FormVIP is the first `vip` source. Enabled false removes it.
type FormVIP struct {
	Enabled    bool         `json:"enabled"`
	Interval   string       `json:"interval"`
	MaxTargets string       `json:"max_targets"`
	Prefixes   []FormTarget `json:"prefixes"`
	ASNs       []string     `json:"asns"`
}

// FormOutage is the first `outage` source. Enabled false removes it.
type FormOutage struct {
	Enabled     bool     `json:"enabled"`
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
	flow := FormFlow{Listen: []string{}, Exclude: []string{}}
	if src, ok := firstSource(root, "flow"); ok {
		flow.Enabled = true
		if cfg, ok := mappingChild(src, "config"); ok {
			flow.Listen = listOrScalar(cfg, "listen")
			flow.Window = scalar(cfg, "window")
			flow.TopN = scalar(cfg, "top_n")
			flow.MaxTargets = scalar(cfg, "max_targets")
			flow.TailInterval = scalar(cfg, "tail_interval")
			flow.MinBytes = scalar(cfg, "min_bytes")
			flow.MinPct = scalar(cfg, "min_pct")
			flow.Exclude = scalarList(cfg, "exclude")
		}
	}
	f.Flow = &flow

	pol := FormPolicies{Rules: []FormRule{}}
	if node, ok := rulesPolicy(root); ok {
		if cfg, ok := mappingChild(node, "config"); ok {
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
	}
	f.Policies = &pol

	vip := FormVIP{Prefixes: []FormTarget{}, ASNs: []string{}}
	if src, ok := firstSource(root, "vip"); ok {
		vip.Enabled = true
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
	}
	f.VIP = &vip

	out := FormOutage{IgnoreASNs: []string{}}
	if src, ok := firstSource(root, "outage"); ok {
		out.Enabled = true
		if cfg, ok := mappingChild(src, "config"); ok {
			out.MinPrefixes = scalar(cfg, "min_prefixes")
			out.Window = scalar(cfg, "window")
			out.LossPct = scalar(cfg, "loss_pct")
			out.RTTMs = scalar(cfg, "rtt_ms")
			out.Interval = scalar(cfg, "interval")
			out.MaxTargets = scalar(cfg, "max_targets")
			out.IgnoreASNs = scalarList(cfg, "ignore_asns")
		}
	}
	f.Outage = &out
	return readProtection(root, f)
}

// firstSource is the first source of the given type.
func firstSource(root *yaml.Node, typ string) (*yaml.Node, bool) {
	seq, ok := sequenceChild(root, "sources")
	if !ok {
		return nil, false
	}
	for _, item := range seq.Content {
		if item.Kind == yaml.MappingNode && scalar(item, "type") == typ {
			return item, true
		}
	}
	return nil, false
}

// rulesPolicy is the first policies entry of type rules.
func rulesPolicy(root *yaml.Node) (*yaml.Node, bool) {
	seq, ok := sequenceChild(root, "policies")
	if !ok {
		return nil, false
	}
	for _, item := range seq.Content {
		if item.Kind == yaml.MappingNode && scalar(item, "type") == "rules" {
			return item, true
		}
	}
	return nil, false
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
	if fl := f.Flow; fl != nil {
		fl.Listen = trimAll(fl.Listen)
		fl.Exclude = trimAll(fl.Exclude)
		for _, p := range []*string{&fl.Window, &fl.TopN, &fl.MaxTargets, &fl.TailInterval, &fl.MinBytes, &fl.MinPct} {
			*p = strings.TrimSpace(*p)
		}
	}
	if p := f.Policies; p != nil {
		if p.Rules == nil {
			p.Rules = []FormRule{}
		}
		for i := range p.Rules {
			r := &p.Rules[i]
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
	if v := f.VIP; v != nil {
		v.Interval = strings.TrimSpace(v.Interval)
		v.MaxTargets = strings.TrimSpace(v.MaxTargets)
		v.ASNs = trimAll(v.ASNs)
		if v.Prefixes == nil {
			v.Prefixes = []FormTarget{}
		}
		for i := range v.Prefixes {
			t := &v.Prefixes[i]
			t.Key = strings.TrimSpace(t.Key)
			t.Prefix = strings.TrimSpace(t.Prefix)
			t.Host = strings.TrimSpace(t.Host)
		}
	}
	if o := f.Outage; o != nil {
		for _, p := range []*string{&o.MinPrefixes, &o.Window, &o.LossPct, &o.RTTMs, &o.Interval, &o.MaxTargets} {
			*p = strings.TrimSpace(*p)
		}
		o.IgnoreASNs = trimAll(o.IgnoreASNs)
	}
}

// fillSections gives a nil section the file's current value, so a request
// that omits it changes nothing. Every list becomes non-nil.
func (f *Form) fillSections(cur Form) {
	f.fillProtection(cur)
	if f.Flow == nil {
		f.Flow = cur.Flow
	}
	if f.Policies == nil {
		f.Policies = cur.Policies
	}
	if f.VIP == nil {
		f.VIP = cur.VIP
	}
	if f.Outage == nil {
		f.Outage = cur.Outage
	}
	if f.Flow != nil {
		if f.Flow.Listen == nil {
			f.Flow.Listen = []string{}
		}
		if f.Flow.Exclude == nil {
			f.Flow.Exclude = []string{}
		}
	}
	if f.VIP != nil && f.VIP.ASNs == nil {
		f.VIP.ASNs = []string{}
	}
	if f.Outage != nil && f.Outage.IgnoreASNs == nil {
		f.Outage.IgnoreASNs = []string{}
	}
	if f.Policies != nil {
		for i := range f.Policies.Rules {
			r := &f.Policies.Rules[i]
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
	if reflect.DeepEqual(f.Flow, cur.Flow) {
		f.Flow = nil
	}
	if reflect.DeepEqual(f.Policies, cur.Policies) {
		f.Policies = nil
	}
	if reflect.DeepEqual(f.VIP, cur.VIP) {
		f.VIP = nil
	}
	if reflect.DeepEqual(f.Outage, cur.Outage) {
		f.Outage = nil
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
	return reflect.DeepEqual(f.Flow, g.Flow) && reflect.DeepEqual(f.Policies, g.Policies) &&
		reflect.DeepEqual(f.VIP, g.VIP) && reflect.DeepEqual(f.Outage, g.Outage) && protectionEqual(f, g)
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
	fl := f.Flow
	if fl == nil || !fl.Enabled {
		return nil
	}
	if len(fl.Listen) == 0 {
		return fmt.Errorf("%w: flow: at least one listen address (host:port) is required; uncheck the collector to remove the source", ErrForm)
	}
	if err := validateListLen("flow.listen", len(fl.Listen)); err != nil {
		return err
	}
	seen := map[string]bool{}
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
		if seen[key] {
			return fmt.Errorf("%w: flow.listen: duplicate %s", ErrForm, l)
		}
		seen[key] = true
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
	p := f.Policies
	if p == nil {
		return nil
	}
	if len(p.Rules) > MaxFormRules {
		return fmt.Errorf("%w: at most %d rules in the form", ErrForm, MaxFormRules)
	}
	provs := map[string]bool{}
	for _, pr := range f.Providers {
		provs[pr.Name] = true
	}
	names := map[string]bool{}
	keys := map[string]bool{}
	for i, r := range p.Rules {
		at := fmt.Sprintf("rules[%d]", i)
		if r.Name != "" {
			if strings.ContainsAny(r.Name, "\r\n") {
				return fmt.Errorf("%w: %s: name must be one line", ErrForm, at)
			}
			if names[r.Name] {
				return fmt.Errorf("%w: %s: duplicate name %s", ErrForm, at, r.Name)
			}
			names[r.Name] = true
			at = fmt.Sprintf("rules[%d] (%s)", i, r.Name)
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
	}
	return nil
}

func (f Form) validateVIP() error {
	v := f.VIP
	if v == nil || !v.Enabled {
		return nil
	}
	if v.Interval == "" {
		return fmt.Errorf("%w: vip.interval is required (for example 10s)", ErrForm)
	}
	if err := validDuration("vip.interval", v.Interval, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt("vip.max_targets", v.MaxTargets, 1, 10000); err != nil {
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
	o := f.Outage
	if o == nil || !o.Enabled {
		return nil
	}
	if err := validInt("outage.min_prefixes", o.MinPrefixes, 0, 10000); err != nil {
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
	if err := validInt("outage.max_targets", o.MaxTargets, 0, 10000); err != nil {
		return err
	}
	return validASNs("outage.ignore_asns", o.IgnoreASNs)
}

// ---- applying ----

func applySections(root *yaml.Node, cur, next Form) error {
	if !reflect.DeepEqual(cur.Flow, next.Flow) {
		applyFlow(root, next.Flow)
	}
	if !reflect.DeepEqual(cur.VIP, next.VIP) {
		applyVIP(root, next.VIP)
	}
	if !reflect.DeepEqual(cur.Outage, next.Outage) {
		applyOutage(root, next.Outage)
	}
	if err := applyProtection(root, cur, next); err != nil {
		return err
	}
	if !reflect.DeepEqual(cur.Policies, next.Policies) {
		return applyRules(root, next.Policies)
	}
	return nil
}

// sourceNode returns the first source of a type, creating it (type and an
// empty config) when enabled and absent. Disabled removes it and returns
// nil. A file with no sources key and nothing to enable is left alone.
func sourceNode(root *yaml.Node, typ string, enabled bool) *yaml.Node {
	seq, hasSeq := sequenceChild(root, "sources")
	if !enabled {
		if !hasSeq {
			return nil
		}
		for i, item := range seq.Content {
			if item.Kind == yaml.MappingNode && scalar(item, "type") == typ {
				seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
				break
			}
		}
		if len(seq.Content) == 0 {
			deleteKey(root, "sources")
		}
		return nil
	}
	if src, ok := firstSource(root, typ); ok {
		return src
	}
	seq = ensureSequence(root, "sources")
	src := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	setOrDelete(src, "type", typ, "!!str")
	seq.Content = append(seq.Content, src)
	return src
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

func applyFlow(root *yaml.Node, fl *FormFlow) {
	if fl == nil {
		return
	}
	src := sourceNode(root, "flow", fl.Enabled)
	if src == nil {
		return
	}
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
	setStringList(cfg, "exclude", fl.Exclude, "!!str")
}

func applyVIP(root *yaml.Node, v *FormVIP) {
	if v == nil {
		return
	}
	src := sourceNode(root, "vip", v.Enabled)
	if src == nil {
		return
	}
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

func applyOutage(root *yaml.Node, o *FormOutage) {
	if o == nil {
		return
	}
	src := sourceNode(root, "outage", o.Enabled)
	if src == nil {
		return
	}
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

func applyRules(root *yaml.Node, p *FormPolicies) error {
	if p == nil {
		return nil
	}
	node, exists := rulesPolicy(root)
	if len(p.Rules) == 0 {
		if !exists {
			return nil
		}
		seq, _ := sequenceChild(root, "policies")
		for i, item := range seq.Content {
			if item == node {
				seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
				break
			}
		}
		if len(seq.Content) == 0 {
			deleteKey(root, "policies")
		}
		return nil
	}
	if !exists {
		seq := ensureSequence(root, "policies")
		node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setOrDelete(node, "type", "rules", "!!str")
		seq.Content = append(seq.Content, node)
	}
	cfg := ensureMapping(node, "config")
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
