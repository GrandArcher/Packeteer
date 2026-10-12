package configedit

import (
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Form sections added in #131: the inbound block and the anomaly rules.
// They follow the #130 sections: a nil section in a request leaves that
// part of the file alone, ParseForm always fills them, and applying
// edits the YAML text only. Save runs the same checks as a start, and
// the editor asks for confirm_inject when a block turns inject on.
// Nothing here announces. The inbound announcer, the anomaly detector,
// and every key the sections do not show stay in the YAML.

// MaxFormAnomalyRules bounds the rows of the anomaly rules section.
const MaxFormAnomalyRules = config.MaxAnomalyRules

// FormInbound is the `inbound` block. Enabled false removes the block,
// announcer included. Mode may be observe or suggest. A block that is
// already inject keeps inject until the operator changes it; the form
// never turns inject on, because that is a YAML edit with confirm_inject.
// HasAnnouncer is display only.
type FormInbound struct {
	Enabled         bool     `json:"enabled"`
	Mode            string   `json:"mode"`
	Prefixes        []string `json:"prefixes"`
	LocalPref       string   `json:"local_pref"`
	ReleasePct      string   `json:"release_pct"`
	MaxImprovements string   `json:"max_improvements"`
	Moderated       []string `json:"moderated"`
	HasAnnouncer    bool     `json:"has_announcer"`

	Performance FormInboundPerformance `json:"performance"`
	Damping     FormInboundDamping     `json:"damping"`
}

// FormInboundPerformance is `inbound.performance`. Enabled false removes
// it. A negative loss_pct or latency_ms disables that check.
type FormInboundPerformance struct {
	Enabled     bool   `json:"enabled"`
	LossPct     string `json:"loss_pct"`
	LatencyMs   string `json:"latency_ms"`
	MinPrefixes string `json:"min_prefixes"`
	ReleasePct  string `json:"release_pct"`
}

// FormInboundDamping is `inbound.damping`. Empty fields use the defaults.
type FormInboundDamping struct {
	Disabled bool   `json:"disabled"`
	Confirm  string `json:"confirm"`
	Backoff  string `json:"backoff"`
	MaxHold  string `json:"max_hold"`
}

// FormAnomaly is `anomaly.rules`. Enabled (the anomaly block exists, so a
// detector is configured), MitigationMode, and MitigationAllowlist are
// display only and are always re-read from the file. Rules need that
// block: the form never creates a detector.
type FormAnomaly struct {
	Enabled             bool              `json:"enabled"`
	MitigationMode      string            `json:"mitigation_mode"`
	MitigationAllowlist []string          `json:"mitigation_allowlist"`
	Rules               []FormAnomalyRule `json:"rules"`
}

// FormAnomalyRule is one rule. Key is the rule's position in the file when
// the form was loaded; empty means a new rule. Rule order is the file
// order, and the first matching rule wins.
type FormAnomalyRule struct {
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	Prefixes  []string `json:"prefixes"`
	Protocols []string `json:"protocols"`
	MinMbps   string   `json:"min_mbps"`
	Action    string   `json:"action"`
	Target    string   `json:"target"`
	RateMbps  string   `json:"rate_mbps"`
	TTL       string   `json:"ttl"`
}

// ---- reading ----

func readProtection(root *yaml.Node, f *Form) error {
	in := FormInbound{Prefixes: []string{}, Moderated: []string{}, Mode: config.ModeObserve}
	if n, ok := mappingChild(root, "inbound"); ok {
		in.Enabled = true
		if m := scalar(n, "mode"); m != "" {
			in.Mode = m
		}
		in.Prefixes = scalarList(n, "prefixes")
		in.LocalPref = scalar(n, "local_pref")
		in.ReleasePct = scalar(n, "release_pct")
		in.MaxImprovements = scalar(n, "max_improvements")
		in.Moderated = scalarList(n, "moderated")
		if a, ok := mappingChild(n, "announcer"); ok && scalar(a, "type") != "" {
			in.HasAnnouncer = true
		}
		if pf, ok := mappingChild(n, "performance"); ok {
			in.Performance = FormInboundPerformance{Enabled: true, LossPct: scalar(pf, "loss_pct"),
				LatencyMs: scalar(pf, "latency_ms"), MinPrefixes: scalar(pf, "min_prefixes"), ReleasePct: scalar(pf, "release_pct")}
		}
		if d, ok := mappingChild(n, "damping"); ok {
			in.Damping = FormInboundDamping{Disabled: scalar(d, "disabled") == "true", Confirm: scalar(d, "confirm"),
				Backoff: scalar(d, "backoff"), MaxHold: scalar(d, "max_hold")}
		}
	}
	f.Inbound = &in

	an := FormAnomaly{MitigationAllowlist: []string{}, Rules: []FormAnomalyRule{}}
	if m, ok := mappingChild(root, "mitigation"); ok {
		an.MitigationMode = scalar(m, "mode")
		if an.MitigationMode == "" {
			an.MitigationMode = config.ModeObserve
		}
		an.MitigationAllowlist = scalarList(m, "allowlist")
	}
	if n, ok := mappingChild(root, "anomaly"); ok {
		an.Enabled = true
		if seq, ok := sequenceChild(n, "rules"); ok {
			for i, item := range seq.Content {
				if item.Kind != yaml.MappingNode {
					return fmt.Errorf("%w: anomaly rules must be a list of mappings", ErrForm)
				}
				an.Rules = append(an.Rules, FormAnomalyRule{
					Key: strconv.Itoa(i), Name: scalar(item, "name"), Prefixes: scalarList(item, "prefixes"),
					Protocols: scalarList(item, "protocols"), MinMbps: scalar(item, "min_mbps"), Action: scalar(item, "action"),
					Target: scalar(item, "target"), RateMbps: scalar(item, "rate_mbps"), TTL: scalar(item, "ttl"),
				})
			}
		}
	}
	f.Anomaly = &an
	return nil
}

// ---- normalize, fill, validate ----

func (f *Form) normalizeProtection() {
	if in := f.Inbound; in != nil {
		in.Mode = strings.TrimSpace(in.Mode)
		in.Prefixes = trimAll(in.Prefixes)
		in.Moderated = trimAll(in.Moderated)
		for _, p := range []*string{&in.LocalPref, &in.ReleasePct, &in.MaxImprovements,
			&in.Performance.LossPct, &in.Performance.LatencyMs, &in.Performance.MinPrefixes, &in.Performance.ReleasePct,
			&in.Damping.Confirm, &in.Damping.Backoff, &in.Damping.MaxHold} {
			*p = strings.TrimSpace(*p)
		}
	}
	if an := f.Anomaly; an != nil {
		if an.Rules == nil {
			an.Rules = []FormAnomalyRule{}
		}
		for i := range an.Rules {
			r := &an.Rules[i]
			for _, p := range []*string{&r.Key, &r.Name, &r.MinMbps, &r.Target, &r.RateMbps, &r.TTL} {
				*p = strings.TrimSpace(*p)
			}
			r.Action = strings.ToLower(strings.TrimSpace(r.Action))
			r.Prefixes = trimAll(r.Prefixes)
			r.Protocols = trimAll(r.Protocols)
		}
	}
}

// fillProtection gives a nil section the file's current value, restores
// the display-only fields from the file, and makes every list non-nil.
func (f *Form) fillProtection(cur Form) {
	if f.Inbound == nil {
		f.Inbound = cur.Inbound
	}
	if f.Anomaly == nil {
		f.Anomaly = cur.Anomaly
	}
	if f.Inbound != nil {
		if f.Inbound.Prefixes == nil {
			f.Inbound.Prefixes = []string{}
		}
		if f.Inbound.Moderated == nil {
			f.Inbound.Moderated = []string{}
		}
		if cur.Inbound != nil {
			f.Inbound.HasAnnouncer = cur.Inbound.HasAnnouncer
		}
	}
	if f.Anomaly != nil {
		if f.Anomaly.Rules == nil {
			f.Anomaly.Rules = []FormAnomalyRule{}
		}
		if cur.Anomaly != nil {
			f.Anomaly.Enabled = cur.Anomaly.Enabled
			f.Anomaly.MitigationMode = cur.Anomaly.MitigationMode
			f.Anomaly.MitigationAllowlist = cur.Anomaly.MitigationAllowlist
		}
		for i := range f.Anomaly.Rules {
			r := &f.Anomaly.Rules[i]
			if r.Prefixes == nil {
				r.Prefixes = []string{}
			}
			if r.Protocols == nil {
				r.Protocols = []string{}
			}
		}
	}
}

func (f Form) validateProtection() error {
	if err := f.validateInbound(); err != nil {
		return err
	}
	return f.validateAnomaly()
}

func (f Form) validateInbound() error {
	in := f.Inbound
	if in == nil || !in.Enabled {
		return nil
	}
	switch in.Mode {
	case config.ModeObserve, config.ModeSuggest, config.ModeInject:
	default:
		return fmt.Errorf("%w: inbound.mode %q is invalid (want observe or suggest)", ErrForm, in.Mode)
	}
	if len(in.Prefixes) == 0 {
		return fmt.Errorf("%w: inbound: at least one prefix is required; uncheck inbound to remove the block", ErrForm)
	}
	if err := validPrefixList("inbound.prefixes", in.Prefixes); err != nil {
		return err
	}
	if in.LocalPref != "" {
		if n, err := strconv.ParseUint(in.LocalPref, 10, 32); err != nil || n == 0 {
			return fmt.Errorf("%w: inbound.local_pref %q must be a whole number from 1 to 4294967295", ErrForm, in.LocalPref)
		}
	}
	if err := pctField("inbound.release_pct", in.ReleasePct); err != nil {
		return err
	}
	if err := validInt("inbound.max_improvements", in.MaxImprovements, 1, config.MaxImprovementsLimit); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, t := range in.Moderated {
		if t != config.InboundTriggerCommit && t != config.InboundTriggerPerformance {
			return fmt.Errorf("%w: inbound.moderated %q is invalid (want commit or performance)", ErrForm, t)
		}
		if seen[t] {
			return fmt.Errorf("%w: inbound.moderated: duplicate trigger %s", ErrForm, t)
		}
		seen[t] = true
	}
	if pf := in.Performance; pf.Enabled {
		for _, c := range []struct{ name, v string }{{"inbound.performance.loss_pct", pf.LossPct}, {"inbound.performance.latency_ms", pf.LatencyMs}} {
			if c.v == "" {
				continue
			}
			v, err := strconv.ParseFloat(c.v, 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v > 1e9 || (c.name == "inbound.performance.loss_pct" && v > 100) {
				return fmt.Errorf("%w: %s %q must be a number (negative turns the check off, loss at most 100)", ErrForm, c.name, c.v)
			}
		}
		if pf.LossPct != "" && pf.LatencyMs != "" {
			l, _ := strconv.ParseFloat(pf.LossPct, 64)
			m, _ := strconv.ParseFloat(pf.LatencyMs, 64)
			if l < 0 && m < 0 {
				return fmt.Errorf("%w: inbound.performance: loss_pct and latency_ms cannot both be off", ErrForm)
			}
		}
		if err := validInt("inbound.performance.min_prefixes", pf.MinPrefixes, 1, 10000); err != nil {
			return err
		}
		if err := pctField("inbound.performance.release_pct", pf.ReleasePct); err != nil {
			return err
		}
	}
	if err := validDuration("inbound.damping.confirm", in.Damping.Confirm, 0, 24*time.Hour); err != nil {
		return err
	}
	if err := numberField("inbound.damping.backoff", in.Damping.Backoff, 1, 16); err != nil {
		return err
	}
	return validDuration("inbound.damping.max_hold", in.Damping.MaxHold, 0, 30*24*time.Hour)
}

// pctField is a percent above 0 and at most 100.
func pctField(name, v string) error {
	if v == "" {
		return nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(n) || n <= 0 || n > 100 {
		return fmt.Errorf("%w: %s %q must be greater than 0 and at most 100", ErrForm, name, v)
	}
	return nil
}

func (f Form) validateAnomaly() error {
	an := f.Anomaly
	if an == nil {
		return nil
	}
	if len(an.Rules) > 0 && !an.Enabled {
		return fmt.Errorf("%w: anomaly rules need an anomaly block with a detector in the file; add it in the YAML first", ErrForm)
	}
	if len(an.Rules) > MaxFormAnomalyRules {
		return fmt.Errorf("%w: at most %d anomaly rules in the form", ErrForm, MaxFormAnomalyRules)
	}
	var allow []netip.Prefix
	for _, s := range an.MitigationAllowlist {
		if p, err := netip.ParsePrefix(s); err == nil {
			allow = append(allow, p.Masked())
		}
	}
	names, keys := map[string]bool{}, map[string]bool{}
	for i, r := range an.Rules {
		at := fmt.Sprintf("anomaly rules[%d]", i)
		if r.Name == "" {
			return fmt.Errorf("%w: %s: name is required", ErrForm, at)
		}
		if len(r.Name) > 64 || strings.ContainsAny(r.Name, "\r\n") {
			return fmt.Errorf("%w: %s: name must be one line of at most 64 characters", ErrForm, at)
		}
		if names[r.Name] {
			return fmt.Errorf("%w: %s: duplicate name %s", ErrForm, at, r.Name)
		}
		names[r.Name] = true
		at = fmt.Sprintf("anomaly rules[%d] (%s)", i, r.Name)
		if r.Key != "" {
			if keys[r.Key] {
				return fmt.Errorf("%w: %s: row listed twice", ErrForm, at)
			}
			keys[r.Key] = true
		}
		if len(r.Prefixes) == 0 {
			return fmt.Errorf("%w: %s: at least one prefix is required", ErrForm, at)
		}
		if err := validPrefixList(at+" prefixes", r.Prefixes); err != nil {
			return err
		}
		for _, s := range r.Prefixes {
			p := netip.MustParsePrefix(s)
			if p.Bits() == 0 {
				return fmt.Errorf("%w: %s: %s would match every prefix", ErrForm, at, p)
			}
			if len(allow) > 0 && !prefixCovered(allow, p) {
				return fmt.Errorf("%w: %s: %s is not inside mitigation.allowlist", ErrForm, at, p)
			}
		}
		if len(r.Protocols) > plugin.MaxFlowSpecProtocols {
			return fmt.Errorf("%w: %s: at most %d protocols", ErrForm, at, plugin.MaxFlowSpecProtocols)
		}
		for _, s := range r.Protocols {
			var p plugin.IPProtocol
			if err := p.UnmarshalText([]byte(s)); err != nil {
				return fmt.Errorf("%w: %s: protocol %q is invalid (a name such as tcp or udp, or a number)", ErrForm, at, s)
			}
		}
		if r.MinMbps != "" {
			v, err := strconv.ParseFloat(r.MinMbps, 64)
			if err != nil || !(v >= 0 && v <= 1e8) {
				return fmt.Errorf("%w: %s: min_mbps %q must be between 0 and 100000000", ErrForm, at, r.MinMbps)
			}
		}
		if err := validDuration(at+" ttl", r.TTL, config.MinMitigationTTL, config.MaxMitigationMaxTTL); err != nil {
			return err
		}
		var rate float64
		if r.RateMbps != "" {
			v, err := strconv.ParseFloat(r.RateMbps, 64)
			if err != nil || math.IsNaN(v) || v < 0 {
				return fmt.Errorf("%w: %s: rate_mbps %q must be a positive number", ErrForm, at, r.RateMbps)
			}
			rate = v
		}
		switch r.Action {
		case plugin.MitigationBlackhole, plugin.MitigationFlowSpecDrop:
			if r.Target != "" || r.RateMbps != "" {
				return fmt.Errorf("%w: %s: %s takes no target or rate_mbps", ErrForm, at, r.Action)
			}
		case plugin.MitigationRedirect, plugin.MitigationFlowSpecRedirect:
			if r.Target == "" {
				return fmt.Errorf("%w: %s: %s needs a target", ErrForm, at, r.Action)
			}
			if r.RateMbps != "" {
				return fmt.Errorf("%w: %s: %s takes no rate_mbps", ErrForm, at, r.Action)
			}
		case plugin.MitigationFlowSpecRateLimit:
			if r.Target != "" {
				return fmt.Errorf("%w: %s: %s takes no target", ErrForm, at, r.Action)
			}
			if !(rate > 0 && rate <= plugin.MaxFlowSpecRateMbps) {
				return fmt.Errorf("%w: %s: rate_mbps must be above 0 and at most %d", ErrForm, at, plugin.MaxFlowSpecRateMbps)
			}
		default:
			return fmt.Errorf("%w: %s: action %q is invalid (want %s, %s, %s, %s, or %s)", ErrForm, at, r.Action,
				plugin.MitigationBlackhole, plugin.MitigationRedirect, plugin.MitigationFlowSpecDrop,
				plugin.MitigationFlowSpecRateLimit, plugin.MitigationFlowSpecRedirect)
		}
	}
	return nil
}

func prefixCovered(list []netip.Prefix, p netip.Prefix) bool {
	return slices.ContainsFunc(list, func(a netip.Prefix) bool { return a.Bits() <= p.Bits() && a.Contains(p.Addr()) })
}

// checkProtectionChange refuses the one thing the sections may not do:
// turn inbound inject on. That is a YAML edit the editor confirms with
// confirm_inject.
func (f Form) checkProtectionChange(cur Form) error {
	in := f.Inbound
	if in == nil || !in.Enabled || in.Mode != config.ModeInject {
		return nil
	}
	if cur.Inbound != nil && cur.Inbound.Enabled && cur.Inbound.Mode == config.ModeInject {
		return nil
	}
	return fmt.Errorf("%w: inbound.mode inject is not a form choice: edit the YAML (and confirm_inject on save) after the inject checklist in docs/CONFIG.md", ErrForm)
}

// protectionUnchanged reports whether the #131 sections match.
func protectionEqual(f, g Form) bool {
	return reflect.DeepEqual(f.Inbound, g.Inbound) && reflect.DeepEqual(f.Anomaly, g.Anomaly)
}

// ---- applying ----

func applyProtection(root *yaml.Node, cur, next Form) error {
	if !reflect.DeepEqual(cur.Inbound, next.Inbound) {
		applyInbound(root, next.Inbound)
	}
	if !reflect.DeepEqual(cur.Anomaly, next.Anomaly) {
		return applyAnomalyRules(root, next.Anomaly)
	}
	return nil
}

func applyInbound(root *yaml.Node, in *FormInbound) {
	if in == nil {
		return
	}
	if !in.Enabled {
		deleteKey(root, "inbound")
		return
	}
	n := ensureMapping(root, "inbound")
	setOrDelete(n, "mode", in.Mode, "!!str")
	setStringList(n, "prefixes", in.Prefixes, "!!str")
	setOrDelete(n, "local_pref", in.LocalPref, "!!int")
	setOrDelete(n, "release_pct", in.ReleasePct, "!!float")
	setOrDelete(n, "max_improvements", in.MaxImprovements, "!!int")
	setStringList(n, "moderated", in.Moderated, "!!str")
	if pf := in.Performance; pf.Enabled {
		m := ensureMapping(n, "performance")
		setOrDelete(m, "loss_pct", pf.LossPct, "!!float")
		setOrDelete(m, "latency_ms", pf.LatencyMs, "!!float")
		setOrDelete(m, "min_prefixes", pf.MinPrefixes, "!!int")
		setOrDelete(m, "release_pct", pf.ReleasePct, "!!float")
		if len(m.Content) == 0 {
			// An empty mapping is still "performance on, defaults".
			m.Style = yaml.FlowStyle
		}
	} else {
		deleteKey(n, "performance")
	}
	d := in.Damping
	if !d.Disabled && d.Confirm == "" && d.Backoff == "" && d.MaxHold == "" {
		deleteKey(n, "damping")
		return
	}
	m := ensureMapping(n, "damping")
	if d.Disabled {
		setOrDelete(m, "disabled", "true", "!!bool")
	} else {
		deleteKey(m, "disabled")
	}
	setOrDelete(m, "confirm", d.Confirm, "!!str")
	setOrDelete(m, "backoff", d.Backoff, "!!float")
	setOrDelete(m, "max_hold", d.MaxHold, "!!str")
}

func applyAnomalyRules(root *yaml.Node, an *FormAnomaly) error {
	if an == nil {
		return nil
	}
	node, ok := mappingChild(root, "anomaly")
	if !ok {
		if len(an.Rules) > 0 {
			return fmt.Errorf("%w: anomaly rules need an anomaly block with a detector in the file", ErrForm)
		}
		return nil
	}
	if len(an.Rules) == 0 {
		deleteKey(node, "rules")
		return nil
	}
	rules := ensureSequence(node, "rules")
	old := map[string]*yaml.Node{}
	for i, item := range rules.Content {
		if item.Kind == yaml.MappingNode {
			old[strconv.Itoa(i)] = item
		}
	}
	var next []*yaml.Node
	used := map[*yaml.Node]bool{}
	for _, r := range an.Rules {
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
		setStringList(n, "prefixes", r.Prefixes, "!!str")
		setStringList(n, "protocols", r.Protocols, "!!str")
		setOrDelete(n, "min_mbps", r.MinMbps, "!!float")
		setOrDelete(n, "action", r.Action, "!!str")
		setOrDelete(n, "target", r.Target, "!!str")
		setOrDelete(n, "rate_mbps", r.RateMbps, "!!float")
		setOrDelete(n, "ttl", r.TTL, "!!str")
		next = append(next, n)
	}
	rules.Content = next
	return nil
}
