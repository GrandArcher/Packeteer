package configedit

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// The settings form (#102) edits the common decision fields as rows and
// knobs. Apply merges those fields into the YAML the operator already
// has; it does not write the file, start a probe, or announce. Save is
// still the editor's Save, with the same checks as a start. Secrets are
// not fields here: plugins keep them in environment variables.

// Form limits. A larger edit belongs in the YAML.
const (
	MaxFormProviders = 64
	MaxFormTargets   = 4096
	MaxFormAllowlist = 4096
)

// ErrForm is a form that cannot be read or applied. The file is not
// touched; Apply does not write it anyway.
var ErrForm = errors.New("settings form")

// Form is the operator-facing slice of a config file.
type Form struct {
	Mode            string `json:"mode"`
	HoldTime        string `json:"hold_time"`
	MaxImprovements string `json:"max_improvements"`
	MinLossDeltaPct string `json:"min_loss_delta_pct"`
	MinRTTDeltaMs   string `json:"min_rtt_delta_ms"`
	// MinRTTDeltaPct is thresholds.min_rtt_delta_pct. Empty omits the key
	// (0, off). ConfirmRounds is thresholds.confirm_rounds. Empty omits
	// the key (the default, 1).
	MinRTTDeltaPct string `json:"min_rtt_delta_pct"`
	ConfirmRounds  string `json:"confirm_rounds"`
	// Precedence is performance or cost when the scorer is cost (omitted
	// on a cost scorer means performance). Empty means the file's scorer
	// is not cost and the knob is unused.
	Precedence   string         `json:"precedence"`
	ScorerType   string         `json:"scorer_type"`
	FloorLossPct string         `json:"floor_max_loss_pct"`
	FloorRTT     string         `json:"floor_max_rtt"`
	Providers    []FormProvider `json:"providers"`
	Targets      []FormTarget   `json:"targets"`
	Allowlist    []string       `json:"allowlist"`
	// Sections (#130). A nil section in a request leaves that part of the
	// file alone; ParseForm always fills them.
	Flow     *FormFlow     `json:"flow"`
	Policies *FormPolicies `json:"policies"`
	VIP      *FormVIP      `json:"vip"`
	Outage   *FormOutage   `json:"outage"`
	// #131: the inbound block and anomaly.rules, same rules.
	Inbound *FormInbound `json:"inbound"`
	Anomaly *FormAnomaly `json:"anomaly"`
}

// FormProvider is one provider row. Key is the name in the file when the
// row was loaded; empty means a new row. ASN and Draft are display only:
// accepting a BGP suggestion fills them in the browser and Apply never
// writes them. CommitMbps is the telemetry binding's commit, not a
// provider field. CommitBound reports that a binding exists.
type FormProvider struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	SourceIP    string `json:"source_ip"`
	NextHop     string `json:"next_hop"`
	Cost        string `json:"cost"`
	CommitMbps  string `json:"commit_mbps"`
	CommitBound bool   `json:"commit_bound"`
	ASN         string `json:"asn,omitempty"`
	Draft       bool   `json:"draft,omitempty"`
}

// FormTarget is one static probe target. Key is the prefix in the file
// when the row was loaded.
type FormTarget struct {
	Key    string `json:"key"`
	Prefix string `json:"prefix"`
	Host   string `json:"host"`
}

// ParseForm reads the form fields from a config document. It does not
// validate the file the way a start does; Save does that.
func ParseForm(data []byte) (Form, error) {
	root, err := mappingRoot(data)
	if err != nil {
		return Form{}, err
	}
	f := Form{
		Mode:            scalar(root, "mode"),
		HoldTime:        scalar(root, "hold_time"),
		MaxImprovements: scalar(root, "max_improvements"),
		Providers:       []FormProvider{},
		Targets:         []FormTarget{},
		Allowlist:       []string{},
	}
	if th, ok := mappingChild(root, "thresholds"); ok {
		f.MinLossDeltaPct = scalar(th, "min_loss_delta_pct")
		f.MinRTTDeltaMs = scalar(th, "min_rtt_delta_ms")
		f.MinRTTDeltaPct = scalar(th, "min_rtt_delta_pct")
		f.ConfirmRounds = scalar(th, "confirm_rounds")
	}
	f.ScorerType = scorerType(root)
	if f.ScorerType == "cost" {
		if cfg, ok := scorerConfig(root); ok {
			f.Precedence = scalar(cfg, "precedence")
			if f.Precedence == "" {
				f.Precedence = "performance"
			}
			if floor, ok := mappingChild(cfg, "floor"); ok {
				f.FloorLossPct = scalar(floor, "max_loss_pct")
				f.FloorRTT = scalar(floor, "max_rtt")
			}
		} else {
			f.Precedence = "performance"
		}
	}
	if err := readProviders(root, &f); err != nil {
		return Form{}, err
	}
	if err := readTargets(root, &f); err != nil {
		return Form{}, err
	}
	if al, ok := mappingChild(root, "allowlist"); ok {
		f.Allowlist = scalarList(al, "prefixes")
	}
	if err := readSections(root, &f); err != nil {
		return Form{}, err
	}
	f.normalize()
	return f, nil
}

// ApplyForm merges form into the YAML document and returns the new text.
// Identical fields return the original bytes, so an untouched form does
// not reformat the file. It does not write the file.
func ApplyForm(data []byte, form Form) ([]byte, error) {
	cur, err := ParseForm(data)
	if err != nil {
		return nil, err
	}
	form.normalize()
	form.fillSections(cur)
	if err := form.checkProtectionChange(cur); err != nil {
		return nil, err
	}
	if err := form.withoutUnchangedSections(cur).validate(); err != nil {
		return nil, err
	}
	if form.editable().equal(cur.editable()) {
		return append([]byte(nil), data...), nil
	}
	root, err := mappingRoot(data)
	if err != nil {
		return nil, err
	}
	if err := applyScalars(root, form); err != nil {
		return nil, err
	}
	if err := applyScorer(root, cur, form); err != nil {
		return nil, err
	}
	if err := applyProviders(root, form); err != nil {
		return nil, err
	}
	if err := applyCommits(root, cur, form); err != nil {
		return nil, err
	}
	if err := applyTargets(root, form); err != nil {
		return nil, err
	}
	if err := applyAllowlist(root, form); err != nil {
		return nil, err
	}
	if err := applySections(root, cur, form); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	return buf.Bytes(), nil
}

func (f *Form) normalize() {
	f.Mode = strings.TrimSpace(f.Mode)
	f.HoldTime = strings.TrimSpace(f.HoldTime)
	f.MaxImprovements = strings.TrimSpace(f.MaxImprovements)
	f.MinLossDeltaPct = strings.TrimSpace(f.MinLossDeltaPct)
	f.MinRTTDeltaMs = strings.TrimSpace(f.MinRTTDeltaMs)
	f.MinRTTDeltaPct = strings.TrimSpace(f.MinRTTDeltaPct)
	f.ConfirmRounds = strings.TrimSpace(f.ConfirmRounds)
	f.Precedence = strings.TrimSpace(f.Precedence)
	f.FloorLossPct = strings.TrimSpace(f.FloorLossPct)
	f.FloorRTT = strings.TrimSpace(f.FloorRTT)
	if f.Providers == nil {
		f.Providers = []FormProvider{}
	}
	if f.Targets == nil {
		f.Targets = []FormTarget{}
	}
	if f.Allowlist == nil {
		f.Allowlist = []string{}
	}
	f.normalizeSections()
	for i := range f.Providers {
		p := &f.Providers[i]
		p.Key = strings.TrimSpace(p.Key)
		p.Name = strings.TrimSpace(p.Name)
		p.SourceIP = strings.TrimSpace(p.SourceIP)
		p.NextHop = strings.TrimSpace(p.NextHop)
		p.Cost = strings.TrimSpace(p.Cost)
		p.CommitMbps = strings.TrimSpace(p.CommitMbps)
		p.ASN = strings.TrimSpace(p.ASN)
	}
	for i := range f.Targets {
		t := &f.Targets[i]
		t.Key = strings.TrimSpace(t.Key)
		t.Prefix = strings.TrimSpace(t.Prefix)
		t.Host = strings.TrimSpace(t.Host)
	}
	for i := range f.Allowlist {
		f.Allowlist[i] = strings.TrimSpace(f.Allowlist[i])
	}
}

// editable drops display-only fields so a suggestion's AS does not count
// as a config change.
func (f Form) editable() Form {
	g := f
	g.ScorerType = ""
	g.Providers = append([]FormProvider(nil), f.Providers...)
	for i := range g.Providers {
		g.Providers[i].ASN = ""
		g.Providers[i].Draft = false
		g.Providers[i].CommitBound = false
	}
	return g
}

func (f Form) equal(g Form) bool {
	if f.Mode != g.Mode || f.HoldTime != g.HoldTime || f.MaxImprovements != g.MaxImprovements ||
		f.MinLossDeltaPct != g.MinLossDeltaPct || f.MinRTTDeltaMs != g.MinRTTDeltaMs ||
		f.MinRTTDeltaPct != g.MinRTTDeltaPct || f.ConfirmRounds != g.ConfirmRounds ||
		f.Precedence != g.Precedence || f.FloorLossPct != g.FloorLossPct || f.FloorRTT != g.FloorRTT {
		return false
	}
	if !sectionsEqual(f, g) {
		return false
	}
	if len(f.Providers) != len(g.Providers) || len(f.Targets) != len(g.Targets) || len(f.Allowlist) != len(g.Allowlist) {
		return false
	}
	for i := range f.Providers {
		a, b := f.Providers[i], g.Providers[i]
		if a.Key != b.Key || a.Name != b.Name || a.SourceIP != b.SourceIP || a.NextHop != b.NextHop ||
			a.Cost != b.Cost || a.CommitMbps != b.CommitMbps {
			return false
		}
	}
	for i := range f.Targets {
		if f.Targets[i] != g.Targets[i] {
			return false
		}
	}
	for i := range f.Allowlist {
		if f.Allowlist[i] != g.Allowlist[i] {
			return false
		}
	}
	return true
}

func (f Form) validate() error {
	switch f.Mode {
	case "", "observe", "suggest", "inject":
	default:
		return fmt.Errorf("%w: mode %q is invalid (want observe, suggest, or inject)", ErrForm, f.Mode)
	}
	if f.HoldTime != "" {
		if _, err := time.ParseDuration(f.HoldTime); err != nil {
			return fmt.Errorf("%w: hold_time %q is not a duration (for example 15m)", ErrForm, f.HoldTime)
		}
	}
	if f.MaxImprovements != "" {
		n, err := strconv.Atoi(f.MaxImprovements)
		if err != nil || n < 0 || n > config.MaxImprovementsLimit {
			return fmt.Errorf("%w: max_improvements %q must be a whole number from 0 to %d (0 retires every improvement)", ErrForm, f.MaxImprovements, config.MaxImprovementsLimit)
		}
	}
	if err := numberField("thresholds.min_loss_delta_pct", f.MinLossDeltaPct, 0, 100); err != nil {
		return err
	}
	if f.MinRTTDeltaMs != "" {
		v, err := strconv.ParseFloat(f.MinRTTDeltaMs, 64)
		if err != nil || v < 0 {
			return fmt.Errorf("%w: thresholds.min_rtt_delta_ms %q must be zero or positive", ErrForm, f.MinRTTDeltaMs)
		}
	}
	if err := numberField("thresholds.min_rtt_delta_pct", f.MinRTTDeltaPct, 0, 100); err != nil {
		return err
	}
	if f.ConfirmRounds != "" {
		n, err := strconv.Atoi(f.ConfirmRounds)
		if err != nil || n < 1 || n > config.MaxConfirmRounds {
			return fmt.Errorf("%w: thresholds.confirm_rounds %q must be a whole number between 1 and %d", ErrForm, f.ConfirmRounds, config.MaxConfirmRounds)
		}
	}
	switch f.Precedence {
	case "", "performance", "cost":
	default:
		return fmt.Errorf("%w: precedence %q is invalid (want performance or cost)", ErrForm, f.Precedence)
	}
	if err := numberField("floor.max_loss_pct", f.FloorLossPct, 0, 100); err != nil {
		return err
	}
	if f.FloorRTT != "" {
		d, err := time.ParseDuration(f.FloorRTT)
		if err != nil || d < 0 {
			return fmt.Errorf("%w: floor.max_rtt %q is not a duration (for example 10ms)", ErrForm, f.FloorRTT)
		}
	}
	if len(f.Providers) == 0 {
		return fmt.Errorf("%w: at least one provider is required", ErrForm)
	}
	if len(f.Providers) > MaxFormProviders {
		return fmt.Errorf("%w: at most %d providers in the form", ErrForm, MaxFormProviders)
	}
	names := map[string]bool{}
	keys := map[string]bool{}
	for i, p := range f.Providers {
		if p.Name == "" || strings.ContainsAny(p.Name, "\n\r") {
			return fmt.Errorf("%w: providers[%d]: name is required", ErrForm, i)
		}
		if names[p.Name] {
			return fmt.Errorf("%w: providers[%d]: duplicate name %s", ErrForm, i, p.Name)
		}
		names[p.Name] = true
		if p.Key != "" {
			if keys[p.Key] {
				return fmt.Errorf("%w: providers[%d]: duplicate row %s", ErrForm, i, p.Key)
			}
			keys[p.Key] = true
		}
		if p.SourceIP != "" {
			if _, err := netip.ParseAddr(p.SourceIP); err != nil {
				return fmt.Errorf("%w: providers[%d] (%s): source_ip %q is not an IP address", ErrForm, i, p.Name, p.SourceIP)
			}
		}
		if _, err := netip.ParseAddr(p.NextHop); err != nil {
			return fmt.Errorf("%w: providers[%d] (%s): next_hop %q is not an IP address", ErrForm, i, p.Name, p.NextHop)
		}
		if p.Cost != "" {
			v, err := strconv.ParseFloat(p.Cost, 64)
			if err != nil || v < 0 {
				return fmt.Errorf("%w: providers[%d] (%s): cost %q must be zero or positive", ErrForm, i, p.Name, p.Cost)
			}
		}
		if p.CommitMbps != "" {
			v, err := strconv.ParseFloat(p.CommitMbps, 64)
			if err != nil || v <= 0 {
				return fmt.Errorf("%w: providers[%d] (%s): commit %q must be greater than zero", ErrForm, i, p.Name, p.CommitMbps)
			}
		}
	}
	if len(f.Targets) > MaxFormTargets {
		return fmt.Errorf("%w: at most %d probe prefixes in the form", ErrForm, MaxFormTargets)
	}
	seenPrefix := map[string]bool{}
	for i, t := range f.Targets {
		p, err := netip.ParsePrefix(t.Prefix)
		if err != nil || p != p.Masked() {
			return fmt.Errorf("%w: targets[%d]: prefix %q must be a prefix without host bits", ErrForm, i, t.Prefix)
		}
		if seenPrefix[p.String()] {
			return fmt.Errorf("%w: targets[%d]: duplicate prefix %s", ErrForm, i, p)
		}
		seenPrefix[p.String()] = true
		if t.Host != "" {
			h, err := netip.ParseAddr(t.Host)
			if err != nil || !p.Contains(h) {
				return fmt.Errorf("%w: targets[%d]: host %q must be an address inside %s", ErrForm, i, t.Host, p)
			}
		}
	}
	if len(f.Allowlist) > MaxFormAllowlist {
		return fmt.Errorf("%w: at most %d allowlist prefixes in the form", ErrForm, MaxFormAllowlist)
	}
	for i, s := range f.Allowlist {
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() {
			return fmt.Errorf("%w: allowlist[%d]: prefix %q must be a prefix without host bits", ErrForm, i, s)
		}
	}
	return f.validateSections()
}

func numberField(name, value string, min, max float64) error {
	if value == "" {
		return nil
	}
	v, err := strconv.ParseFloat(value, 64)
	if err != nil || v < min || v > max {
		return fmt.Errorf("%w: %s %q must be between %v and %v", ErrForm, name, value, min, max)
	}
	return nil
}

func readProviders(root *yaml.Node, f *Form) error {
	seq, ok := sequenceChild(root, "providers")
	if !ok {
		return nil
	}
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			return fmt.Errorf("%w: providers must be a list of mappings", ErrForm)
		}
		name := scalar(item, "name")
		if name == "" {
			return fmt.Errorf("%w: a provider is missing its name", ErrForm)
		}
		commit, bound := bindingCommit(root, name)
		f.Providers = append(f.Providers, FormProvider{
			Key: name, Name: name, SourceIP: scalar(item, "source_ip"), NextHop: scalar(item, "next_hop"),
			Cost: scalar(item, "cost"), CommitMbps: commit, CommitBound: bound,
		})
	}
	return nil
}

func readTargets(root *yaml.Node, f *Form) error {
	src, ok := firstStatic(root)
	if !ok {
		return nil
	}
	cfg, ok := mappingChild(src, "config")
	if !ok {
		return nil
	}
	seq, ok := sequenceChild(cfg, "targets")
	if !ok {
		return nil
	}
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			return fmt.Errorf("%w: sources static targets must be a list of mappings", ErrForm)
		}
		prefix := scalar(item, "prefix")
		f.Targets = append(f.Targets, FormTarget{Key: prefix, Prefix: prefix, Host: scalar(item, "host")})
	}
	return nil
}

func applyScalars(root *yaml.Node, f Form) error {
	setOrDelete(root, "mode", f.Mode, "!!str")
	setOrDelete(root, "hold_time", f.HoldTime, "!!str")
	setOrDelete(root, "max_improvements", f.MaxImprovements, "!!int")
	th, ok := mappingChild(root, "thresholds")
	if f.MinLossDeltaPct == "" && f.MinRTTDeltaMs == "" && f.MinRTTDeltaPct == "" && f.ConfirmRounds == "" {
		if ok {
			deleteKey(th, "min_loss_delta_pct")
			deleteKey(th, "min_rtt_delta_ms")
			deleteKey(th, "min_rtt_delta_pct")
			deleteKey(th, "confirm_rounds")
			if len(th.Content) == 0 {
				deleteKey(root, "thresholds")
			}
		}
		return nil
	}
	if !ok {
		th = ensureMapping(root, "thresholds")
	}
	setOrDelete(th, "min_loss_delta_pct", f.MinLossDeltaPct, "!!float")
	setOrDelete(th, "min_rtt_delta_ms", f.MinRTTDeltaMs, "!!float")
	setOrDelete(th, "min_rtt_delta_pct", f.MinRTTDeltaPct, "!!float")
	setOrDelete(th, "confirm_rounds", f.ConfirmRounds, "!!int")
	return nil
}

func applyScorer(root *yaml.Node, cur, next Form) error {
	if cur.Precedence == next.Precedence && cur.FloorLossPct == next.FloorLossPct && cur.FloorRTT == next.FloorRTT {
		return nil
	}
	typ := scorerType(root)
	switch typ {
	case "", "weighted", "cost":
	default:
		return fmt.Errorf("%w: the cost floor and whether cost or performance wins are the cost scorer's knobs; this file uses scorer type %s. Change the scorer in the YAML if you mean to replace it", ErrForm, typ)
	}
	if next.Precedence == "" && next.FloorLossPct == "" && next.FloorRTT == "" {
		// Leaving the knobs unused must not switch the scorer on.
		if typ != "cost" {
			return nil
		}
	}
	scorer, ok := mappingChild(root, "scorer")
	if !ok {
		scorer = ensureMapping(root, "scorer")
	}
	if typ != "cost" {
		setOrDelete(scorer, "type", "cost", "!!str")
	}
	cfg := ensureMapping(scorer, "config")
	switch next.Precedence {
	case "", "performance":
		if next.Precedence == "" {
			deleteKey(cfg, "precedence")
		} else {
			setOrDelete(cfg, "precedence", "performance", "!!str")
		}
	case "cost":
		setOrDelete(cfg, "precedence", "cost", "!!str")
	}
	if next.FloorLossPct == "" && next.FloorRTT == "" {
		if floor, ok := mappingChild(cfg, "floor"); ok {
			deleteKey(floor, "max_loss_pct")
			deleteKey(floor, "max_rtt")
			if len(floor.Content) == 0 {
				deleteKey(cfg, "floor")
			}
		}
		return nil
	}
	floor := ensureMapping(cfg, "floor")
	setOrDelete(floor, "max_loss_pct", next.FloorLossPct, "!!float")
	setOrDelete(floor, "max_rtt", next.FloorRTT, "!!str")
	return nil
}

func applyProviders(root *yaml.Node, form Form) error {
	seq, ok := sequenceChild(root, "providers")
	old := map[string]*yaml.Node{}
	if ok {
		for _, item := range seq.Content {
			if item.Kind != yaml.MappingNode {
				return fmt.Errorf("%w: providers must be a list of mappings", ErrForm)
			}
			name := scalar(item, "name")
			if name == "" {
				return fmt.Errorf("%w: a provider is missing its name", ErrForm)
			}
			if _, dup := old[name]; dup {
				return fmt.Errorf("%w: duplicate provider name %s in the file", ErrForm, name)
			}
			old[name] = item
		}
	} else {
		seq = ensureSequence(root, "providers")
	}
	var next []*yaml.Node
	used := map[string]bool{}
	for _, p := range form.Providers {
		var node *yaml.Node
		if p.Key != "" {
			node = old[p.Key]
			if node == nil {
				return fmt.Errorf("%w: provider %s is not in the file anymore; reload the form", ErrForm, p.Key)
			}
			if used[p.Key] {
				return fmt.Errorf("%w: provider %s is listed twice", ErrForm, p.Key)
			}
			used[p.Key] = true
		} else {
			node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		writeProvider(node, p)
		next = append(next, node)
	}
	seq.Content = next
	return nil
}

func writeProvider(m *yaml.Node, p FormProvider) {
	setOrDelete(m, "name", p.Name, "!!str")
	setOrDelete(m, "source_ip", p.SourceIP, "!!str")
	setOrDelete(m, "next_hop", p.NextHop, "!!str")
	if p.Cost == "" {
		deleteKey(m, "cost")
	} else {
		setOrDelete(m, "cost", p.Cost, "!!float")
	}
	// ASN, draft, and commit are not provider keys. Commit stays on the
	// telemetry binding. A suggestion must not become a provider field
	// the loader would reject, and must not start a probe.
}

func applyCommits(root *yaml.Node, cur, next Form) error {
	prev := map[string]string{}
	for _, p := range cur.Providers {
		prev[p.Key] = p.CommitMbps
	}
	for _, p := range next.Providers {
		was := prev[p.Key]
		renamed := p.Key != "" && p.Key != p.Name
		if p.CommitMbps == was && !renamed {
			continue
		}
		if p.CommitMbps == "" && was != "" {
			return fmt.Errorf("%w: provider %s: commit stays on its telemetry binding; set it, or remove the binding in the YAML", ErrForm, p.Name)
		}
		n := rewriteBinding(root, p.Key, p.Name, p.CommitMbps, p.CommitMbps != was)
		if (p.CommitMbps != "" || was != "") && n == 0 {
			return fmt.Errorf("%w: provider %s: commit is the telemetry binding (secrets stay in environment variables). Add the binding in the YAML before setting a commit", ErrForm, p.Name)
		}
	}
	return nil
}

func applyTargets(root *yaml.Node, form Form) error {
	src, ok := firstStatic(root)
	if !ok {
		if len(form.Targets) == 0 {
			return nil
		}
		sources := ensureSequence(root, "sources")
		src = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setOrDelete(src, "type", "static", "!!str")
		sources.Content = append(sources.Content, src)
	}
	cfg := ensureMapping(src, "config")
	seq := ensureSequence(cfg, "targets")
	old := map[string]*yaml.Node{}
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		prefix := scalar(item, "prefix")
		if prefix != "" {
			old[prefix] = item
		}
	}
	var next []*yaml.Node
	used := map[*yaml.Node]bool{}
	for _, t := range form.Targets {
		node := old[t.Key]
		if t.Key == "" || node == nil || used[node] {
			node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		used[node] = true
		setOrDelete(node, "prefix", t.Prefix, "!!str")
		setOrDelete(node, "host", t.Host, "!!str")
		next = append(next, node)
	}
	seq.Content = next
	return nil
}

func applyAllowlist(root *yaml.Node, form Form) error {
	_, existed := mappingChild(root, "allowlist")
	if !existed && len(form.Allowlist) == 0 {
		return nil
	}
	al := ensureMapping(root, "allowlist")
	seq := ensureSequence(al, "prefixes")
	seq.Content = nil
	for _, p := range form.Allowlist {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p})
	}
	return nil
}

func mappingRoot(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, fmt.Errorf("%w: config must be one YAML document", ErrForm)
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: config must be a YAML mapping", ErrForm)
	}
	return root, nil
}

func child(m *yaml.Node, key string) (*yaml.Node, int) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1], i
		}
	}
	return nil, -1
}

func mappingChild(m *yaml.Node, key string) (*yaml.Node, bool) {
	n, _ := child(m, key)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, false
	}
	return n, true
}

func sequenceChild(m *yaml.Node, key string) (*yaml.Node, bool) {
	n, _ := child(m, key)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil, false
	}
	return n, true
}

func scalar(m *yaml.Node, key string) string {
	n, _ := child(m, key)
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return ""
	}
	return n.Value
}

func scalarList(m *yaml.Node, key string) []string {
	seq, ok := sequenceChild(m, key)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(seq.Content))
	for _, n := range seq.Content {
		if n.Kind == yaml.ScalarNode && n.Tag != "!!null" {
			out = append(out, n.Value)
		}
	}
	return out
}

func scorerType(root *yaml.Node) string {
	scorer, ok := mappingChild(root, "scorer")
	if !ok {
		return ""
	}
	return scalar(scorer, "type")
}

func scorerConfig(root *yaml.Node) (*yaml.Node, bool) {
	scorer, ok := mappingChild(root, "scorer")
	if !ok {
		return nil, false
	}
	return mappingChild(scorer, "config")
}

func firstStatic(root *yaml.Node) (*yaml.Node, bool) {
	seq, ok := sequenceChild(root, "sources")
	if !ok {
		return nil, false
	}
	for _, item := range seq.Content {
		if item.Kind == yaml.MappingNode && scalar(item, "type") == "static" {
			return item, true
		}
	}
	return nil, false
}

func ensureMapping(parent *yaml.Node, key string) *yaml.Node {
	if n, ok := mappingChild(parent, key); ok {
		return n
	}
	if n, i := child(parent, key); n != nil {
		parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
	}
	created := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, created)
	return created
}

func ensureSequence(parent *yaml.Node, key string) *yaml.Node {
	if n, ok := sequenceChild(parent, key); ok {
		return n
	}
	if n, i := child(parent, key); n != nil {
		parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
	}
	created := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, created)
	return created
}

func setOrDelete(m *yaml.Node, key, value, tag string) {
	if value == "" {
		deleteKey(m, key)
		return
	}
	tag = plainTag(value, tag)
	if n, _ := child(m, key); n != nil && n.Kind == yaml.ScalarNode {
		n.Value = value
		n.Tag = tag
		n.Style = 0
		return
	}
	deleteKey(m, key)
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value})
}

// plainTag keeps a whole number as an integer so the encoder does not
// write an explicit !!float tag. Float targets accept an integer.
func plainTag(value, tag string) string {
	if tag != "!!int" && tag != "!!float" {
		return tag
	}
	if strings.ContainsAny(value, ".eE") {
		return "!!float"
	}
	return "!!int"
}

func deleteKey(m *yaml.Node, key string) {
	_, i := child(m, key)
	if i < 0 {
		return
	}
	m.Content = append(m.Content[:i], m.Content[i+2:]...)
}

// bindingCommit is the first snmp telemetry binding's commit for name.
// The secret (community, passphrase) is never read into the form.
func bindingCommit(root *yaml.Node, name string) (string, bool) {
	seq, ok := sequenceChild(root, "telemetry")
	if !ok {
		return "", false
	}
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode || scalar(item, "type") != "snmp" {
			continue
		}
		cfg, ok := mappingChild(item, "config")
		if !ok {
			continue
		}
		provs, ok := sequenceChild(cfg, "providers")
		if !ok {
			continue
		}
		for _, b := range provs.Content {
			if b.Kind == yaml.MappingNode && scalar(b, "name") == name {
				return scalar(b, "commit_mbps"), true
			}
		}
	}
	return "", false
}

// rewriteBinding retargets snmp bindings from the provider's previous
// name to its new name, and writes commit when it changed. It returns
// how many bindings it found. An empty commit is not written; the caller
// refuses a clear instead of deleting a required field. Community strings
// and passphrases are not read or written.
func rewriteBinding(root *yaml.Node, from, to, commit string, commitChanged bool) int {
	seq, ok := sequenceChild(root, "telemetry")
	if !ok {
		return 0
	}
	match := from
	if match == "" {
		match = to
	}
	n := 0
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode || scalar(item, "type") != "snmp" {
			continue
		}
		cfg, ok := mappingChild(item, "config")
		if !ok {
			continue
		}
		provs, ok := sequenceChild(cfg, "providers")
		if !ok {
			continue
		}
		for _, b := range provs.Content {
			if b.Kind != yaml.MappingNode || scalar(b, "name") != match {
				continue
			}
			if from != "" && from != to {
				setOrDelete(b, "name", to, "!!str")
			}
			if commitChanged && commit != "" {
				setOrDelete(b, "commit_mbps", commit, "!!float")
			}
			n++
		}
	}
	return n
}
