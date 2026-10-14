package configedit

import (
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// The commit setup (#174) edits the pieces commit control reads: the
// scorer, its balance mode, the SNMP hosts and per-provider telemetry
// bindings, and each provider's group, precedence, and cc_disable. Like
// the other sections, a nil Commit in a request leaves the file alone and
// applying edits the YAML text only. Save runs the loader's checks. A
// community or passphrase is never a field: a new host names the
// environment variable that holds it.

// Limits of the commit setup.
const MaxFormHosts = 16

// FormCommit is the commit setup. Scorer asks for a switch to weighted,
// commit, or cost; ParseForm leaves it empty, and the scorer in the file is
// Form.ScorerType. Balance is the commit scorer's balance and is empty
// under any other scorer.
type FormCommit struct {
	Scorer    string               `json:"scorer"`
	Balance   string               `json:"balance"`
	Hosts     []FormCommitHost     `json:"hosts"`
	Providers []FormCommitProvider `json:"providers"`
}

// FormCommitHost is one SNMP host. Key is its name in the file; empty means
// a new host, written as SNMP version 2c. An existing host is shown for
// choosing and is edited in the YAML, which also holds SNMP version 3.
type FormCommitHost struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	Address      string `json:"address"`
	CommunityEnv string `json:"community_env"`
}

// FormCommitProvider is what commit control reads about one provider. Host
// names the telemetry binding (empty: none). The binding's commit_mbps is
// the provider row's CommitMbps in Form.Providers.
type FormCommitProvider struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	Interface  string `json:"interface"`
	BillingDay string `json:"billing_day"`
	Percentile string `json:"percentile"`
	Group      string `json:"group"`
	Precedence string `json:"precedence"`
	CCDisable  bool   `json:"cc_disable"`
}

var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// scorerShared are the scorer config keys every built-in scorer reads. The
// others belong to one scorer, and another scorer's strict decoder would
// refuse them.
var scorerShared = []string{"loss_weight", "rtt_weight", "jitter_weight", "improvement_weights"}

// ---- reading ----

func readCommit(root *yaml.Node, f *Form) {
	c := FormCommit{Hosts: []FormCommitHost{}, Providers: []FormCommitProvider{}}
	if f.ScorerType == "commit" {
		if cfg, ok := scorerConfig(root); ok {
			c.Balance = scalar(cfg, "balance")
		}
	}
	for _, cfg := range snmpConfigs(root) {
		if hosts, ok := sequenceChild(cfg, "hosts"); ok {
			for _, h := range hosts.Content {
				if h.Kind == yaml.MappingNode {
					name := scalar(h, "name")
					c.Hosts = append(c.Hosts, FormCommitHost{Key: name, Name: name, Address: scalar(h, "address"), CommunityEnv: scalar(h, "community_env")})
				}
			}
		}
	}
	if seq, ok := sequenceChild(root, "providers"); ok {
		for _, item := range seq.Content {
			name := scalar(item, "name")
			row := FormCommitProvider{Name: name, Group: scalar(item, "group"), Precedence: scalar(item, "precedence"), CCDisable: scalar(item, "cc_disable") == "true"}
			if b := findBinding(root, name); b != nil {
				row.Host, row.Interface = scalar(b, "host"), scalar(b, "interface")
				row.BillingDay, row.Percentile = scalar(b, "billing_day"), scalar(b, "percentile")
			}
			c.Providers = append(c.Providers, row)
		}
	}
	f.Commit = &c
}

// ---- normalize, fill, validate ----

func (f *Form) normalizeCommit() {
	c := f.Commit
	if c == nil {
		return
	}
	c.Scorer = strings.TrimSpace(c.Scorer)
	c.Balance = strings.TrimSpace(c.Balance)
	if c.Hosts == nil {
		c.Hosts = []FormCommitHost{}
	}
	if c.Providers == nil {
		c.Providers = []FormCommitProvider{}
	}
	for i := range c.Hosts {
		h := &c.Hosts[i]
		h.Key, h.Name = strings.TrimSpace(h.Key), strings.TrimSpace(h.Name)
		h.Address, h.CommunityEnv = strings.TrimSpace(h.Address), strings.TrimSpace(h.CommunityEnv)
	}
	for i := range c.Providers {
		p := &c.Providers[i]
		for _, s := range []*string{&p.Name, &p.Host, &p.Interface, &p.BillingDay, &p.Percentile, &p.Group, &p.Precedence} {
			*s = strings.TrimSpace(*s)
		}
	}
}

// fillCommit restores the display-only scorer type from the file, so the
// checks read the scorer the file has, not what a stale form remembers.
func (f *Form) fillCommit(cur Form) {
	f.ScorerType = cur.ScorerType
	if f.Commit == nil {
		f.Commit = cur.Commit
	}
}

func (f Form) validateCommit() error {
	c := f.Commit
	if c == nil {
		return nil
	}
	switch c.Scorer {
	case "":
	case "weighted", "commit", "cost":
		switch f.ScorerType {
		case "", "weighted", "commit", "cost":
		default:
			return fmt.Errorf("%w: commit.scorer: this file uses scorer type %s, which the form does not replace. Change it in the YAML", ErrForm, f.ScorerType)
		}
	default:
		return fmt.Errorf("%w: commit.scorer %q is invalid (want weighted, commit, or cost)", ErrForm, c.Scorer)
	}
	scorer := c.Scorer
	if scorer == "" {
		scorer = f.ScorerType
	}
	switch c.Balance {
	case "":
	case "off", "equal", "proportional":
		if scorer != "commit" {
			return fmt.Errorf("%w: commit.balance is the commit scorer's; the scorer is %s", ErrForm, orWeighted(scorer))
		}
	default:
		return fmt.Errorf("%w: commit.balance %q is invalid (want off, equal, or proportional)", ErrForm, c.Balance)
	}
	hosts, err := c.validateHosts()
	if err != nil {
		return err
	}
	provs := map[string]bool{}
	for _, p := range f.Providers {
		provs[p.Name] = true
	}
	seen := map[string]bool{}
	for i, p := range c.Providers {
		if !provs[p.Name] {
			return fmt.Errorf("%w: commit.providers[%d]: %q is not a provider in the form", ErrForm, i, p.Name)
		}
		if seen[p.Name] {
			return fmt.Errorf("%w: commit.providers[%d]: duplicate provider %s", ErrForm, i, p.Name)
		}
		seen[p.Name] = true
		if err := p.validate(hosts); err != nil {
			return err
		}
	}
	return nil
}

func orWeighted(typ string) string {
	if typ == "" {
		return "weighted"
	}
	return typ
}

// validateHosts checks the host rows and returns the names a binding may use.
func (c *FormCommit) validateHosts() (map[string]bool, error) {
	if len(c.Hosts) > MaxFormHosts {
		return nil, fmt.Errorf("%w: at most %d SNMP hosts in the form", ErrForm, MaxFormHosts)
	}
	names := map[string]bool{}
	for i, h := range c.Hosts {
		if !instanceName.MatchString(h.Name) {
			return nil, fmt.Errorf("%w: commit.hosts[%d]: name %q must be 1 to 64 letters, digits, dot, dash, or underscore", ErrForm, i, h.Name)
		}
		if names[h.Name] {
			return nil, fmt.Errorf("%w: commit.hosts[%d]: duplicate host %s", ErrForm, i, h.Name)
		}
		names[h.Name] = true
		if h.Key != "" {
			continue
		}
		if _, err := netip.ParseAddr(h.Address); err != nil && (h.Address == "" || len(h.Address) > 253 || strings.ContainsAny(h.Address, " /\\:@")) {
			return nil, fmt.Errorf("%w: commit.hosts[%d] (%s): address %q must be an IP address or a hostname", ErrForm, i, h.Name, h.Address)
		}
		if !envVarName.MatchString(h.CommunityEnv) {
			return nil, fmt.Errorf("%w: commit.hosts[%d] (%s): community_env %q must be the name of an environment variable, not the community", ErrForm, i, h.Name, h.CommunityEnv)
		}
	}
	return names, nil
}

func (p FormCommitProvider) validate(hosts map[string]bool) error {
	label := "commit.providers " + p.Name
	if p.Group != "" && !instanceName.MatchString(p.Group) {
		return fmt.Errorf("%w: %s: group %q must be 1 to 64 letters, digits, dot, dash, or underscore", ErrForm, label, p.Group)
	}
	if err := validInt(label+": precedence", p.Precedence, 0, 10000); err != nil {
		return err
	}
	if p.Host == "" {
		if p.Interface != "" || p.BillingDay != "" || p.Percentile != "" {
			return fmt.Errorf("%w: %s: the telemetry binding needs a host", ErrForm, label)
		}
		return nil
	}
	if !hosts[p.Host] {
		return fmt.Errorf("%w: %s: host %q is not an SNMP host in the form", ErrForm, label, p.Host)
	}
	if p.Interface == "" || len(p.Interface) > 255 {
		return fmt.Errorf("%w: %s: interface is required (at most 255 characters)", ErrForm, label)
	}
	if p.BillingDay == "" {
		return fmt.Errorf("%w: %s: billing_day is required (1 to 28)", ErrForm, label)
	}
	if err := validInt(label+": billing_day", p.BillingDay, 1, 28); err != nil {
		return err
	}
	switch p.Percentile {
	case "separate", "greater", "greater_separate":
		return nil
	}
	return fmt.Errorf("%w: %s: percentile %q is invalid (want separate, greater, or greater_separate)", ErrForm, label, p.Percentile)
}

// checkCommitChange refuses an edit to, or the removal of, an SNMP host that
// is already in the file. The setup shows those hosts for choosing; their
// address and credentials stay in the YAML.
func (f Form) checkCommitChange(cur Form) error {
	if f.Commit == nil || cur.Commit == nil {
		return nil
	}
	old := map[string]FormCommitHost{}
	for _, h := range cur.Commit.Hosts {
		old[h.Key] = h
	}
	kept := map[string]bool{}
	for _, h := range f.Commit.Hosts {
		kept[h.Key] = true
		if h.Key == "" {
			if _, dup := old[h.Name]; dup {
				return fmt.Errorf("%w: SNMP host %s is already in the file; choose it instead of adding it", ErrForm, h.Name)
			}
			continue
		}
		if o, ok := old[h.Key]; !ok || o != h {
			return fmt.Errorf("%w: SNMP host %s is edited in the YAML (its address, version, and credentials stay there)", ErrForm, h.Key)
		}
	}
	for key := range old {
		if !kept[key] {
			return fmt.Errorf("%w: SNMP host %s is removed in the YAML, not in the form", ErrForm, key)
		}
	}
	return nil
}

// ---- applying ----

func applyCommit(root *yaml.Node, cur, next Form) error {
	nc := next.Commit
	if nc == nil || reflect.DeepEqual(cur.Commit, nc) {
		return nil
	}
	applyCommitScorer(root, cur, *nc)
	for _, h := range nc.Hosts {
		if h.Key == "" {
			addHost(root, h)
		}
	}
	old := map[string]FormCommitProvider{}
	for _, p := range cur.Commit.Providers {
		old[p.Name] = p
	}
	rows := map[string]FormProvider{}
	for _, p := range next.Providers {
		rows[p.Name] = p
	}
	byName := map[string]*yaml.Node{}
	if seq, ok := sequenceChild(root, "providers"); ok {
		for _, item := range seq.Content {
			byName[scalar(item, "name")] = item
		}
	}
	for _, row := range nc.Providers {
		if o, ok := old[row.Name]; ok && o == row {
			continue
		}
		node := byName[row.Name]
		if node == nil {
			return fmt.Errorf("%w: provider %s is not in the file", ErrForm, row.Name)
		}
		setOrDelete(node, "group", row.Group, "!!str")
		setOrDelete(node, "precedence", row.Precedence, "!!int")
		if row.CCDisable {
			setOrDelete(node, "cc_disable", "true", "!!bool")
		} else {
			deleteKey(node, "cc_disable")
		}
		if row.Host == "" {
			continue
		}
		fp := rows[row.Name]
		if err := writeBinding(root, fp, row); err != nil {
			return err
		}
	}
	return nil
}

func applyCommitScorer(root *yaml.Node, cur Form, nc FormCommit) {
	typ := orWeighted(cur.ScorerType)
	if nc.Scorer != "" && nc.Scorer != typ {
		scorer := ensureMapping(root, "scorer")
		setOrDelete(scorer, "type", nc.Scorer, "!!str")
		if cfg, ok := mappingChild(scorer, "config"); ok {
			var kept []*yaml.Node
			for i := 0; i+1 < len(cfg.Content); i += 2 {
				if slices.Contains(scorerShared, cfg.Content[i].Value) {
					kept = append(kept, cfg.Content[i], cfg.Content[i+1])
				}
			}
			cfg.Content = kept
			if len(kept) == 0 {
				deleteKey(scorer, "config")
			}
		}
		typ = nc.Scorer
	}
	if typ != "commit" || nc.Balance == cur.Commit.Balance {
		return
	}
	scorer := ensureMapping(root, "scorer")
	if nc.Balance == "" {
		if cfg, ok := mappingChild(scorer, "config"); ok {
			deleteKey(cfg, "balance")
		}
		return
	}
	setOrDelete(ensureMapping(scorer, "config"), "balance", nc.Balance, "!!str")
}

// addHost appends a version 2c host to the first snmp telemetry entry,
// creating the entry when the file has none.
func addHost(root *yaml.Node, h FormCommitHost) {
	cfg := firstSNMPConfig(root)
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	setOrDelete(node, "name", h.Name, "!!str")
	setOrDelete(node, "address", h.Address, "!!str")
	setOrDelete(node, "version", "2c", "!!str")
	setOrDelete(node, "community_env", h.CommunityEnv, "!!str")
	seq := ensureSequence(cfg, "hosts")
	seq.Content = append(seq.Content, node)
}

func firstSNMPConfig(root *yaml.Node) *yaml.Node {
	if cfgs := snmpConfigs(root); len(cfgs) > 0 {
		return cfgs[0]
	}
	seq := ensureSequence(root, "telemetry")
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	setOrDelete(entry, "type", "snmp", "!!str")
	seq.Content = append(seq.Content, entry)
	return ensureMapping(entry, "config")
}

// writeBinding sets the binding of fp's provider, adding it to the snmp
// entry that lists the host. A rename in the same request is retargeted
// later by applyCommits, so the binding is looked up by the old name.
func writeBinding(root *yaml.Node, fp FormProvider, row FormCommitProvider) error {
	match := fp.Key
	if match == "" {
		match = fp.Name
	}
	b := findBinding(root, match)
	if b == nil {
		if fp.CommitMbps == "" {
			return fmt.Errorf("%w: provider %s: enter commit_mbps (greater than zero) to add its telemetry binding", ErrForm, fp.Name)
		}
		var cfg *yaml.Node
		for _, c := range snmpConfigs(root) {
			if hostNamed(c, row.Host) {
				cfg = c
			}
		}
		if cfg == nil {
			return fmt.Errorf("%w: provider %s: host %s is not an SNMP host in the file", ErrForm, fp.Name, row.Host)
		}
		b = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setOrDelete(b, "name", match, "!!str")
		seq := ensureSequence(cfg, "providers")
		seq.Content = append(seq.Content, b)
	}
	setOrDelete(b, "host", row.Host, "!!str")
	setOrDelete(b, "interface", row.Interface, "!!str")
	setOrDelete(b, "billing_day", row.BillingDay, "!!int")
	setOrDelete(b, "percentile", row.Percentile, "!!str")
	return nil
}

func hostNamed(cfg *yaml.Node, name string) bool {
	hosts, ok := sequenceChild(cfg, "hosts")
	if !ok {
		return false
	}
	for _, h := range hosts.Content {
		if scalar(h, "name") == name {
			return true
		}
	}
	return false
}
