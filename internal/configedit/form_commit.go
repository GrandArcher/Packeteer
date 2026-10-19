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

// FormCommitHost is one SNMP host (#330: v2c or v3, new or edited). Key is
// its name in the file; empty means a new host. Version is 2c or 3; a new
// host that leaves it empty is 2c. Every credential field names an
// environment variable: the community and the passphrases are never typed
// here and never read into the form.
type FormCommitHost struct {
	Key           string `json:"key"`
	Name          string `json:"name"`
	Address       string `json:"address"`
	Port          string `json:"port"`
	Version       string `json:"version"`
	CommunityEnv  string `json:"community_env"`
	UsernameEnv   string `json:"username_env"`
	SecurityLevel string `json:"security_level"`
	AuthProtocol  string `json:"auth_protocol"`
	AuthEnv       string `json:"auth_env"`
	PrivProtocol  string `json:"priv_protocol"`
	PrivEnv       string `json:"priv_env"`
	ContextName   string `json:"context_name"`
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
					c.Hosts = append(c.Hosts, readHost(h))
				}
			}
		}
	}
	if seq, ok := sequenceChild(root, "providers"); ok {
		for _, item := range seq.Content {
			name := scalar(item, "name")
			row := FormCommitProvider{Name: name, Group: scalar(item, "group"), Precedence: scalar(item, "precedence"), CCDisable: boolScalar(item, "cc_disable")}
			if b := findBinding(root, name); b != nil {
				row.Host, row.Interface = scalar(b, "host"), scalar(b, "interface")
				row.BillingDay, row.Percentile = scalar(b, "billing_day"), strings.ToLower(strings.TrimSpace(scalar(b, "percentile")))
			}
			c.Providers = append(c.Providers, row)
		}
	}
	f.Commit = &c
}

func readHost(h *yaml.Node) FormCommitHost {
	name := scalar(h, "name")
	return FormCommitHost{
		Key: name, Name: name, Address: scalar(h, "address"), Port: scalar(h, "port"), Version: scalar(h, "version"),
		CommunityEnv: scalar(h, "community_env"), UsernameEnv: scalar(h, "username_env"),
		SecurityLevel: scalar(h, "security_level"), AuthProtocol: scalar(h, "auth_protocol"), AuthEnv: scalar(h, "auth_env"),
		PrivProtocol: scalar(h, "priv_protocol"), PrivEnv: scalar(h, "priv_env"), ContextName: scalar(h, "context_name"),
	}
}

// boolScalar reads a YAML boolean the way the loader does, so True and TRUE
// count. A value the loader would refuse reads as false.
func boolScalar(m *yaml.Node, key string) bool {
	n, _ := child(m, key)
	var b bool
	if n == nil || n.Kind != yaml.ScalarNode || n.Decode(&b) != nil {
		return false
	}
	return b
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
		for _, s := range []*string{&h.Key, &h.Name, &h.Address, &h.Port, &h.Version, &h.CommunityEnv, &h.UsernameEnv,
			&h.SecurityLevel, &h.AuthProtocol, &h.AuthEnv, &h.PrivProtocol, &h.PrivEnv, &h.ContextName} {
			*s = strings.TrimSpace(*s)
		}
		if h.Key == "" && h.Version == "" {
			h.Version = "2c"
		}
	}
	for i := range c.Providers {
		p := &c.Providers[i]
		for _, s := range []*string{&p.Name, &p.Host, &p.Interface, &p.BillingDay, &p.Percentile, &p.Group, &p.Precedence} {
			*s = strings.TrimSpace(*s)
		}
		p.Percentile = strings.ToLower(p.Percentile)
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
	}
	return names, nil
}

// snmpSecurityLevels are the v3 security levels, and the protocols each
// secret type accepts.
var (
	snmpSecurityLevels = []string{"noAuthNoPriv", "authNoPriv", "authPriv"}
	snmpAuthProtocols  = []string{"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"}
	snmpPrivProtocols  = []string{"DES", "AES", "AES192", "AES256", "AES192C", "AES256C"}
)

// validateFields checks one host the operator added or edited. The place
// of a credential is an environment variable name, never its value.
func (h FormCommitHost) validateFields(at string) error {
	if _, err := netip.ParseAddr(h.Address); err != nil && (h.Address == "" || len(h.Address) > 253 || strings.ContainsAny(h.Address, " /\\:@")) {
		return fmt.Errorf("%w: %s.address: %q must be an IP address or a hostname", ErrForm, at, h.Address)
	}
	if err := validInt(at+".port", h.Port, 1, 65535); err != nil {
		return err
	}
	if len(h.ContextName) > 64 || strings.ContainsAny(h.ContextName, "\r\n") {
		return fmt.Errorf("%w: %s.context_name must be one line of at most 64 characters", ErrForm, at)
	}
	env := func(key, v string, want bool) error {
		switch {
		case v == "" && !want:
			return nil
		case v == "":
			return fmt.Errorf("%w: %s.%s: the name of an environment variable is required", ErrForm, at, key)
		case !want:
			return fmt.Errorf("%w: %s.%s does not apply to %s", ErrForm, at, key, h.describe())
		case !envVarName.MatchString(v):
			return fmt.Errorf("%w: %s.%s: %q must be the name of an environment variable, not the secret", ErrForm, at, key, v)
		}
		return nil
	}
	switch h.Version {
	case "2c":
		for _, k := range [][2]string{{"username_env", h.UsernameEnv}, {"security_level", h.SecurityLevel}, {"auth_protocol", h.AuthProtocol},
			{"auth_env", h.AuthEnv}, {"priv_protocol", h.PrivProtocol}, {"priv_env", h.PrivEnv}, {"context_name", h.ContextName}} {
			if k[1] != "" {
				return fmt.Errorf("%w: %s.%s does not apply to SNMP version 2c", ErrForm, at, k[0])
			}
		}
		return env("community_env", h.CommunityEnv, true)
	case "3":
		if err := env("community_env", h.CommunityEnv, false); err != nil {
			return err
		}
		if err := env("username_env", h.UsernameEnv, true); err != nil {
			return err
		}
		if !containsStr(snmpSecurityLevels, h.SecurityLevel) {
			return fmt.Errorf("%w: %s.security_level %q is invalid (want %s)", ErrForm, at, h.SecurityLevel, strings.Join(snmpSecurityLevels, ", "))
		}
		auth, priv := h.SecurityLevel != "noAuthNoPriv", h.SecurityLevel == "authPriv"
		if auth && !containsStr(snmpAuthProtocols, h.AuthProtocol) {
			return fmt.Errorf("%w: %s.auth_protocol %q is invalid (want %s)", ErrForm, at, h.AuthProtocol, strings.Join(snmpAuthProtocols, ", "))
		}
		if !auth && h.AuthProtocol != "" {
			return fmt.Errorf("%w: %s.auth_protocol does not apply to %s", ErrForm, at, h.SecurityLevel)
		}
		if priv && !containsStr(snmpPrivProtocols, h.PrivProtocol) {
			return fmt.Errorf("%w: %s.priv_protocol %q is invalid (want %s)", ErrForm, at, h.PrivProtocol, strings.Join(snmpPrivProtocols, ", "))
		}
		if !priv && h.PrivProtocol != "" {
			return fmt.Errorf("%w: %s.priv_protocol does not apply to %s", ErrForm, at, h.SecurityLevel)
		}
		if err := env("auth_env", h.AuthEnv, auth); err != nil {
			return err
		}
		return env("priv_env", h.PrivEnv, priv)
	}
	return fmt.Errorf("%w: %s.version %q is invalid (want 2c or 3)", ErrForm, at, h.Version)
}

// SNMPSecurityLevels, SNMPAuthProtocols, and SNMPPrivProtocols are the
// choices of an SNMP version 3 host, for the page.
func SNMPSecurityLevels() []string { return slices.Clone(snmpSecurityLevels) }
func SNMPAuthProtocols() []string  { return slices.Clone(snmpAuthProtocols) }
func SNMPPrivProtocols() []string  { return slices.Clone(snmpPrivProtocols) }

func (h FormCommitHost) describe() string {
	if h.Version == "3" {
		return "SNMP version 3 at " + h.SecurityLevel
	}
	return "SNMP version " + h.Version
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

// checkCommitChange checks the hosts the operator added or edited, and that
// a host is removed only when no provider is bound to it any more. A host
// that is not changed is not checked again: the loader judged it.
func (f Form) checkCommitChange(cur Form) error {
	if f.Commit == nil || cur.Commit == nil {
		return nil
	}
	old := map[string]FormCommitHost{}
	for _, h := range cur.Commit.Hosts {
		old[h.Key] = h
	}
	kept := map[string]bool{}
	for i, h := range f.Commit.Hosts {
		at := fmt.Sprintf("commit.hosts[%d]", i)
		if h.Key == "" {
			if _, dup := old[h.Name]; dup {
				return fmt.Errorf("%w: %s: SNMP host %s is already in the file; choose it instead of adding it", ErrForm, at, h.Name)
			}
			if err := h.validateFields(at); err != nil {
				return err
			}
			continue
		}
		o, ok := old[h.Key]
		if !ok {
			return fmt.Errorf("%w: %s: SNMP host %s is not in the file anymore; reload the form", ErrForm, at, h.Key)
		}
		kept[h.Key] = true
		if o != h {
			if err := h.validateFields(at); err != nil {
				return err
			}
		}
	}
	bound := map[string]string{}
	for _, p := range f.Commit.Providers {
		if p.Host != "" {
			bound[p.Host] = p.Name
		}
	}
	for key := range old {
		if !kept[key] && bound[key] != "" {
			return fmt.Errorf("%w: commit.hosts: SNMP host %s is still used by provider %s; untrack the provider first", ErrForm, key, bound[key])
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
	applyHosts(root, cur.Commit.Hosts, nc.Hosts)
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
		if o, ok := old[row.Name]; ok && o.Host != "" && row.Host == "" {
			untrack(root, rows[row.Name], row)
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

// applyHosts adds the new hosts to the first snmp telemetry entry, rewrites
// the edited ones where they are, and removes the ones the form dropped. A
// rename also retargets the bindings that named the host.
func applyHosts(root *yaml.Node, cur, next []FormCommitHost) {
	old := map[string]FormCommitHost{}
	for _, h := range cur {
		old[h.Key] = h
	}
	kept := map[string]bool{}
	for _, h := range next {
		if h.Key == "" {
			node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			writeHost(node, h)
			seq := ensureSequence(firstSNMPConfig(root), "hosts")
			seq.Content = append(seq.Content, node)
			continue
		}
		kept[h.Key] = true
		if old[h.Key] == h {
			continue
		}
		for _, cfg := range snmpConfigs(root) {
			hosts, ok := sequenceChild(cfg, "hosts")
			if !ok {
				continue
			}
			for _, node := range hosts.Content {
				if scalar(node, "name") == h.Key {
					writeHost(node, h)
				}
			}
		}
		if h.Name != h.Key {
			for _, b := range bindingNodes(root) {
				if scalar(b, "host") == h.Key {
					setOrDelete(b, "host", h.Name, "!!str")
				}
			}
		}
	}
	removed := false
	for key := range old {
		if kept[key] {
			continue
		}
		removed = true
		for _, cfg := range snmpConfigs(root) {
			if hosts, ok := sequenceChild(cfg, "hosts"); ok {
				hosts.Content = slices.DeleteFunc(hosts.Content, func(n *yaml.Node) bool { return scalar(n, "name") == key })
			}
		}
	}
	if removed {
		pruneSNMP(root)
	}
}

// writeHost sets the keys of one host for its SNMP version. The keys of the
// other version are deleted, so a version switch leaves a host the loader
// accepts. Credentials are environment variable names.
func writeHost(node *yaml.Node, h FormCommitHost) {
	setOrDelete(node, "name", h.Name, "!!str")
	setOrDelete(node, "address", h.Address, "!!str")
	setOrDelete(node, "port", h.Port, "!!int")
	setOrDelete(node, "version", h.Version, "!!str")
	setOrDelete(node, "community_env", h.CommunityEnv, "!!str")
	setOrDelete(node, "username_env", h.UsernameEnv, "!!str")
	setOrDelete(node, "security_level", h.SecurityLevel, "!!str")
	setOrDelete(node, "auth_protocol", h.AuthProtocol, "!!str")
	setOrDelete(node, "auth_env", h.AuthEnv, "!!str")
	setOrDelete(node, "priv_protocol", h.PrivProtocol, "!!str")
	setOrDelete(node, "priv_env", h.PrivEnv, "!!str")
	setOrDelete(node, "context_name", h.ContextName, "!!str")
}

// untrack removes a provider's telemetry bindings. The provider stays.
func untrack(root *yaml.Node, fp FormProvider, row FormCommitProvider) {
	name := fp.Key
	if name == "" {
		name = row.Name
	}
	for _, cfg := range snmpConfigs(root) {
		if provs, ok := sequenceChild(cfg, "providers"); ok {
			provs.Content = slices.DeleteFunc(provs.Content, func(n *yaml.Node) bool { return scalar(n, "name") == name })
			if len(provs.Content) == 0 {
				deleteKey(cfg, "providers")
			}
		}
	}
	pruneSNMP(root)
}

// pruneSNMP drops an snmp telemetry entry with no host and no binding left,
// and the telemetry list when that empties it.
func pruneSNMP(root *yaml.Node) {
	seq, ok := sequenceChild(root, "telemetry")
	if !ok {
		return
	}
	seq.Content = slices.DeleteFunc(seq.Content, func(item *yaml.Node) bool {
		if item.Kind != yaml.MappingNode || scalar(item, "type") != "snmp" {
			return false
		}
		cfg, ok := mappingChild(item, "config")
		if !ok {
			return false
		}
		for _, k := range []string{"hosts", "providers"} {
			if s, ok := sequenceChild(cfg, k); ok && len(s.Content) > 0 {
				return false
			}
		}
		return true
	})
	if len(seq.Content) == 0 {
		deleteKey(root, "telemetry")
	}
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
