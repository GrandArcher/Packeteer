package configedit

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Form sections (#130, #226): the flow, vip, and outage sources and the
// rules policies. Each is a list with one entry per instance in the file.
// A nil list in a request means "leave it alone", so an older client that
// does not know the section cannot remove anything. ParseForm always
// fills them. An entry's Key is its position in the file's sources (or
// policies) list when the form was loaded; empty means a new entry. An
// entry left out of the list is removed. Applying a section edits the
// YAML text only; Save runs the same checks as a start, and nothing here
// can turn inject on or announce.

// Section limits. A larger edit belongs in the YAML.
const (
	MaxFormRules      = 1000
	MaxFormListValues = 4096
	MaxFormInstances  = 64
)

// FormFlow is one `flow` source. Removing it from the list removes the
// source from the file, including its problems, transit, and subranges
// blocks. Those three blocks are kept as they are while the source stays.
// TopN is the priority tier, MaxTargets the larger capped set, and
// TailInterval the interval for the rest. AggregateV4 and AggregateV6 are
// the prefix lengths unmatched destinations are grouped to.
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

// FormPolicies is one `rules` policy. Its order among the rules policies
// is its order in the list: the entries swap into the file positions the
// rules policies already hold, so other policy types keep their place. A
// policy with no rules is refused (the loader requires one); remove the
// entry instead. GeoIPDB is the absolute path of a MaxMind-format
// database in the container; a rule with countries needs it. The form
// does not fetch the database.
type FormPolicies struct {
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

// entry is one instance of a plugin type in a top-level list.
type entry struct {
	key  string
	node *yaml.Node
}

// entries lists the mapping items of type typ in the sequence at seqKey,
// keyed by their position in that sequence.
func entries(root *yaml.Node, seqKey, typ string) []entry {
	seq, ok := sequenceChild(root, seqKey)
	if !ok {
		return nil
	}
	var out []entry
	for i, item := range seq.Content {
		if item.Kind == yaml.MappingNode && scalar(item, "type") == typ {
			out = append(out, entry{key: strconv.Itoa(i), node: item})
		}
	}
	return out
}

func configMap(node *yaml.Node) *yaml.Node {
	cfg, _ := mappingChild(node, "config")
	return cfg
}

func readSections(root *yaml.Node, f *Form) error {
	f.Flows = []FormFlow{}
	for _, e := range entries(root, "sources", "flow") {
		fl := FormFlow{Key: e.key, Name: scalar(e.node, "name"), Listen: []string{}, Exclude: []string{}}
		if cfg := configMap(e.node); cfg != nil {
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

	f.Policies = []FormPolicies{}
	for _, e := range entries(root, "policies", "rules") {
		pol := FormPolicies{Key: e.key, Name: scalar(e.node, "name"), Rules: []FormRule{}}
		if cfg := configMap(e.node); cfg != nil {
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
	for _, e := range entries(root, "sources", "vip") {
		vip := FormVIP{Key: e.key, Name: scalar(e.node, "name"), Prefixes: []FormTarget{}, ASNs: []string{}}
		if cfg := configMap(e.node); cfg != nil {
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
	for _, e := range entries(root, "sources", "outage") {
		out := FormOutage{Key: e.key, Name: scalar(e.node, "name"), IgnoreASNs: []string{}}
		if cfg := configMap(e.node); cfg != nil {
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

// listOrScalar reads a key that is one string or a list of them.
func listOrScalar(m *yaml.Node, key string) []string {
	if n, _ := child(m, key); n != nil && n.Kind == yaml.ScalarNode && n.Tag != "!!null" {
		return []string{n.Value}
	}
	return scalarList(m, key)
}
