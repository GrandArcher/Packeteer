package configedit

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

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

func applyRules(node *yaml.Node, p FormPolicies) error {
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
