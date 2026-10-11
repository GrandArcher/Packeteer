package configedit

import (
	"fmt"
	"reflect"

	"gopkg.in/yaml.v3"
)

// ---- applying ----

func applySections(root *yaml.Node, cur, next Form) error {
	if !reflect.DeepEqual(cur.Flows, next.Flows) {
		keys := make([]string, len(next.Flows))
		for i, fl := range next.Flows {
			keys[i] = fl.Key
		}
		nodes, err := syncEntries(root, "sources", "flow", keys)
		if err != nil {
			return err
		}
		for i, fl := range next.Flows {
			applyFlow(nodes[i], fl)
		}
	}
	if !reflect.DeepEqual(cur.VIPs, next.VIPs) {
		keys := make([]string, len(next.VIPs))
		for i, v := range next.VIPs {
			keys[i] = v.Key
		}
		nodes, err := syncEntries(root, "sources", "vip", keys)
		if err != nil {
			return err
		}
		for i, v := range next.VIPs {
			applyVIP(nodes[i], v)
		}
	}
	if !reflect.DeepEqual(cur.Outages, next.Outages) {
		keys := make([]string, len(next.Outages))
		for i, o := range next.Outages {
			keys[i] = o.Key
		}
		nodes, err := syncEntries(root, "sources", "outage", keys)
		if err != nil {
			return err
		}
		for i, o := range next.Outages {
			applyOutage(nodes[i], o)
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
		nodes, err := syncEntries(root, "policies", "rules", keys)
		if err != nil {
			return err
		}
		for i, p := range next.Policies {
			if err := applyRules(nodes[i], p); err != nil {
				return err
			}
		}
	}
	return nil
}

// syncEntries makes the instances of typ in the top-level list seqKey match
// keys: an empty key is a new entry, a key the list lacks is removed, and
// the order of the listed entries is their order among the positions the
// type already holds, so entries of other types do not move. It returns
// the nodes in key order for the caller to fill.
func syncEntries(root *yaml.Node, seqKey, typ string, keys []string) ([]*yaml.Node, error) {
	old := map[string]*yaml.Node{}
	for _, e := range entries(root, seqKey, typ) {
		old[e.key] = e.node
	}
	ordered := make([]*yaml.Node, len(keys))
	kept := map[*yaml.Node]bool{}
	for i, k := range keys {
		if k == "" {
			n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			setOrDelete(n, "type", typ, "!!str")
			ordered[i] = n
			continue
		}
		n := old[k]
		if n == nil {
			return nil, fmt.Errorf("%w: %s entry %s is not in the file anymore; reload the form", ErrForm, seqKey, k)
		}
		if kept[n] {
			return nil, fmt.Errorf("%w: %s entry %s is listed twice", ErrForm, seqKey, k)
		}
		kept[n] = true
		ordered[i] = n
	}
	seq, ok := sequenceChild(root, seqKey)
	if !ok {
		if len(ordered) == 0 {
			return nil, nil
		}
		seq = ensureSequence(root, seqKey)
	}
	var content []*yaml.Node
	for _, item := range seq.Content {
		switch {
		case kept[item]:
			content = append(content, nil)
		case item.Kind == yaml.MappingNode && scalar(item, "type") == typ:
		default:
			content = append(content, item)
		}
	}
	next := 0
	for i := range content {
		if content[i] == nil {
			content[i] = ordered[next]
			next++
		}
	}
	seq.Content = append(content, ordered[next:]...)
	if len(seq.Content) == 0 {
		deleteKey(root, seqKey)
	}
	return ordered, nil
}
