package configedit

import (
	"fmt"
	"slices"

	"gopkg.in/yaml.v3"
)

// Change is one scalar key that differs between two config files. Old is
// nil when the key was not in the old file, New is nil when it is gone.
// Key is a dotted path; a list item is name[index].
type Change struct {
	Key string  `json:"key"`
	Old *string `json:"old"`
	New *string `json:"new"`
}

// Diff lists the scalar keys that differ between two config files, sorted
// by key. A file that does not parse as YAML counts as empty; Save has
// already checked the new one.
func Diff(oldData, newData []byte) []Change {
	before, after := flatten(oldData), flatten(newData)
	keys := make([]string, 0, len(before)+len(after))
	for k := range before {
		keys = append(keys, k)
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var out []Change
	for _, k := range keys {
		o, hadOld := before[k]
		n, hadNew := after[k]
		if hadOld && hadNew && o == n {
			continue
		}
		c := Change{Key: k}
		if hadOld {
			c.Old = &o
		}
		if hadNew {
			c.New = &n
		}
		out = append(out, c)
	}
	return out
}

func flatten(data []byte) map[string]string {
	out := map[string]string{}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil || len(doc.Content) == 0 {
		return out
	}
	walk(out, "", doc.Content[0], 0)
	return out
}

// maxDepth bounds recursion through aliases.
const maxDepth = 32

func walk(out map[string]string, key string, n *yaml.Node, depth int) {
	if depth > maxDepth {
		return
	}
	switch n.Kind {
	case yaml.AliasNode:
		walk(out, key, n.Alias, depth+1)
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if key != "" {
				k = key + "." + k
			}
			walk(out, k, n.Content[i+1], depth+1)
		}
	case yaml.SequenceNode:
		for i, item := range n.Content {
			walk(out, fmt.Sprintf("%s[%d]", key, i), item, depth+1)
		}
	case yaml.ScalarNode:
		out[key] = n.Value
	}
}
