package configedit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// FieldChange is one managed provider key. Old is empty when the key was
// not set.
type FieldChange struct {
	Field string
	Old   string
	New   string
}

// ProviderChange is what the plan does to one provider: "add" appends it,
// "update" changes the listed keys and leaves every other key as it is.
type ProviderChange struct {
	Name   string
	Action string
	Fields []FieldChange
}

// InventoryPlan is the change an inventory read would make to a config
// file (#208). Nothing is written. YAML is the file after the change, and
// ID names those exact bytes, so `apply` can refuse when the inventory or
// the file moved since the plan was shown. The plan never removes a
// provider, and it never touches a key the inventory does not manage.
type InventoryPlan struct {
	Changes        []ProviderChange
	Skipped        []plugin.InventorySkip
	Unchanged      []string
	NotInInventory []string
	YAML           []byte
	Diff           string
	ID             string
}

// Changed reports whether applying the plan would change the file.
func (p InventoryPlan) Changed() bool { return len(p.Changes) > 0 }

// PlanInventory merges res into the providers of current. A provider is
// matched by name. Its asn, type, source_ip, next_hop, and communities are
// set from the inventory when the inventory has a value for them. A new
// provider needs both next_hop and source_ip. The result must pass
// config.Parse, which holds the same checks the controller starts with.
func PlanInventory(current []byte, res plugin.InventoryResult) (InventoryPlan, error) {
	if _, err := config.Parse(current); err != nil {
		return InventoryPlan{}, fmt.Errorf("the current config does not load: %w", err)
	}
	root, err := mappingRoot(current)
	if err != nil {
		return InventoryPlan{}, err
	}
	seq := ensureSequence(root, "providers")
	byName := map[string]*yaml.Node{}
	for _, item := range seq.Content {
		if item.Kind == yaml.MappingNode {
			byName[scalar(item, "name")] = item
		}
	}
	plan := InventoryPlan{Skipped: slices.Clone(res.Skipped)}
	named := map[string]bool{}
	for _, p := range res.Providers {
		named[p.Name] = true
		node, exists := byName[p.Name]
		if !exists {
			if p.NextHop == "" || p.SourceIP == "" {
				plan.Skipped = append(plan.Skipped, plugin.InventorySkip{Name: p.Name, Reason: "not in the config, and a new provider needs next_hop and source_ip"})
				continue
			}
			node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			setOrDelete(node, "name", p.Name, "!!str")
			seq.Content = append(seq.Content, node)
		}
		fields := applyManaged(node, p)
		switch {
		case !exists:
			plan.Changes = append(plan.Changes, ProviderChange{Name: p.Name, Action: "add", Fields: fields})
		case len(fields) > 0:
			plan.Changes = append(plan.Changes, ProviderChange{Name: p.Name, Action: "update", Fields: fields})
		default:
			plan.Unchanged = append(plan.Unchanged, p.Name)
		}
	}
	for _, item := range seq.Content {
		if n := scalar(item, "name"); n != "" && !named[n] {
			plan.NotInInventory = append(plan.NotInInventory, n)
		}
	}
	slices.Sort(plan.NotInInventory)
	slices.SortFunc(plan.Skipped, func(a, b plugin.InventorySkip) int { return strings.Compare(a.Name, b.Name) })
	plan.YAML = current
	if plan.Changed() {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(root); err != nil {
			return InventoryPlan{}, err
		}
		if err := enc.Close(); err != nil {
			return InventoryPlan{}, err
		}
		if _, err := config.Parse(buf.Bytes()); err != nil {
			return InventoryPlan{}, fmt.Errorf("the inventory does not fit the config: %w", err)
		}
		plan.YAML = buf.Bytes()
		plan.Diff = lineDiff(string(current), string(plan.YAML))
	}
	sum := sha256.Sum256(plan.YAML)
	plan.ID = hex.EncodeToString(sum[:6])
	return plan, nil
}

// applyManaged sets each managed key the inventory has a value for and
// returns what changed.
func applyManaged(node *yaml.Node, p plugin.InventoryProvider) []FieldChange {
	var out []FieldChange
	set := func(key, value, tag string) {
		if value == "" {
			return
		}
		old := scalar(node, key)
		if old == value {
			return
		}
		setOrDelete(node, key, value, tag)
		out = append(out, FieldChange{Field: key, Old: old, New: value})
	}
	if p.ASN != 0 {
		set("asn", strconv.FormatUint(uint64(p.ASN), 10), "!!int")
	}
	set("type", p.Type, "!!str")
	set("source_ip", p.SourceIP, "!!str")
	set("next_hop", p.NextHop, "!!str")
	if len(p.Communities) > 0 {
		old := scalarList(node, "communities")
		if !slices.Equal(old, p.Communities) {
			list := ensureSequence(node, "communities")
			list.Content = nil
			for _, c := range p.Communities {
				list.Content = append(list.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: c, Style: yaml.DoubleQuotedStyle})
			}
			out = append(out, FieldChange{Field: "communities", Old: strings.Join(old, ","), New: strings.Join(p.Communities, ",")})
		}
	}
	return out
}

// Format writes the plan as text for an operator to read before apply.
func (p InventoryPlan) Format(w io.Writer) {
	for _, c := range p.Changes {
		sign := "~"
		if c.Action == "add" {
			sign = "+"
		}
		fmt.Fprintf(w, "%s %s\n", sign, c.Name)
		for _, f := range c.Fields {
			if f.Old == "" {
				fmt.Fprintf(w, "    %s: %s\n", f.Field, f.New)
				continue
			}
			fmt.Fprintf(w, "    %s: %s -> %s\n", f.Field, f.Old, f.New)
		}
	}
	for _, s := range p.Skipped {
		fmt.Fprintf(w, "! %s: skipped: %s\n", s.Name, s.Reason)
	}
	if len(p.Unchanged) > 0 {
		fmt.Fprintf(w, "= no change: %s\n", strings.Join(p.Unchanged, ", "))
	}
	if len(p.NotInInventory) > 0 {
		fmt.Fprintf(w, ". not in the inventory, left as they are: %s\n", strings.Join(p.NotInInventory, ", "))
	}
	if !p.Changed() {
		fmt.Fprintln(w, "plan: the config already matches the inventory")
		return
	}
	fmt.Fprintf(w, "plan id: %s\n", p.ID)
}
