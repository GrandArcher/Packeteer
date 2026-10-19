package configedit

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The plugins section (#330) lists the plugin entries that have no card of
// their own: probers, notifiers, the other sources, other telemetry, other
// policies, and storage. Each shows its type, its name, and the scalar keys
// of its config. An entry is on while it is in the file; switching it off
// removes it on Save, and the preview shows what goes. A key the form does
// not know stays as it is: a nested value is listed but never rewritten, and
// a key that looks like a secret is listed by name only. Its value is never
// read into the form, never written from it, and a new key of that kind
// must name an environment variable (a *_env key), like every plugin does.

// MaxFormPlugins bounds the plugin rows of the form.
const (
	MaxFormPlugins  = 128
	MaxPluginFields = 64
)

// FormPlugin is one plugin entry. List is the config key (probers, sources,
// notifiers, telemetry, policies, or storage). Key is the entry's index in
// the file when the form was loaded; empty means a new entry. Type cannot
// change on an existing entry.
type FormPlugin struct {
	List     string        `json:"list"`
	Key      string        `json:"key"`
	Type     string        `json:"type"`
	Name     string        `json:"name"`
	Enabled  bool          `json:"enabled"`
	Settings []FormSetting `json:"settings"`
}

// Setting kinds. hidden and nested are read-only markers.
const (
	settingString = "string"
	settingInt    = "int"
	settingFloat  = "float"
	settingBool   = "bool"
	settingHidden = "hidden"
	settingNested = "nested"
)

// FormSetting is one key of a plugin's config. Kind is empty on a new key
// and inferred from Value when it is written.
type FormSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Kind  string `json:"kind"`
}

// pluginLists are the lists the section edits, and the types in each that
// another card owns.
var pluginLists = []struct {
	key  string
	skip []string
}{
	{"probers", nil},
	{"sources", []string{"flow", "vip", "outage", "static"}},
	{"notifiers", nil},
	{"telemetry", []string{"snmp"}},
	{"policies", []string{"rules", "maintenance"}},
}

// PluginLists names the lists, for the page's add-a-plugin picker.
func PluginLists() []string {
	out := []string{}
	for _, l := range pluginLists {
		out = append(out, l.key)
	}
	return append(out, "storage")
}

// PluginTypes is what the add-a-plugin picker offers per list: the registered
// types, less the ones another card owns and exec, which is added in the raw
// YAML.
func PluginTypes() map[string][]string {
	registered := map[string][]string{
		"probers":   plugin.Probers.Types(),
		"sources":   plugin.Sources.Types(),
		"notifiers": plugin.Notifiers.Types(),
		"telemetry": plugin.Telemetries.Types(),
		"policies":  plugin.Policies.Types(),
		"storage":   plugin.Storages.Types(),
	}
	out := map[string][]string{}
	for list, types := range registered {
		out[list] = []string{}
		for _, t := range types {
			if t != "exec" && !ownedElsewhere(list, t) {
				out[list] = append(out[list], t)
			}
		}
	}
	return out
}

// ownedElsewhere is true for a type that another card of the settings page
// edits, so a plugin entry of that type would be invisible to the card.
func ownedElsewhere(list, typ string) bool {
	for _, l := range pluginLists {
		if l.key == list {
			return slices.Contains(l.skip, typ)
		}
	}
	return false
}

var (
	settingKey  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	pluginType  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	secretName  = regexp.MustCompile(`(?i)(secret|passw|passphrase|token|community|api_?key|private_?key|credential)`)
	urlName     = regexp.MustCompile(`(?i)(^|_)(url|uri|dsn)$`)
	boolLiteral = regexp.MustCompile(`^(true|false)$`)
	intLiteral  = regexp.MustCompile(`^-?[0-9]+$`)
)

// isSecretKey is true for a key that holds, or may hold, a secret: a name
// that says so, or a URL that does not take its value from ${VAR}. The page
// lists such a key by name and never shows or writes its value.
func isSecretKey(k, v string) bool {
	if strings.HasSuffix(k, "_env") {
		return false
	}
	return secretName.MatchString(k) || (urlName.MatchString(k) && !strings.Contains(v, "${"))
}

type pluginRef struct {
	list string
	node *yaml.Node
}

// pluginRefs maps "list/key" to the file's entries, before anything is
// merged, so a section that moves entries cannot change what a key means.
func pluginRefs(root *yaml.Node) map[string]pluginRef {
	refs := map[string]pluginRef{}
	for _, l := range pluginLists {
		seq, ok := sequenceChild(root, l.key)
		if !ok {
			continue
		}
		for i, item := range seq.Content {
			if item.Kind == yaml.MappingNode && !slices.Contains(l.skip, scalar(item, "type")) {
				refs[l.key+"/"+strconv.Itoa(i)] = pluginRef{l.key, item}
			}
		}
	}
	if n, ok := mappingChild(root, "storage"); ok && scalar(n, "type") != "" {
		refs["storage/0"] = pluginRef{"storage", n}
	}
	return refs
}

func readPlugins(root *yaml.Node, f *Form) {
	f.Plugins = []FormPlugin{}
	for _, l := range pluginLists {
		seq, ok := sequenceChild(root, l.key)
		if !ok {
			continue
		}
		for i, item := range seq.Content {
			if item.Kind == yaml.MappingNode && !slices.Contains(l.skip, scalar(item, "type")) {
				f.Plugins = append(f.Plugins, readPlugin(l.key, strconv.Itoa(i), item))
			}
		}
	}
	if n, ok := mappingChild(root, "storage"); ok && scalar(n, "type") != "" {
		f.Plugins = append(f.Plugins, readPlugin("storage", "0", n))
	}
}

func readPlugin(list, key string, node *yaml.Node) FormPlugin {
	p := FormPlugin{List: list, Key: key, Type: scalar(node, "type"), Name: scalar(node, "name"), Enabled: true, Settings: []FormSetting{}}
	cfg, ok := mappingChild(node, "config")
	if !ok {
		return p
	}
	for i := 0; i+1 < len(cfg.Content); i += 2 {
		k, v := cfg.Content[i].Value, cfg.Content[i+1]
		s := FormSetting{Key: k}
		switch {
		case v.Kind != yaml.ScalarNode:
			s.Kind = settingNested
		case isSecretKey(k, v.Value):
			s.Kind = settingHidden
		default:
			s.Value = v.Value
			switch v.Tag {
			case "!!int":
				s.Kind = settingInt
			case "!!float":
				s.Kind = settingFloat
			case "!!bool":
				s.Kind = settingBool
			case "!!null":
				s.Value = ""
				s.Kind = settingString
			default:
				s.Kind = settingString
			}
		}
		p.Settings = append(p.Settings, s)
	}
	return p
}

func (f *Form) normalizePlugins() {
	for i := range f.Plugins {
		p := &f.Plugins[i]
		for _, s := range []*string{&p.List, &p.Key, &p.Type, &p.Name} {
			*s = strings.TrimSpace(*s)
		}
		if p.Settings == nil {
			p.Settings = []FormSetting{}
		}
		for j := range p.Settings {
			s := &p.Settings[j]
			s.Key, s.Value, s.Kind = strings.TrimSpace(s.Key), strings.TrimSpace(s.Value), strings.TrimSpace(s.Kind)
		}
	}
}

func (f Form) validatePlugins(cur Form) error {
	if len(f.Plugins) > MaxFormPlugins {
		return fmt.Errorf("%w: at most %d plugins in the form", ErrForm, MaxFormPlugins)
	}
	old := map[string]FormPlugin{}
	for _, p := range cur.Plugins {
		old[p.List+"/"+p.Key] = p
	}
	storage := 0
	seen := map[string]bool{}
	for i, p := range f.Plugins {
		at := fmt.Sprintf("plugins[%d]", i)
		if !slices.Contains(PluginLists(), p.List) {
			return fmt.Errorf("%w: %s.list: %q is not a plugin list", ErrForm, at, p.List)
		}
		if p.List == "storage" && p.Enabled {
			if storage++; storage > 1 {
				return fmt.Errorf("%w: %s: storage takes one plugin", ErrForm, at)
			}
		}
		if p.Name != "" && !instanceName.MatchString(p.Name) {
			return fmt.Errorf("%w: %s.name: %q must be 1 to 64 letters, digits, dot, dash, or underscore", ErrForm, at, p.Name)
		}
		if !pluginType.MatchString(p.Type) {
			return fmt.Errorf("%w: %s.type: %q must be a plugin type such as webhook", ErrForm, at, p.Type)
		}
		if p.Key != "" {
			o, ok := old[p.List+"/"+p.Key]
			if !ok {
				return fmt.Errorf("%w: %s: the plugin is not in the file anymore; reload the form", ErrForm, at)
			}
			if o.Type != p.Type {
				return fmt.Errorf("%w: %s.type: the type of %s cannot change; remove it and add another", ErrForm, at, o.Type)
			}
			if o.Type == "exec" && !reflect.DeepEqual(o, p) {
				return fmt.Errorf("%w: %s: an exec plugin runs a program; edit it in the raw YAML", ErrForm, at)
			}
			if seen[p.List+"/"+p.Key] {
				return fmt.Errorf("%w: %s: listed twice", ErrForm, at)
			}
			seen[p.List+"/"+p.Key] = true
		} else if p.Type == "exec" && p.Enabled {
			return fmt.Errorf("%w: %s.type: an exec plugin runs a program; add it in the raw YAML", ErrForm, at)
		} else if ownedElsewhere(p.List, p.Type) {
			return fmt.Errorf("%w: %s.type: %s is edited in its own section; add it there", ErrForm, at, p.Type)
		}
		if err := validateSettings(at, p); err != nil {
			return err
		}
	}
	// applyPlugins removes every file entry the form leaves out, so an exec
	// entry missing from the request would be deleted, not kept read-only.
	for _, o := range cur.Plugins {
		if o.Type == "exec" && !seen[o.List+"/"+o.Key] {
			return fmt.Errorf("%w: plugins: the exec plugin %s %s is missing; an exec plugin runs a program, remove it in the raw YAML", ErrForm, o.List, o.Key)
		}
	}
	return nil
}

func validateSettings(at string, p FormPlugin) error {
	if len(p.Settings) > MaxPluginFields {
		return fmt.Errorf("%w: %s: at most %d settings", ErrForm, at, MaxPluginFields)
	}
	seen := map[string]bool{}
	for j, s := range p.Settings {
		sat := fmt.Sprintf("%s.settings[%d]", at, j)
		if !settingKey.MatchString(s.Key) {
			return fmt.Errorf("%w: %s.key: %q must be lowercase letters, digits, and underscores", ErrForm, sat, s.Key)
		}
		if seen[s.Key] {
			return fmt.Errorf("%w: %s.key: duplicate %s", ErrForm, sat, s.Key)
		}
		seen[s.Key] = true
		if s.Kind == settingHidden || s.Kind == settingNested {
			continue
		}
		if len(s.Value) > maxBlockString || strings.ContainsAny(s.Value, "\r\n") {
			return fmt.Errorf("%w: %s.value: one line of at most %d characters", ErrForm, sat, maxBlockString)
		}
		if s.Value != "" && isSecretKey(s.Key, s.Value) {
			// Only a URL key may take its value from ${VAR}; isSecretKey
			// refuses that for any other secret-looking name.
			ref := ""
			if urlName.MatchString(s.Key) {
				ref = "take the value from a ${VAR} reference, or "
			}
			return fmt.Errorf("%w: %s.key: %s may hold a secret. Secrets stay in environment variables: %suse a %s_env key with the variable's name", ErrForm, sat, s.Key, ref, s.Key)
		}
		switch settingKind(s) {
		case settingInt:
			if _, err := strconv.ParseInt(s.Value, 10, 64); err != nil {
				return fmt.Errorf("%w: %s.value: %q must be a whole number", ErrForm, sat, s.Value)
			}
		case settingFloat:
			if _, err := strconv.ParseFloat(s.Value, 64); err != nil {
				return fmt.Errorf("%w: %s.value: %q must be a number", ErrForm, sat, s.Value)
			}
		case settingBool:
			if !boolLiteral.MatchString(s.Value) {
				return fmt.Errorf("%w: %s.value: %q must be true or false", ErrForm, sat, s.Value)
			}
		}
	}
	return nil
}

// settingKind is the kind a value is written as. A new key has none, so it
// is read from the value: a whole number, a number, true or false, else text.
func settingKind(s FormSetting) string {
	if s.Kind != "" {
		return s.Kind
	}
	switch {
	case boolLiteral.MatchString(s.Value):
		return settingBool
	case intLiteral.MatchString(s.Value):
		return settingInt
	}
	if _, err := strconv.ParseFloat(s.Value, 64); err == nil && !strings.ContainsAny(s.Value, "xXnNiI_") {
		return settingFloat
	}
	return settingString
}

func settingTag(kind string) string {
	switch kind {
	case settingInt:
		return "!!int"
	case settingFloat:
		return "!!float"
	case settingBool:
		return "!!bool"
	}
	return "!!str"
}

func applyPlugins(root *yaml.Node, refs map[string]pluginRef, cur, next Form) error {
	if reflect.DeepEqual(cur.Plugins, next.Plugins) {
		return nil
	}
	kept := map[string]bool{}
	for _, p := range next.Plugins {
		switch {
		case p.Key == "" && p.Enabled:
			addPlugin(root, p)
		case p.Key == "":
		case !p.Enabled:
			// Removed below with every entry the form no longer lists.
		default:
			ref, ok := refs[p.List+"/"+p.Key]
			if !ok {
				return fmt.Errorf("%w: plugin %s %s is not in the file anymore; reload the form", ErrForm, p.List, p.Key)
			}
			kept[p.List+"/"+p.Key] = true
			if !reflect.DeepEqual(readPlugin(p.List, p.Key, ref.node), p) {
				writePlugin(ref.node, p)
			}
		}
	}
	for key, ref := range refs {
		if !kept[key] {
			removePlugin(root, ref)
		}
	}
	return nil
}

func addPlugin(root *yaml.Node, p FormPlugin) {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	setOrDelete(node, "type", p.Type, "!!str")
	writePlugin(node, p)
	if p.List == "storage" {
		deleteKey(root, "storage")
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "storage"}, node)
		return
	}
	seq := ensureSequence(root, p.List)
	seq.Content = append(seq.Content, node)
}

// writePlugin sets the name and the scalar settings of an entry. A scalar key
// the form no longer lists is deleted; a nested or hidden one is untouched.
func writePlugin(node *yaml.Node, p FormPlugin) {
	setOrDelete(node, "name", p.Name, "!!str")
	listed := map[string]bool{}
	for _, s := range p.Settings {
		listed[s.Key] = true
	}
	if cfg, ok := mappingChild(node, "config"); ok {
		for i := len(cfg.Content) - 2; i >= 0; i -= 2 {
			k, v := cfg.Content[i].Value, cfg.Content[i+1]
			if !listed[k] && v.Kind == yaml.ScalarNode && !isSecretKey(k, v.Value) {
				deleteKey(cfg, k)
			}
		}
	}
	for _, s := range p.Settings {
		if s.Kind == settingHidden || s.Kind == settingNested {
			continue
		}
		if s.Value == "" {
			if cfg, ok := mappingChild(node, "config"); ok {
				deleteKey(cfg, s.Key)
			}
			continue
		}
		setOrDelete(ensureMapping(node, "config"), s.Key, s.Value, settingTag(settingKind(s)))
	}
	trimConfig(node)
}

func removePlugin(root *yaml.Node, ref pluginRef) {
	if ref.list == "storage" {
		deleteKey(root, "storage")
		return
	}
	seq, ok := sequenceChild(root, ref.list)
	if !ok {
		return
	}
	seq.Content = slices.DeleteFunc(seq.Content, func(n *yaml.Node) bool { return n == ref.node })
	if len(seq.Content) == 0 {
		deleteKey(root, ref.list)
	}
}
