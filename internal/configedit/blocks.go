package configedit

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// Blocks (#330) are the sections of the settings form that the older typed
// sections (#102 to #181) do not cover: the scorer knobs, bgp, BMP, the
// maintenance policy, the inbound announcer, anomaly, mitigation, http, and
// the inject settings. One block is one YAML mapping described by a list of
// Fields. The same description drives reading the file, checking the form,
// merging it back, and rendering it in the browser (GET /api/config/schema),
// so a new key is one Field. A merge touches only the keys whose value
// changed, so every key the form does not know, and every key it knows but
// the operator did not edit, stays byte for byte.

// Kind is the type of a block field.
type Kind string

// Field kinds. A value in Values is a string for string, int, float,
// duration, enum, env, and time; a bool for bool; a []string for list and
// cidrs; a []Values for rows; and a Values (nil when absent) for group.
const (
	KindString   Kind = "string"
	KindInt      Kind = "int"
	KindFloat    Kind = "float"
	KindBool     Kind = "bool"
	KindDuration Kind = "duration"
	KindEnum     Kind = "enum"
	KindList     Kind = "list"
	KindCIDRs    Kind = "cidrs"
	KindEnv      Kind = "env"
	KindTime     Kind = "time"
	KindRows     Kind = "rows"
	KindGroup    Kind = "group"
)

// rowKey is the Values key that carries a row's position in the file when
// the form was loaded. An empty or missing one is a new row.
const rowKey = "_key"

// Limits of a block.
const (
	maxBlockRows   = 256
	maxBlockList   = 256
	maxBlockString = 512
)

// Field describes one key of a block mapping. Key may be a dotted path
// (detector.config.min_mbps) into nested mappings. Min and Max bound an
// int or float; for a duration they are seconds.
type Field struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Help     string   `json:"help"`
	Kind     Kind     `json:"kind"`
	Options  []string `json:"options,omitempty"`
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
	Default  string   `json:"default,omitempty"`
	Check    string   `json:"check,omitempty"`
	Required bool     `json:"required,omitempty"`
	Advanced bool     `json:"advanced,omitempty"`
	// DefaultTrue is a bool the loader reads as true when the key is
	// absent. Writing true then deletes the key.
	DefaultTrue bool `json:"default_true,omitempty"`
	// For names the scorer types a knob belongs to. Another scorer's
	// strict decoder refuses the key, so a switch drops it.
	For []string `json:"for,omitempty"`
	// NoInject refuses to turn an enum to inject from the form when the
	// file is not already there: that is the top-level mode's job, behind
	// the inject checklist and the confirmation.
	NoInject bool `json:"no_inject,omitempty"`
	// RowKey names a field of each row whose value must be unique.
	RowKey string  `json:"row_key,omitempty"`
	Fields []Field `json:"fields,omitempty"`
}

// Values holds the values of one mapping, by Field.Key.
type Values map[string]any

func num(v float64) *float64 { return &v }

// ---- checks ----

// checkers are the named per-item checks a Field may use. The page runs
// the same names before Apply.
var checkers = map[string]func(string) error{
	"ip": func(s string) error {
		if _, err := netip.ParseAddr(s); err != nil {
			return fmt.Errorf("%q is not an IP address", s)
		}
		return nil
	},
	"ipport": func(s string) error {
		host, port, err := splitHostPort(s)
		if err != nil {
			return err
		}
		if host != "" {
			if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil {
				return fmt.Errorf("%q: the host must be an IP address", s)
			}
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%q: the port must be 1 to 65535", s)
		}
		return nil
	},
	"name": func(s string) error {
		if !instanceName.MatchString(s) {
			return fmt.Errorf("%q must be 1 to 64 letters, digits, dot, dash, or underscore", s)
		}
		return nil
	},
	"community": func(s string) error {
		_, err := config.CommunityText(s)
		return err
	},
	"abspath": func(s string) error {
		if !strings.HasPrefix(s, "/") || strings.ContainsAny(s, "\r\n") {
			return fmt.Errorf("%q must be an absolute path", s)
		}
		return nil
	},
}

func splitHostPort(s string) (host, port string, err error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("%q must be host:port", s)
	}
	return s[:i], s[i+1:], nil
}

// ---- reading ----

// readValues reads the fields of mapping m. A nil m reads as an empty
// mapping, so a block that is not in the file shows its defaults.
func readValues(m *yaml.Node, fields []Field) Values {
	v := Values{}
	for _, f := range fields {
		v[f.Key] = readField(m, f)
	}
	return v
}

func readField(m *yaml.Node, f Field) any {
	n := lookupPath(m, f.Key)
	switch f.Kind {
	case KindBool:
		var b bool
		if n == nil || n.Kind != yaml.ScalarNode || n.Decode(&b) != nil {
			return f.DefaultTrue
		}
		return b
	case KindList, KindCIDRs:
		if n != nil && n.Kind == yaml.ScalarNode && n.Tag != "!!null" {
			return []string{n.Value}
		}
		out := []string{}
		if n != nil && n.Kind == yaml.SequenceNode {
			for _, item := range n.Content {
				if item.Kind == yaml.ScalarNode && item.Tag != "!!null" {
					out = append(out, item.Value)
				}
			}
		}
		return out
	case KindRows:
		rows := []Values{}
		if n != nil && n.Kind == yaml.SequenceNode {
			for i, item := range n.Content {
				if item.Kind != yaml.MappingNode {
					continue
				}
				row := readValues(item, f.Fields)
				row[rowKey] = strconv.Itoa(i)
				rows = append(rows, row)
			}
		}
		return rows
	case KindGroup:
		if n == nil || n.Kind != yaml.MappingNode {
			return Values(nil)
		}
		return readValues(n, f.Fields)
	}
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return ""
	}
	return n.Value
}

// lookupPath follows a dotted key through nested mappings.
func lookupPath(m *yaml.Node, key string) *yaml.Node {
	for _, p := range strings.Split(key, ".") {
		n, _ := child(m, p)
		if n == nil {
			return nil
		}
		m = n
	}
	return m
}

// ---- normalizing ----

// normalizeValues turns a decoded request into the canonical shape
// readValues produces, so two values compare with reflect.DeepEqual. Keys
// the fields do not name are dropped; missing keys read as empty.
func normalizeValues(path string, fields []Field, raw Values) (Values, error) {
	out := Values{}
	for _, f := range fields {
		v, err := normalizeField(joinPath(path, f.Key), f, raw[f.Key])
		if err != nil {
			return nil, err
		}
		out[f.Key] = v
	}
	return out, nil
}

func normalizeField(path string, f Field, raw any) (any, error) {
	bad := func() (any, error) {
		return nil, fmt.Errorf("%w: %s: the value has the wrong type", ErrForm, path)
	}
	switch f.Kind {
	case KindBool:
		switch b := raw.(type) {
		case nil:
			return f.DefaultTrue, nil
		case bool:
			return b, nil
		case string:
			return strings.EqualFold(strings.TrimSpace(b), "true"), nil
		}
		return bad()
	case KindList, KindCIDRs:
		switch l := raw.(type) {
		case nil:
			return []string{}, nil
		case []string:
			return trimAll(l), nil
		case []any:
			out := make([]string, 0, len(l))
			for _, item := range l {
				s, ok := item.(string)
				if !ok {
					return bad()
				}
				out = append(out, strings.TrimSpace(s))
			}
			return out, nil
		}
		return bad()
	case KindRows:
		var items []any
		switch l := raw.(type) {
		case nil:
		case []Values:
			for _, r := range l {
				items = append(items, r)
			}
		case []any:
			items = l
		default:
			return bad()
		}
		if len(items) > maxBlockRows {
			return nil, fmt.Errorf("%w: %s: at most %d rows in the form", ErrForm, path, maxBlockRows)
		}
		rows := make([]Values, 0, len(items))
		for i, item := range items {
			rv, ok := asValues(item)
			if !ok {
				return bad()
			}
			row, err := normalizeValues(fmt.Sprintf("%s[%d]", path, i), f.Fields, rv)
			if err != nil {
				return nil, err
			}
			k, _ := rv[rowKey].(string)
			row[rowKey] = strings.TrimSpace(k)
			rows = append(rows, row)
		}
		return rows, nil
	case KindGroup:
		if raw == nil {
			return Values(nil), nil
		}
		rv, ok := asValues(raw)
		if !ok {
			return bad()
		}
		if rv == nil {
			return Values(nil), nil
		}
		return normalizeValues(path, f.Fields, rv)
	}
	switch s := raw.(type) {
	case nil:
		return "", nil
	case string:
		return strings.TrimSpace(s), nil
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64), nil
	case json.Number:
		return s.String(), nil
	}
	return bad()
}

func asValues(raw any) (Values, bool) {
	switch v := raw.(type) {
	case Values:
		return v, true
	case map[string]any:
		return Values(v), true
	}
	return nil, false
}

// ---- checking ----

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func fieldErr(path, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrForm, path, fmt.Sprintf(format, args...))
}

// validateValues checks v, which normalizeValues produced, against fields.
// path is the YAML path the messages start with; the page maps a message
// back to the field whose path it starts with.
func validateValues(path string, fields []Field, v Values) error {
	for _, f := range fields {
		if err := validateField(joinPath(path, f.Key), f, v[f.Key]); err != nil {
			return err
		}
	}
	return nil
}

func validateField(path string, f Field, val any) error {
	switch f.Kind {
	case KindBool:
		return nil
	case KindList, KindCIDRs:
		return validateList(path, f, val.([]string))
	case KindRows:
		return validateRows(path, f, val.([]Values))
	case KindGroup:
		g, _ := val.(Values)
		if g == nil {
			return nil
		}
		return validateValues(path, f.Fields, g)
	}
	s := val.(string)
	if s == "" {
		if f.Required {
			return fieldErr(path, "is required")
		}
		return nil
	}
	if len(s) > maxBlockString || strings.ContainsAny(s, "\r\n") {
		return fieldErr(path, "must be one line of at most %d characters", maxBlockString)
	}
	switch f.Kind {
	case KindInt:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || !within(float64(n), f) {
			return fieldErr(path, "%q must be a whole number%s", s, bounds(f, ""))
		}
	case KindFloat:
		n, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || !within(n, f) {
			return fieldErr(path, "%q must be a number%s", s, bounds(f, ""))
		}
	case KindDuration:
		d, err := time.ParseDuration(s)
		if err != nil || !within(d.Seconds(), f) {
			return fieldErr(path, "%q must be a duration such as 5m%s", s, bounds(f, "s"))
		}
	case KindEnum:
		if !containsStr(f.Options, s) {
			return fieldErr(path, "%q is invalid (want %s)", s, strings.Join(f.Options, ", "))
		}
	case KindEnv:
		if !envVarName.MatchString(s) {
			return fieldErr(path, "%q must be the name of an environment variable, not the secret", s)
		}
	case KindTime:
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return fieldErr(path, "%q must be a date and time (RFC 3339)", s)
		}
	}
	if f.Check != "" {
		if err := checkers[f.Check](s); err != nil {
			return fieldErr(path, "%v", err)
		}
	}
	return nil
}

func within(n float64, f Field) bool {
	return (f.Min == nil || n >= *f.Min) && (f.Max == nil || n <= *f.Max)
}

func bounds(f Field, unit string) string {
	switch {
	case f.Min != nil && f.Max != nil:
		return fmt.Sprintf(" from %v%s to %v%s", *f.Min, unit, *f.Max, unit)
	case f.Min != nil:
		return fmt.Sprintf(" of at least %v%s", *f.Min, unit)
	case f.Max != nil:
		return fmt.Sprintf(" of at most %v%s", *f.Max, unit)
	}
	return ""
}

func containsStr(list []string, s string) bool {
	for _, o := range list {
		if o == s {
			return true
		}
	}
	return false
}

func validateList(path string, f Field, list []string) error {
	if len(list) > maxBlockList {
		return fieldErr(path, "at most %d values", maxBlockList)
	}
	if f.Required && len(list) == 0 {
		return fieldErr(path, "needs at least one value")
	}
	seen := map[string]bool{}
	for i, s := range list {
		at := fmt.Sprintf("%s[%d]", path, i)
		if s == "" || len(s) > maxBlockString || strings.ContainsAny(s, "\r\n") {
			return fieldErr(at, "is empty or too long")
		}
		if seen[s] {
			return fieldErr(at, "duplicate value %s", s)
		}
		seen[s] = true
		if f.Kind == KindCIDRs {
			p, err := netip.ParsePrefix(s)
			if err != nil || p != p.Masked() {
				return fieldErr(at, "%q must be a prefix without host bits, for example 192.0.2.0/24", s)
			}
		}
		if f.Check != "" {
			if err := checkers[f.Check](s); err != nil {
				return fieldErr(at, "%v", err)
			}
		}
	}
	return nil
}

func validateRows(path string, f Field, rows []Values) error {
	seen := map[string]bool{}
	keys := map[string]bool{}
	for i, row := range rows {
		at := fmt.Sprintf("%s[%d]", path, i)
		if err := validateValues(at, f.Fields, row); err != nil {
			return err
		}
		if k := row[rowKey].(string); k != "" {
			if keys[k] {
				return fieldErr(at, "row listed twice")
			}
			keys[k] = true
		}
		if f.RowKey == "" {
			continue
		}
		id, _ := row[f.RowKey].(string)
		if id == "" {
			return fieldErr(joinPath(at, f.RowKey), "is required")
		}
		if seen[id] {
			return fieldErr(joinPath(at, f.RowKey), "duplicate %s", id)
		}
		seen[id] = true
	}
	return nil
}

// ---- merging ----

// syncValues writes next into mapping m. The current values are read from
// m itself, so only a changed field is touched. A field whose value is the
// same as in the file keeps its node, comments, and style.
func syncValues(m *yaml.Node, fields []Field, next Values) error {
	cur := readValues(m, fields)
	for _, f := range fields {
		if reflect.DeepEqual(cur[f.Key], next[f.Key]) {
			continue
		}
		if err := writeField(m, f, next[f.Key]); err != nil {
			return err
		}
	}
	return nil
}

func writeField(m *yaml.Node, f Field, val any) error {
	switch f.Kind {
	case KindBool:
		b := val.(bool)
		switch {
		case b == f.DefaultTrue:
			setPath(m, f.Key, "", "")
		case b:
			setPath(m, f.Key, "true", "!!bool")
		default:
			setPath(m, f.Key, "false", "!!bool")
		}
	case KindList, KindCIDRs:
		setPathList(m, f.Key, val.([]string))
	case KindRows:
		return writeRows(m, f, val.([]Values))
	case KindGroup:
		g, _ := val.(Values)
		if g == nil {
			setPath(m, f.Key, "", "")
			return nil
		}
		parts := strings.Split(f.Key, ".")
		node := m
		for _, p := range parts {
			node = ensureMapping(node, p)
		}
		return syncValues(node, f.Fields, g)
	default:
		setPath(m, f.Key, val.(string), kindTag(f.Kind))
	}
	return nil
}

func kindTag(k Kind) string {
	switch k {
	case KindInt:
		return "!!int"
	case KindFloat:
		return "!!float"
	}
	return "!!str"
}

// setPath sets or, with an empty value, deletes a dotted key. Parent
// mappings are created only to hold a value, and a parent the delete empties
// is removed.
func setPath(m *yaml.Node, key, value, tag string) {
	parts := strings.Split(key, ".")
	if value == "" {
		deletePath(m, parts)
		return
	}
	for _, p := range parts[:len(parts)-1] {
		m = ensureMapping(m, p)
	}
	setOrDelete(m, parts[len(parts)-1], value, tag)
}

func deletePath(m *yaml.Node, parts []string) {
	chain := []*yaml.Node{m}
	for _, p := range parts[:len(parts)-1] {
		n, ok := mappingChild(chain[len(chain)-1], p)
		if !ok {
			return
		}
		chain = append(chain, n)
	}
	deleteKey(chain[len(chain)-1], parts[len(parts)-1])
	for i := len(chain) - 1; i > 0 && len(chain[i].Content) == 0; i-- {
		deleteKey(chain[i-1], parts[i-1])
	}
}

func setPathList(m *yaml.Node, key string, vals []string) {
	parts := strings.Split(key, ".")
	if len(vals) == 0 {
		deletePath(m, parts)
		return
	}
	for _, p := range parts[:len(parts)-1] {
		m = ensureMapping(m, p)
	}
	setStringList(m, parts[len(parts)-1], vals, "!!str")
}

func writeRows(m *yaml.Node, f Field, rows []Values) error {
	parts := strings.Split(f.Key, ".")
	var seq *yaml.Node
	if n := lookupPath(m, f.Key); n != nil && n.Kind == yaml.SequenceNode {
		seq = n
	}
	if len(rows) == 0 {
		deletePath(m, parts)
		return nil
	}
	if seq == nil {
		parent := m
		for _, p := range parts[:len(parts)-1] {
			parent = ensureMapping(parent, p)
		}
		seq = ensureSequence(parent, parts[len(parts)-1])
	}
	next := make([]*yaml.Node, 0, len(rows))
	used := map[int]bool{}
	for _, row := range rows {
		k := row[rowKey].(string)
		var node *yaml.Node
		if k == "" {
			node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		} else {
			i, err := strconv.Atoi(k)
			if err != nil || i < 0 || i >= len(seq.Content) || seq.Content[i].Kind != yaml.MappingNode {
				return fmt.Errorf("%w: %s row %s is not in the file anymore; reload the form", ErrForm, f.Key, k)
			}
			if used[i] {
				return fmt.Errorf("%w: %s row %s is listed twice", ErrForm, f.Key, k)
			}
			used[i] = true
			node = seq.Content[i]
		}
		if err := syncValues(node, f.Fields, row); err != nil {
			return err
		}
		next = append(next, node)
	}
	seq.Content = next
	return nil
}

// ---- block locations ----

// Block is one section of the page built from Fields.
type Block struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Help  string `json:"help"`
	// YAML is the path of the block's mapping, for display and for mapping
	// a loader error back to a field.
	YAML string `json:"yaml"`
	// Optional blocks can be absent from the file; Values is then nil and
	// the page shows a switch.
	Optional bool    `json:"optional,omitempty"`
	Fields   []Field `json:"fields"`

	// path is the mapping chain from the document root. list and typ, when
	// set, locate the first entry of a plugin type in a top-level list and
	// path is then below that entry.
	path []string
	list string
	typ  string
	// check is a cross-field check of the block's values. fix runs after
	// a merge to give the block's parent the keys it cannot load without.
	check func(v Values) error
	fix   func(root *yaml.Node)
}

// locate returns the block's mapping, or nil when it is not in the file.
func (b Block) locate(root *yaml.Node) *yaml.Node {
	m := root
	if b.list != "" {
		entries := typedEntries(root, b.list, b.typ)
		if len(entries) == 0 {
			return nil
		}
		m = entries[0].node
	}
	for _, p := range b.path {
		n, ok := mappingChild(m, p)
		if !ok {
			return nil
		}
		m = n
	}
	return m
}

// create returns the block's mapping, adding it (and its plugin entry) to
// the document when it is not there.
func (b Block) create(root *yaml.Node) *yaml.Node {
	if m := b.locate(root); m != nil {
		return m
	}
	m := root
	if b.list != "" {
		seq := ensureSequence(root, b.list)
		if entries := typedEntries(root, b.list, b.typ); len(entries) > 0 {
			m = entries[0].node
		} else {
			m = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			setOrDelete(m, "type", b.typ, "!!str")
			seq.Content = append(seq.Content, m)
		}
	}
	for _, p := range b.path {
		m = ensureMapping(m, p)
	}
	return m
}

// remove deletes the block from the document. A plugin entry goes with its
// config, and an emptied list goes too.
func (b Block) remove(root *yaml.Node) {
	if b.list != "" {
		seq, ok := sequenceChild(root, b.list)
		if !ok {
			return
		}
		entries := typedEntries(root, b.list, b.typ)
		if len(entries) == 0 {
			return
		}
		for i, item := range seq.Content {
			if item == entries[0].node {
				seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
				break
			}
		}
		if len(seq.Content) == 0 {
			deleteKey(root, b.list)
		}
		return
	}
	deletePath(root, b.path)
}

// prune removes the block's mapping chain when a merge left it empty. An
// optional block stays as the operator left it, and a plugin entry keeps
// its type.
func (b Block) prune(root *yaml.Node) {
	if b.Optional || b.list != "" || len(b.path) == 0 {
		return
	}
	if m := b.locate(root); m != nil && len(m.Content) == 0 {
		deletePath(root, b.path)
	}
}

func (b Block) read(root *yaml.Node) Values {
	m := b.locate(root)
	if m == nil && b.Optional && !(b.list != "" && len(typedEntries(root, b.list, b.typ)) > 0) {
		return nil
	}
	return readValues(m, b.Fields)
}

func (b Block) apply(root *yaml.Node, next Values) error {
	if next == nil {
		b.remove(root)
		return nil
	}
	m := b.locate(root)
	if m == nil {
		if reflect.DeepEqual(readValues(nil, b.Fields), next) && !b.Optional {
			return nil
		}
		m = b.create(root)
	}
	if err := syncValues(m, b.Fields, next); err != nil {
		return err
	}
	b.prune(root)
	if b.fix != nil {
		b.fix(root)
	}
	return nil
}
