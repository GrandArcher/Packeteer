package configedit

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// wizardOwned are the top-level keys the wizard writes. Every other key in
// an existing file (auth, http, storage, and blocks the wizard does not
// know) is kept as it is.
var wizardOwned = []string{
	"mode", "asn", "router_id", "packeteer_community", "max_improvements", "hold_time",
	"thresholds", "providers", "allowlist", "bgp", "sources", "scorer",
}

// WizardPlan is what the wizard would put in the editor.
type WizardPlan struct {
	YAML string `json:"yaml"`
	// Existing is true when the wizard ran over a config that was already
	// there; Diff and Removes then describe what changes.
	Existing bool `json:"existing"`
	// Diff is a line diff of the current text to YAML. It is ASCII only.
	Diff string `json:"diff,omitempty"`
	// Removes names what the operator loses, for the confirm step.
	Removes []string `json:"removes,omitempty"`
}

// WizardOver renders the wizard config over current, the text now in the
// editor. With no current text it is Wizard. Otherwise the wizard keys are
// replaced and everything else is kept, auth included: sign-in stays on
// unless in.DisableAuth is set. The result must parse and still be
// observe. Nothing is written.
func WizardOver(in WizardInput, current []byte) (WizardPlan, error) {
	fresh, err := Wizard(in)
	if err != nil {
		return WizardPlan{}, err
	}
	if len(bytes.TrimSpace(current)) == 0 {
		return WizardPlan{YAML: string(fresh)}, nil
	}
	root, err := mappingRoot(current)
	if err != nil {
		return WizardPlan{}, fmt.Errorf("the current config cannot be kept (%v); fix it or clear the editor first", err)
	}
	gen, err := mappingRoot(fresh)
	if err != nil {
		return WizardPlan{}, err
	}
	removes := wizardRemoves(root, gen)
	auth, _ := mappingChild(root, "auth")
	authWas := authOn(auth)
	for _, key := range wizardOwned {
		if n, _ := child(gen, key); n != nil {
			setChild(root, key, n)
		} else {
			deleteKey(root, key)
		}
	}
	if st, _ := child(gen, "storage"); st != nil {
		if _, i := child(root, "storage"); i < 0 {
			setChild(root, "storage", st)
		}
	}
	genHTTP, _ := child(gen, "http")
	if _, i := child(root, "http"); i < 0 {
		setChild(root, "http", genHTTP)
	} else if in.HTTPListen != "" {
		setOrDelete(ensureMapping(root, "http"), "listen", scalar(genHTTP, "listen"), "!!str")
	}
	if a, _ := mappingChild(root, "auth"); in.DisableAuth && authOn(a) {
		setOrDelete(ensureMapping(root, "auth"), "enabled", "false", "!!bool")
		removes = append(removes, "Turns off sign-in")
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return WizardPlan{}, err
	}
	if err := enc.Close(); err != nil {
		return WizardPlan{}, err
	}
	cfg, err := config.Parse(buf.Bytes())
	if err != nil {
		return WizardPlan{}, fmt.Errorf("the setup does not fit the rest of the current config: %w", err)
	}
	if cfg.Mode != config.ModeObserve || len(cfg.Allowlist.Prefixes) != 0 {
		return WizardPlan{}, errors.New("wizard: generated config is not observe")
	}
	if authWas && cfg.AuthOptedOut() && !in.DisableAuth {
		return WizardPlan{}, errors.New("wizard: generated config would turn sign-in off")
	}
	return WizardPlan{YAML: buf.String(), Existing: true, Diff: lineDiff(string(current), buf.String()), Removes: removes}, nil
}

// authOn reads auth.enabled as config does: a missing auth block or an
// unset or null enabled is on (DefaultAuth, #328). A value that is not a
// bool counts as on so the wizard never reports sign-in off by mistake.
func authOn(a *yaml.Node) bool {
	n, _ := child(a, "enabled")
	if n == nil || n.Tag == "!!null" {
		return true
	}
	var on bool
	if err := n.Decode(&on); err != nil {
		return true
	}
	return on
}

// setChild puts val under key, in the key's place when it is there and at
// the end otherwise.
func setChild(m *yaml.Node, key string, val *yaml.Node) {
	if _, i := child(m, key); i >= 0 {
		m.Content[i+1] = val
		return
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
}

// wizardRemoves lists what replacing cur with gen drops. Names come from
// the file, so they are shown ASCII only.
func wizardRemoves(cur, gen *yaml.Node) []string {
	var out []string
	if cm, nm := scalar(cur, "mode"), scalar(gen, "mode"); cm != "" && cm != nm {
		out = append(out, fmt.Sprintf("Changes mode from %s to %s", asciiOnly(cm), nm))
	}
	lost := func(n int, noun string, names []string) {
		if n == 0 {
			return
		}
		s := fmt.Sprintf("Removes %d %s", n, noun)
		if n != 1 {
			s += "s"
		}
		if len(names) > 0 {
			s += " (" + asciiOnly(strings.Join(names, ", ")) + ")"
		}
		out = append(out, s)
	}
	names, n := missing(seqScalars(cur, "providers", "name"), seqScalars(gen, "providers", "name"))
	lost(n, "provider", names)
	addrs, n := missing(neighborAddrs(cur), neighborAddrs(gen))
	lost(n, "BGP neighbor", addrs)
	_, n = missing(sourceTypeNames(cur), sourceTypeNames(gen))
	lost(n, "source", nil)
	targets, n := missing(staticTargets(cur), staticTargets(gen))
	lost(n, "static target", targets)
	for _, d := range droppedFields(cur, gen) {
		out = append(out, "Resets "+d)
	}
	curAllow, _ := mappingChild(cur, "allowlist")
	prefixes, n := missing(scalarList(curAllow, "prefixes"), nil)
	lost(n, "allowlist prefix", prefixes)
	if ct, nt := scorerType(cur), scorerType(gen); ct != "" && ct != nt {
		out = append(out, fmt.Sprintf("Changes scorer from %s to %s", asciiOnly(ct), nt))
	}
	return out
}

// missing counts the entries of old that new does not have, one for one.
func missing(old, next []string) ([]string, int) {
	left := map[string]int{}
	for _, s := range next {
		left[s]++
	}
	var gone []string
	for _, s := range old {
		if left[s] > 0 {
			left[s]--
			continue
		}
		gone = append(gone, s)
	}
	return gone, len(gone)
}

func seqScalars(m *yaml.Node, seq, field string) []string {
	s, ok := sequenceChild(m, seq)
	if !ok {
		return nil
	}
	var out []string
	for _, it := range s.Content {
		out = append(out, scalar(it, field))
	}
	return out
}

func neighborAddrs(root *yaml.Node) []string {
	bgp, _ := mappingChild(root, "bgp")
	return seqScalars(bgp, "neighbors", "address")
}

// staticTargets are the prefixes of every static source.
func staticTargets(root *yaml.Node) []string {
	srcs, ok := sequenceChild(root, "sources")
	if !ok {
		return nil
	}
	var out []string
	for _, src := range srcs.Content {
		if scalar(src, "type") != "static" {
			continue
		}
		cfg, _ := mappingChild(src, "config")
		if ts, ok := sequenceChild(cfg, "targets"); ok {
			for _, t := range ts.Content {
				out = append(out, scalar(t, "prefix"))
			}
		}
	}
	return out
}

// droppedFields names the settings that replacing cur with gen drops from
// an entry that stays: a provider with the same name, a neighbor with the
// same address, or the bgp block itself. The counts in the other lines do
// not show these.
func droppedFields(cur, gen *yaml.Node) []string {
	var out []string
	entry := func(noun, id string, c, g *yaml.Node) {
		if keys := missingKeys(c, g, ""); len(keys) > 0 {
			out = append(out, fmt.Sprintf("%s %s: drops %s", noun, asciiOnly(id), asciiOnly(strings.Join(keys, ", "))))
		}
	}
	byID := func(root *yaml.Node, seq, field string) map[string]*yaml.Node {
		m := map[string]*yaml.Node{}
		if s, ok := sequenceChild(root, seq); ok {
			for _, it := range s.Content {
				m[scalar(it, field)] = it
			}
		}
		return m
	}
	genProv := byID(gen, "providers", "name")
	if s, ok := sequenceChild(cur, "providers"); ok {
		for _, it := range s.Content {
			if g := genProv[scalar(it, "name")]; g != nil {
				entry("provider", scalar(it, "name"), it, g)
			}
		}
	}
	curBGP, _ := mappingChild(cur, "bgp")
	genBGP, _ := mappingChild(gen, "bgp")
	genNb := byID(genBGP, "neighbors", "address")
	if s, ok := sequenceChild(curBGP, "neighbors"); ok {
		for _, it := range s.Content {
			if g := genNb[scalar(it, "address")]; g != nil {
				entry("BGP neighbor", scalar(it, "address"), it, g)
			}
		}
	}
	if keys := missingKeys(curBGP, genBGP, "neighbors"); len(keys) > 0 {
		out = append(out, "bgp: drops "+asciiOnly(strings.Join(keys, ", ")))
	}
	return out
}

// missingKeys are the keys of mapping c, except skip, that mapping g does
// not have.
func missingKeys(c, g *yaml.Node, skip string) []string {
	if c == nil || c.Kind != yaml.MappingNode {
		return nil
	}
	var out []string
	for i := 0; i+1 < len(c.Content); i += 2 {
		if k := c.Content[i].Value; k != skip {
			if n, _ := child(g, k); n == nil {
				out = append(out, k)
			}
		}
	}
	return out
}

func sourceTypeNames(root *yaml.Node) []string { return seqScalars(root, "sources", "type") }

// asciiOnly keeps the editor diff and the confirm text ASCII: anything
// else in a file is shown as a \u escape.
func asciiOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteString(`\t`)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	return b.String()
}

// maxDiffCells bounds the line diff. A bigger pair of files is shown as
// all removed and all added.
const maxDiffCells = 4_000_000

// diffContext is the number of unchanged lines shown around a change.
const diffContext = 2

// lineDiff is a line diff of a to b: "- " removed, "+ " added, "  "
// kept, with "..." between far apart changes. Equal text gives "".
func lineDiff(a, b string) string {
	if a == b {
		return ""
	}
	x, y := splitLines(a), splitLines(b)
	pre := 0
	for pre < len(x) && pre < len(y) && x[pre] == y[pre] {
		pre++
	}
	suf := 0
	for suf < len(x)-pre && suf < len(y)-pre && x[len(x)-1-suf] == y[len(y)-1-suf] {
		suf++
	}
	mx, my := x[pre:len(x)-suf], y[pre:len(y)-suf]
	ops := make([]string, 0, len(x)+len(y))
	for _, l := range x[:pre] {
		ops = append(ops, "  "+l)
	}
	ops = append(ops, middleDiff(mx, my)...)
	for _, l := range x[len(x)-suf:] {
		ops = append(ops, "  "+l)
	}
	return trimContext(ops)
}

func middleDiff(x, y []string) []string {
	var ops []string
	if len(x)*len(y) > maxDiffCells {
		for _, l := range x {
			ops = append(ops, "- "+l)
		}
		for _, l := range y {
			ops = append(ops, "+ "+l)
		}
		return ops
	}
	// lcs[i][j] is the longest common run of x[i:] and y[j:].
	lcs := make([][]int, len(x)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < len(x) && j < len(y) {
		switch {
		case x[i] == y[j]:
			ops = append(ops, "  "+x[i])
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, "- "+x[i])
			i++
		default:
			ops = append(ops, "+ "+y[j])
			j++
		}
	}
	for ; i < len(x); i++ {
		ops = append(ops, "- "+x[i])
	}
	for ; j < len(y); j++ {
		ops = append(ops, "+ "+y[j])
	}
	return ops
}

// trimContext drops kept lines farther than diffContext from a change.
func trimContext(ops []string) string {
	near := make([]bool, len(ops))
	for i, l := range ops {
		if l[0] == ' ' {
			continue
		}
		for k := max(0, i-diffContext); k <= min(len(ops)-1, i+diffContext); k++ {
			near[k] = true
		}
	}
	var out []string
	skipped := false
	for i, l := range ops {
		if !near[i] {
			skipped = true
			continue
		}
		if skipped && len(out) > 0 {
			out = append(out, "...")
		}
		skipped = false
		out = append(out, l)
	}
	return strings.Join(out, "\n") + "\n"
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = asciiOnly(l)
	}
	return lines
}
