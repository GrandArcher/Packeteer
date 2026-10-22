package configedit

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// Limits of the guided inject step (#221): a small allowlist and a small cap,
// so the first injection touches only a few prefixes.
const (
	MaxInjectAllowlist     = 10
	DefaultInjectCap       = 5
	MaxInjectCap           = 50
	DefaultInjectLocalPref = 250
)

// InjectInput is the guided first-run step that offers injection once the
// preflight checks pass.
type InjectInput struct {
	Allowlist       []string `json:"allowlist"`
	MaxImprovements int      `json:"max_improvements,omitempty"`
}

// InjectPlan is what the step would put in the editor. Nothing is written:
// the operator reviews the YAML and saves it like any other edit, which asks
// for the inject confirmation.
type InjectPlan struct {
	YAML string `json:"yaml"`
	Diff string `json:"diff"`
	// Explain says in plain words what turning inject on changes.
	Explain []string `json:"explain"`
}

// EnableInject turns an observe or suggest config into an inject config for
// a small allowlist. It changes mode, allowlist.prefixes, and
// max_improvements, adds local_pref when it is missing, and keeps every
// other key. The config must already name an announcer: the withdrawal
// preflight check refuses without one. The result must pass config.Parse, which holds
// the inject checklist.
func EnableInject(in InjectInput, current []byte) (InjectPlan, error) {
	prefixes, err := injectPrefixes(in.Allowlist)
	if err != nil {
		return InjectPlan{}, err
	}
	max := in.MaxImprovements
	if max == 0 {
		max = DefaultInjectCap
	}
	if max < 1 || max > MaxInjectCap {
		return InjectPlan{}, fmt.Errorf("max_improvements must be 1 to %d for a first injection", MaxInjectCap)
	}
	was, err := config.Parse(current)
	if err != nil {
		return InjectPlan{}, fmt.Errorf("the current config does not load: %w", err)
	}
	if was.Mode == config.ModeInject {
		return InjectPlan{}, errors.New("the config is already in inject mode")
	}
	root, err := mappingRoot(current)
	if err != nil {
		return InjectPlan{}, err
	}
	setOrDelete(root, "mode", config.ModeInject, "!!str")
	setOrDelete(root, "max_improvements", strconv.Itoa(max), "!!int")
	allow := ensureMapping(root, "allowlist")
	deleteKey(allow, "prefixes")
	list := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, p := range prefixes {
		list.Content = append(list.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p})
	}
	allow.Content = append(allow.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "prefixes"}, list)
	var added []string
	if scalar(root, "local_pref") == "" {
		setOrDelete(root, "local_pref", strconv.Itoa(DefaultInjectLocalPref), "!!int")
		added = append(added, fmt.Sprintf("local_pref %d is added. Routes Packeteer announces win over your transits' own routes only if this is higher than their local preference (often 100); change it if yours differs.", DefaultInjectLocalPref))
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return InjectPlan{}, err
	}
	if err := enc.Close(); err != nil {
		return InjectPlan{}, err
	}
	next, err := config.Parse(buf.Bytes())
	if err != nil {
		return InjectPlan{}, fmt.Errorf("the config is not ready for inject: %w", err)
	}
	explain := []string{
		fmt.Sprintf("mode changes from %s to inject. Packeteer starts announcing routes to your router over the iBGP session.", was.Mode),
		"Only these prefixes may be announced: " + strings.Join(prefixes, ", ") + ". A prefix is announced only when your router currently advertises that exact prefix to Packeteer.",
		fmt.Sprintf("At most %d routes are announced at once (max_improvements).", max),
		fmt.Sprintf("Every route carries %s and NO_EXPORT, so the filters you confirmed keep it inside your AS.", next.PacketeerCommunity),
		"Routes are withdrawn when Packeteer stops, when the session drops, and when the data goes stale.",
	}
	return InjectPlan{YAML: buf.String(), Diff: lineDiff(string(current), buf.String()), Explain: append(explain, added...)}, nil
}

func injectPrefixes(in []string) ([]string, error) {
	var out []string
	seen := map[netip.Prefix]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("allowlist: %q is not a prefix such as 198.51.100.0/24", s)
		}
		p = p.Masked()
		if p.Bits() == 0 {
			return nil, fmt.Errorf("allowlist: %s covers everything; list the prefixes you want to steer", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p.String())
		}
	}
	if len(out) == 0 {
		return nil, errors.New("allowlist: list at least one prefix to start with")
	}
	if len(out) > MaxInjectAllowlist {
		return nil, fmt.Errorf("allowlist: start with at most %d prefixes; add more later in the settings form", MaxInjectAllowlist)
	}
	return out, nil
}
