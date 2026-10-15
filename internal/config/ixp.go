package config

import (
	"errors"

	"gopkg.in/yaml.v3"
)

// IXP is exchange-operator mode (#160). A non-nil value, including an
// empty block, is IXP mode. IXP mode never announces. The only key is
// members (#161), a read-only IX-F import. Any other key is a parse error.
type IXP struct {
	Members *PluginSpec `yaml:"members,omitempty"`
}

// ixpForbidsSynthesize rejects a synthesize key when an ixp block is
// present. synthesize is not a field (#122); without this check the
// decode would only say the field is unknown, and an ixp file would
// not name the charter.
func ixpForbidsSynthesize(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	m := doc.Content[0]
	if m.Kind != yaml.MappingNode {
		return nil
	}
	var ixp, synth bool
	for i := 0; i+1 < len(m.Content); i += 2 {
		val := m.Content[i+1]
		switch m.Content[i].Value {
		case "ixp":
			if val.Tag != "!!null" {
				ixp = true
			}
		case "synthesize":
			synth = true
		}
	}
	if ixp && synth {
		return errors.New("ixp forbids synthesize: IXP mode never announces")
	}
	return nil
}

// validateIXP refuses every config that can announce or steer while the
// ixp block is set. Observe and suggest stay valid: neither announces.
// Neighbors are not required, so no RIB view is built when they are absent.
func (c *Config) validateIXP(add func(string, ...any)) {
	if c.IXP == nil {
		return
	}
	if c.Mode == ModeInject {
		add("ixp forbids mode inject: IXP mode is observe-only and never announces")
	}
	if c.Announcer != nil {
		add("ixp forbids announcer: IXP mode never announces")
	}
	if c.Mitigation != nil {
		add("ixp forbids mitigation: IXP mode never announces")
	}
	if c.Inbound != nil {
		add("ixp forbids inbound: IXP mode never announces")
	}
	if c.MoreSpecific != nil {
		add("ixp forbids more_specific: IXP mode never announces")
	}
}
