package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Config is a plugin's raw config block. Plugins decode it into their own
// struct with Decode, which rejects unknown fields.
type Config struct {
	node *yaml.Node
}

// NewConfig wraps a YAML node. A nil or empty node decodes as no fields set.
func NewConfig(n *yaml.Node) Config { return Config{node: n} }

// ConfigFromYAML parses YAML text into a Config (handy in tests).
func ConfigFromYAML(s string) (Config, error) {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		return Config{}, err
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return Config{node: n.Content[0]}, nil
	}
	return Config{}, nil
}

// IsZero reports whether no config was given.
func (c Config) IsZero() bool { return c.node == nil || c.node.Kind == 0 }

// Decode strictly decodes the config into v (a pointer to a struct).
func (c Config) Decode(v any) error {
	if c.IsZero() {
		return nil
	}
	data, err := yaml.Marshal(c.node)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// Raw returns the config as a generic value (maps, slices, scalars), e.g. to
// forward it to an out-of-process plugin as JSON.
func (c Config) Raw() (any, error) {
	if c.IsZero() {
		return nil, nil
	}
	var v any
	if err := c.node.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
