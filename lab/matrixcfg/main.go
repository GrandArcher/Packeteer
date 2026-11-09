// Command matrixcfg prepares a lab Packeteer config for the failure-mode
// matrix (lab/e2e-failure-matrix.sh, #234). The matrix breaks measurements
// by removing the file a fixed prober reads, so a config whose fixed prober
// has its results inline is rewritten to read them from a file instead.
//
//	matrixcfg CONFIG OUT STATE FILE
//
// OUT is CONFIG with the first prober's inline results replaced by
// `file: FILE`, and STATE receives those results. A config whose prober
// already reads a file is copied to OUT unchanged and STATE is not written.
// Comments and key order survive.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: matrixcfg CONFIG OUT STATE FILE")
		os.Exit(2)
	}
	in, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "matrixcfg:", err)
		os.Exit(2)
	}
	out, state, err := fileProber(in, os.Args[4])
	if err != nil {
		fmt.Fprintln(os.Stderr, "matrixcfg:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[2], out, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "matrixcfg:", err)
		os.Exit(2)
	}
	if state != nil {
		if err := os.WriteFile(os.Args[3], state, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "matrixcfg:", err)
			os.Exit(2)
		}
	}
}

// fileProber returns the config with the first prober reading file, and the
// results it used to carry inline. state is nil when the prober already
// reads a file.
func fileProber(raw []byte, file string) (out, state []byte, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("config is not a mapping")
	}
	probers := value(doc.Content[0], "probers")
	if probers == nil || probers.Kind != yaml.SequenceNode || len(probers.Content) == 0 {
		return nil, nil, errors.New("config has no probers")
	}
	first := probers.Content[0]
	if t := value(first, "type"); t == nil || t.Value != "fixed" {
		return nil, nil, errors.New("the first prober is not the fixed prober")
	}
	cfg := value(first, "config")
	if cfg == nil || cfg.Kind != yaml.MappingNode {
		return nil, nil, errors.New("the fixed prober has no config")
	}
	if value(cfg, "file") != nil {
		return raw, nil, nil
	}
	state, err = yaml.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	*cfg = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "file"},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: file},
	}}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), state, nil
}

// value returns the value node of key in a mapping node, or nil.
func value(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
