package configedit

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ReadSections returns the canonical YAML of each named top-level key in
// data, with aliases resolved and map keys sorted, so equal settings
// compare equal as text. A key that is absent or null reads as "". It is
// the sending side of a federation settings push (#137).
func ReadSections(data []byte, names []string) (map[string]string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		text, err := canonical(doc[n])
		if err != nil {
			return nil, err
		}
		out[n] = text
	}
	return out, nil
}

// ReplaceSections returns data with each named top-level key replaced by
// the YAML in sections, or removed when the text is empty. Every other key
// and comment stays as it was. The result is not validated: the caller
// runs the editor's checks on it.
func ReplaceSections(data []byte, sections map[string]string) ([]byte, error) {
	root, err := mappingRoot(data)
	if err != nil {
		return nil, err
	}
	for name, text := range sections {
		var v any
		if err := yaml.Unmarshal([]byte(text), &v); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrForm, name, err)
		}
		if v == nil {
			deleteKey(root, name)
			continue
		}
		var n yaml.Node
		if err := n.Encode(v); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrForm, name, err)
		}
		setChild(root, name, &n)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	return buf.Bytes(), nil
}

// CanonicalSection normalizes section text the way ReadSections does.
func CanonicalSection(text string) (string, error) {
	var v any
	if err := yaml.Unmarshal([]byte(text), &v); err != nil {
		return "", fmt.Errorf("%w: %v", ErrForm, err)
	}
	return canonical(v)
}

func canonical(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	b, err := yaml.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrForm, err)
	}
	return string(b), nil
}
