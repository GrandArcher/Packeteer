package configedit

import (
	"fmt"
	"reflect"

	"gopkg.in/yaml.v3"
)

// Form.Blocks (#330) carries one Values per block of blockDefs. A nil map in
// a request, or a block id it leaves out, means "leave that block alone", so
// an older client cannot remove one. A present id with a nil Values removes
// an optional block (the page's switch off). ParseForm fills every block.

func readBlocks(root *yaml.Node) map[string]Values {
	out := make(map[string]Values, len(blockDefs))
	for _, b := range blockDefs {
		out[b.ID] = b.read(root)
	}
	return out
}

// normalizeBlocks puts every block of the request in the shape readBlocks
// produces. An id that is not a block is an error.
func (f *Form) normalizeBlocks() error {
	for id, v := range f.Blocks {
		b, ok := blockByID(id)
		if !ok {
			return fmt.Errorf("%w: %q is not a settings block", ErrForm, id)
		}
		if v == nil {
			if !b.Optional {
				return fmt.Errorf("%w: %s cannot be turned off", ErrForm, id)
			}
			continue
		}
		n, err := normalizeValues(b.YAML, b.Fields, v)
		if err != nil {
			return err
		}
		f.Blocks[id] = n
	}
	for i := range f.Flows {
		extra, err := normalizeValues("flow", flowExtras, f.Flows[i].Extra)
		if err != nil {
			return err
		}
		f.Flows[i].Extra = extra
	}
	return nil
}

// fillBlocks gives a block the request left out the file's current value.
func (f *Form) fillBlocks(cur Form) {
	if f.Blocks == nil {
		f.Blocks = map[string]Values{}
	}
	for id, v := range cur.Blocks {
		if _, ok := f.Blocks[id]; !ok {
			f.Blocks[id] = v
		}
	}
}

// syncAnomaly keeps the rules list in step with the detector block: rules
// need a detector, so switching the block off drops them with it, and
// switching it on in the same request lets them be added.
func (f *Form) syncAnomaly(cur Form) {
	if f.Anomaly == nil {
		return
	}
	on := f.Blocks["anomaly"] != nil
	if !on && cur.Blocks["anomaly"] != nil {
		f.Anomaly.Rules = []FormAnomalyRule{}
	}
	f.Anomaly.Enabled = on
}

// changedBlocks lists the blocks whose value differs from the file's.
func (f Form) changedBlocks(cur Form) []Block {
	var out []Block
	for _, b := range blockDefs {
		if !reflect.DeepEqual(f.Blocks[b.ID], cur.Blocks[b.ID]) {
			out = append(out, b)
		}
	}
	return out
}

// scorerTypes are the scorer types the form switches between.
var scorerTypes = []string{"", "weighted", "commit", "cost"}

// effectiveScorer is the scorer the file will have once the form is merged.
func (f Form) effectiveScorer() string {
	if f.Commit != nil && f.Commit.Scorer != "" {
		return f.Commit.Scorer
	}
	return orWeighted(f.ScorerType)
}

// dropInapplicable clears the scorer knobs that belong to another scorer
// type than the one the file will have. Switching the type already drops
// those keys from the file, so the form's stale values are not an error.
func (f *Form) dropInapplicable() {
	v := f.Blocks["scorer"]
	b, ok := blockByID("scorer")
	if v == nil || !ok {
		return
	}
	eff := f.effectiveScorer()
	for _, fl := range b.Fields {
		if len(fl.For) == 0 || containsStr(fl.For, eff) {
			continue
		}
		if fl.Kind == KindBool {
			v[fl.Key] = false
		} else {
			v[fl.Key] = ""
		}
	}
}

func (f Form) validateBlocks(cur Form) error {
	for _, b := range f.changedBlocks(cur) {
		v := f.Blocks[b.ID]
		if b.ID == "scorer" && !containsStr(scorerTypes, f.ScorerType) {
			return fmt.Errorf("%w: scorer.config: this file uses scorer type %s, which the form does not edit. Change it in the raw YAML", ErrForm, f.ScorerType)
		}
		if v == nil {
			continue
		}
		if err := validateValues(b.YAML, b.Fields, v); err != nil {
			return err
		}
		if err := noInjectFrom(b, cur.Blocks[b.ID], v); err != nil {
			return err
		}
		if b.check != nil {
			if err := b.check(v); err != nil {
				return err
			}
		}
	}
	return nil
}

// noInjectFrom refuses a field marked NoInject going to inject.
func noInjectFrom(b Block, cur, next Values) error {
	for _, fl := range b.Fields {
		if !fl.NoInject || next[fl.Key] != "inject" {
			continue
		}
		if cur == nil || cur[fl.Key] != "inject" {
			return fieldErr(joinPath(b.YAML, fl.Key), "inject is not a form choice here: set it in the raw YAML after the inject checklist in docs/CONFIG.md, and confirm it on save")
		}
	}
	return nil
}

func applyBlocks(root *yaml.Node, cur, next Form) error {
	for _, b := range next.changedBlocks(cur) {
		if err := b.apply(root, next.Blocks[b.ID]); err != nil {
			return err
		}
	}
	return nil
}
