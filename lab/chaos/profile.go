package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

// Fault kinds a profile can list.
const (
	faultSessionFlap = "session-flap"
	faultLinkFlap    = "link-flap"
	faultSIGTERM     = "sigterm"
	faultSIGKILL     = "sigkill"
)

var faultKinds = []string{faultSessionFlap, faultLinkFlap, faultSIGTERM, faultSIGKILL}

// Profile is one chaos run.
type Profile struct {
	Name string `yaml:"name"`
	// Duration is the soak window. Faults run in order and the list
	// repeats until the window is over; the first pass always completes.
	Duration time.Duration `yaml:"duration"`
	// InjectLab declares the configs under test an inject lab: they may
	// run mode inject, with an allowlist of documentation prefixes only.
	InjectLab bool `yaml:"inject_lab"`
	// Configs are the Packeteer configs the lab mounts, checked before and
	// after the run.
	Configs []string `yaml:"configs"`
	Faults  []string `yaml:"faults"`
}

func loadProfile(path string) (Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var p Profile
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("%s: %w", path, err)
	}
	var errs []error
	if p.Name == "" {
		errs = append(errs, errors.New("name is required"))
	}
	if p.Duration <= 0 {
		errs = append(errs, errors.New("duration must be positive"))
	}
	if len(p.Configs) == 0 {
		errs = append(errs, errors.New("configs is empty"))
	}
	if len(p.Faults) == 0 {
		errs = append(errs, errors.New("faults is empty"))
	}
	for _, f := range p.Faults {
		if !slices.Contains(faultKinds, f) {
			errs = append(errs, fmt.Errorf("unknown fault %q (known: %v)", f, faultKinds))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return Profile{}, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}
