package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Report is chaos-result.json.
type Report struct {
	Profile     string         `json:"profile"`
	Started     time.Time      `json:"started"`
	Ended       time.Time      `json:"ended"`
	DurationS   float64        `json:"duration_s"`
	Pass        bool           `json:"pass"`
	Samples     int            `json:"samples"`
	FaultCounts map[string]int `json:"fault_counts"`
	Faults      []Fault        `json:"faults"`
	Violations  []Violation    `json:"violations"`
	Errors      []string       `json:"errors"`
	Events      []Event        `json:"events"`
}

// Fault is one injected fault and what the edge did.
type Fault struct {
	Kind   string    `json:"kind"`
	Target string    `json:"target"`
	At     time.Time `json:"at"`
	// WithdrawMs is from the fault to the target's routes leaving the edge.
	WithdrawMs *int64 `json:"withdraw_ms,omitempty"`
	// RestoreMs is from the fault (a link flap: from the repair) to a
	// Packeteer route on the edge again.
	RestoreMs *int64 `json:"restore_ms,omitempty"`
	// HoldMs is the negotiated hold time a SIGKILL is bounded by.
	HoldMs int64 `json:"hold_ms,omitempty"`
	// WithdrawnWhileUp is whether a SIGTERM withdraw arrived before the
	// session closed.
	WithdrawnWhileUp *bool  `json:"withdrawn_while_up,omitempty"`
	ExitCode         *int   `json:"exit_code,omitempty"`
	Error            string `json:"error,omitempty"`
}

// Event is a session state change on the edge or a role or lease holder
// change an instance reports.
type Event struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Subject string    `json:"subject"`
	Detail  string    `json:"detail"`
}

func (r *Report) finish() {
	r.DurationS = r.Ended.Sub(r.Started).Seconds()
	r.FaultCounts = map[string]int{}
	for _, f := range r.Faults {
		r.FaultCounts[f.Kind]++
	}
	if r.Violations == nil {
		r.Violations = []Violation{}
	}
	if r.Errors == nil {
		r.Errors = []string{}
	}
	r.Pass = len(r.Violations) == 0 && len(r.Errors) == 0
}

// write puts chaos-result.json and chaos-summary.md in dir.
func (r *Report) write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "chaos-result.json"), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "chaos-summary.md"), []byte(r.markdown()), 0o644)
}

func (r *Report) markdown() string {
	var b strings.Builder
	result := "PASS"
	if !r.Pass {
		result = "FAIL"
	}
	fmt.Fprintf(&b, "# Chaos soak: %s\n\n", r.Profile)
	fmt.Fprintf(&b, "Result: **%s**. %s to %s (%.0fs), %d samples.\n\n", result,
		r.Started.UTC().Format(time.RFC3339), r.Ended.UTC().Format(time.RFC3339), r.DurationS, r.Samples)
	b.WriteString("| Fault | Count | Max withdraw ms | Max restore ms |\n|---|---|---|---|\n")
	for _, kind := range faultKinds {
		n := r.FaultCounts[kind]
		if n == 0 {
			continue
		}
		var w, s int64 = -1, -1
		for _, f := range r.Faults {
			if f.Kind != kind {
				continue
			}
			if f.WithdrawMs != nil && *f.WithdrawMs > w {
				w = *f.WithdrawMs
			}
			if f.RestoreMs != nil && *f.RestoreMs > s {
				s = *f.RestoreMs
			}
		}
		fmt.Fprintf(&b, "| %s | %d | %s | %s |\n", kind, n, msCell(w), msCell(s))
	}
	b.WriteString("\nInvariant failures:")
	if len(r.Violations) == 0 {
		b.WriteString(" none\n")
	} else {
		b.WriteString("\n\n")
		for _, v := range r.Violations {
			fmt.Fprintf(&b, "- %s `%s`: %s\n", v.At.UTC().Format(time.RFC3339), v.Invariant, v.Detail)
		}
	}
	b.WriteString("\nErrors:")
	if len(r.Errors) == 0 {
		b.WriteString(" none\n")
	} else {
		b.WriteString("\n\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "- %s\n", e)
		}
	}
	counts := map[string]int{}
	for _, e := range r.Events {
		counts[e.Kind]++
	}
	fmt.Fprintf(&b, "\nEvents: %d session, %d lease.\n", counts["session"], counts["lease"])
	return b.String()
}

func msCell(v int64) string {
	if v < 0 {
		return "-"
	}
	return fmt.Sprint(v)
}
