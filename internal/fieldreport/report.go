// Package fieldreport builds the redacted summary an operator can paste into
// a field-report or bug issue (#625). It reads facts that hold no secrets
// and no operator names (plugin types and counts), and it runs the whole
// text through a Redactor as a last step, so a value that slipped into a
// field is still replaced. It sends nothing anywhere.
package fieldreport

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Facts are read from the loaded config: counts and plugin type names only.
// A provider, router, or exchange name, an address, a credential, or a
// community never goes in here.
type Facts struct {
	Providers int
	// BGPNeighbors counts the iBGP sessions to the edge router.
	BGPNeighbors int
	AddPath      bool
	// BMP is true when rib_sources is set or a provider uses bmp.
	BMP         bool
	ProbeTypes  []string
	SourceTypes []string
}

// Item is one line of the setup checklist: its id and level, not its text,
// because the text names providers and carries error strings.
type Item struct {
	ID    string
	Level string
}

// Events counts the events the controller kept. Kinds counts only the
// warning and critical ones, by kind (for example "bgp.session_down").
type Events struct {
	Total, Warning, Critical int
	Kinds                    map[string]int
}

// Value is one basis of the value report's total row (#583): the numbers
// only, never a prefix or a provider.
type Value struct {
	Basis          string
	Improvements   int
	Measured       int
	SteeredHours   float64
	LossAvoidedPct *float64
	RTTAvoidedMs   *float64
}

// Input is everything a report is built from.
type Input struct {
	Version   string
	Mode      string
	Facts     Facts
	Checklist []Item
	// Events is nil when the controller keeps no event log.
	Events *Events
	// ValueDays is the range of Value; Value is nil when the value report is
	// not available.
	ValueDays int
	Value     []Value
}

// EventWindow is how many of the newest events the counts cover.
const EventWindow = 1000

// FileName is the name the file is offered under.
const FileName = "packeteer-field-report.txt"

// Render returns the redacted report. It is deterministic: the same input
// gives the same bytes.
func Render(in Input) string {
	var b strings.Builder
	var keep []string
	line := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	line("Packeteer field report (redacted: addresses, prefixes, AS numbers and host names are placeholders)")
	line("version: %s", in.Version)
	line("mode: %s", in.Mode)
	line("providers: %d", in.Facts.Providers)
	line("ibgp sessions: %d (add-path: %s)", in.Facts.BGPNeighbors, yesNo(in.Facts.AddPath))
	line("bmp: %s", yesNo(in.Facts.BMP))
	line("router vendor: not read by Packeteer, add it in the issue form")
	line("probers: %s", list(in.Facts.ProbeTypes))
	line("target sources: %s", list(in.Facts.SourceTypes))

	line("setup checklist (%d):", len(in.Checklist))
	for _, it := range in.Checklist {
		line("  - %s: %s", it.Level, it.ID)
	}

	if e := in.Events; e == nil {
		line("events: not kept")
	} else {
		line("events (newest %d at most): %d total, %d warning, %d critical", EventWindow, e.Total, e.Warning, e.Critical)
		other := 0
		for _, k := range slices.Sorted(maps.Keys(e.Kinds)) {
			// Only a catalog kind is printed as it is; anything else
			// could carry text from a plugin.
			if _, ok := plugin.LookupEvent(k); !ok {
				other += e.Kinds[k]
				continue
			}
			keep = append(keep, k)
			line("  - %s: %d", k, e.Kinds[k])
		}
		if other > 0 {
			line("  - other kinds: %d", other)
		}
	}

	if in.Value == nil {
		line("value report: not available (no history storage, or it failed)")
	} else {
		line("value report, last %d days:", in.ValueDays)
		for _, v := range in.Value {
			line("  - %s: %d improvements, %d measured, %.1f steered hours, loss avoided %s, rtt avoided %s",
				v.Basis, v.Improvements, v.Measured, v.SteeredHours, num(v.LossAvoidedPct, "%"), num(v.RTTAvoidedMs, " ms"))
		}
		if len(in.Value) == 0 {
			line("  - no improvements")
		}
	}
	r := NewRedactor()
	r.Keep(keep...)
	return r.Redact(b.String())
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func list(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(slices.Sorted(slices.Values(s)), ", ")
}

func num(v *float64, unit string) string {
	if v == nil {
		return "not measured"
	}
	return fmt.Sprintf("%.3f%s", *v, unit)
}
