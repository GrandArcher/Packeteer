// Package outside is the outside intelligence on the herd dashboard
// (#296): RIPE Atlas results, routes seen by RIS Live through the leak
// watch, RPKI origin validation, and link-outs. Every section names its
// source and its age, is opt-in, and is kept apart from herd data: nothing
// here is a herd vantage, and nothing here is read by Decide, a scorer, or
// the announcer. Display only.
package outside

import (
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/linkout"
)

// Target is what the operator is looking at on the dashboard. Either part
// may be unset.
type Target struct {
	Prefix netip.Prefix
	ASN    uint32
}

// Section is one outside source's answer: a small table, link-outs, or a
// note on why there is nothing.
type Section struct {
	// ID is atlas, ris, rpki, or links.
	ID     string `json:"id"`
	Source string `json:"source"`
	// AsOf is when the data was produced or fetched; absent when the
	// source has produced none.
	AsOf       *time.Time     `json:"as_of,omitempty"`
	AgeSeconds *float64       `json:"age_seconds,omitempty"`
	Note       string         `json:"note,omitempty"`
	Error      string         `json:"error,omitempty"`
	Columns    []string       `json:"columns,omitempty"`
	Rows       [][]string     `json:"rows,omitempty"`
	Links      []linkout.Link `json:"links,omitempty"`
}

// stamp sets AsOf and the age against now.
func (s *Section) stamp(t, now time.Time) {
	if t.IsZero() {
		return
	}
	age := max(now.Sub(t).Seconds(), 0)
	s.AsOf, s.AgeSeconds = &t, &age
}

// Source is one outside source. Section never blocks on the network: it
// reads what the source already holds.
type Source interface {
	ID() string
	Section(t Target, now time.Time) Section
}

// Set is the enabled sources, in display order. The zero Set has none, and
// the dashboard then shows herd data only.
type Set struct {
	sources []Source
}

// NewSet keeps the sources in order.
func NewSet(sources ...Source) *Set { return &Set{sources: sources} }

// IDs lists the enabled sources.
func (s *Set) IDs() []string {
	ids := []string{}
	if s != nil {
		for _, src := range s.sources {
			ids = append(ids, src.ID())
		}
	}
	return ids
}

// Sections asks each enabled source about t.
func (s *Set) Sections(t Target, now time.Time) []Section {
	out := []Section{}
	if s != nil {
		for _, src := range s.sources {
			out = append(out, src.Section(t, now))
		}
	}
	return out
}
