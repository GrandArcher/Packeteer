package nonbgp

import (
	"net/netip"
	"time"
)

// SourceSynthetic labels a route learned from flow data. A route from a BGP
// session never carries it, and a synthetic one is never exported to a BGP
// peer or the herd as a real route.
const SourceSynthetic = "synthetic"

// Meta is the configuration shown beside the routes.
type Meta struct {
	Mode            string `json:"mode"`
	DefaultProvider string `json:"default_provider"`
	Steerer         string `json:"steerer,omitempty"`
	Covering        string `json:"covering,omitempty"`
	WidenBits       int    `json:"widen_bits"`
	MaxBlocks       int    `json:"max_blocks"`
}

// RouteStatus is one synthetic prefix and, when it is steered, the static
// route that carries it.
type RouteStatus struct {
	Source       string       `json:"source"`
	Prefix       netip.Prefix `json:"prefix"`
	Upper        netip.Prefix `json:"upper,omitzero"`
	Blocks       int          `json:"blocks"`
	LastSeen     time.Time    `json:"last_seen"`
	SteeredTo    string       `json:"steered_to,omitempty"`
	NextHop      netip.Addr   `json:"next_hop,omitzero"`
	SteeredSince time.Time    `json:"steered_since,omitzero"`
}

// Status is /api/synthetic.
type Status struct {
	Meta
	Blocks       int           `json:"tracked_blocks"`
	Pending      int           `json:"pending_lookups"`
	Dropped      uint64        `json:"dropped_blocks"`
	LookupErrors uint64        `json:"lookup_errors"`
	LastError    string        `json:"last_error,omitempty"`
	Routes       []RouteStatus `json:"routes"`
}

// Report joins the table with the routes the steer controller has on the
// router. steer may be nil.
func Report(meta Meta, t *Table, s *Steer) Status {
	st := t.Stats()
	out := Status{Meta: meta, Blocks: st.Blocks, Pending: st.Pending, Dropped: st.Dropped,
		LookupErrors: st.LookupErrors, LastError: st.LastError, Routes: []RouteStatus{}}
	steered := map[netip.Prefix]Steered{}
	for _, r := range s.Active() {
		steered[r.Prefix] = r
	}
	for _, r := range t.Routes() {
		row := RouteStatus{Source: SourceSynthetic, Prefix: r.Prefix, Upper: r.Upper, Blocks: r.Blocks, LastSeen: r.LastSeen}
		if sr, ok := steered[r.Prefix]; ok {
			row.SteeredTo, row.NextHop, row.SteeredSince = sr.Provider, sr.NextHop, sr.Since
		}
		out.Routes = append(out.Routes, row)
	}
	return out
}
