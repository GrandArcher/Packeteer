package outside

import (
	"net/netip"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/leakwatch"
	"github.com/GrandArcher/Packeteer/internal/linkout"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// RIS shows what the leak watch's rislive sources saw (#199): routes of
// this AS that RIPE RIS Live reported outside it. The leak watch owns the
// stream; this only reads its state.
type RIS struct {
	Status func() leakwatch.Status
}

// ID implements Source.
func (RIS) ID() string { return "ris" }

// Section lists the held leaks reported by a rislive source.
func (r RIS) Section(_ Target, now time.Time) Section {
	sec := Section{ID: "ris", Source: "RIPE RIS Live, through leak_watch", Columns: []string{"Prefix", "Seen", "AS path", "Why", "Last seen"}}
	st := r.Status()
	rislive := map[string]bool{}
	healthy := false
	for _, src := range st.Sources {
		if src.Type == "rislive" {
			rislive[src.Name] = true
			healthy = healthy || src.Healthy
		}
	}
	var newest time.Time
	for _, l := range st.Leaks {
		if !rislive[l.Source] {
			continue
		}
		sec.Rows = append(sec.Rows, []string{l.Prefix.String(), l.Seen, asPath(l.ASPath), l.Reason, l.LastSeen.UTC().Format(time.RFC3339)})
		if l.LastSeen.After(newest) {
			newest = l.LastSeen
		}
	}
	sec.stamp(newest, now)
	switch {
	case !healthy:
		sec.Note = "The RIS Live stream is not delivering, so no sighting is not proof that nothing leaked."
	case len(sec.Rows) == 0:
		sec.Note = "No route of this AS was seen outside it."
	}
	return sec
}

func asPath(p []uint32) string {
	s := ""
	for i, a := range p {
		if i > 0 {
			s += " "
		}
		s += strconv.FormatUint(uint64(a), 10)
	}
	return s
}

// RPKI shows the origin validation of a prefix and its origin ASN from the
// configured rpki source (#158).
type RPKI struct {
	Validate func(netip.Prefix, uint32) plugin.RPKIValidity
	// Updated is when the validation cache last completed a fetch.
	Updated func() time.Time
}

// ID implements Source.
func (RPKI) ID() string { return "rpki" }

// Section needs a prefix with its origin ASN.
func (r RPKI) Section(t Target, now time.Time) Section {
	sec := Section{ID: "rpki", Source: "RPKI validation cache"}
	sec.stamp(r.Updated(), now)
	if !t.Prefix.IsValid() || t.ASN == 0 {
		sec.Note = "Validation needs a prefix and its origin ASN."
		return sec
	}
	sec.Columns = []string{"Prefix", "Origin", "State"}
	sec.Rows = [][]string{{t.Prefix.String(), "AS" + strconv.FormatUint(uint64(t.ASN), 10), string(r.Validate(t.Prefix, t.ASN))}}
	return sec
}

// Links are the link-out sites of the linkouts block for the target. No
// request is made to any of them.
type Links struct {
	Set *linkout.Set
}

// ID implements Source.
func (Links) ID() string { return "links" }

// Section builds the links for the prefix and the ASN.
func (l Links) Section(t Target, _ time.Time) Section {
	sec := Section{ID: "links", Source: "link-outs (no request is made)", Links: []linkout.Link{}}
	if t.Prefix.IsValid() {
		sec.Links = append(sec.Links, l.Set.Prefix(t.Prefix)...)
	}
	if t.ASN != 0 {
		sec.Links = append(sec.Links, l.Set.ASN(t.ASN)...)
	}
	if len(sec.Links) == 0 {
		sec.Note = "Choose a prefix or an ASN."
	}
	return sec
}
