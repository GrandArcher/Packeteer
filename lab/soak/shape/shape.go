// Package shape holds the statistics of a real full BGP table (counts only,
// no prefix and no AS number) that the load test's synthetic table follows
// (#341). build/ rebuilds shape.json from a public RIPE RIS or RouteViews
// MRT dump.
package shape

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"regexp"
	"sort"
	"sync"
)

// Caps on the tails. A value above a cap is counted in the cap's bin, so
// no UPDATE the harness builds grows without bound.
const (
	MaxASPath           = 32
	MaxCommunities      = 32
	MaxLargeCommunities = 16
)

// Shape describes a full table, pooled over the peers that passed the
// filter. Every map is a histogram from a small integer (a prefix length, a
// hop count, a number of communities) to the number of routes with that value.
type Shape struct {
	Source    string `json:"source"`
	Collected string `json:"collected"`

	Peers  int    `json:"peers"` // full-feed peers pooled into the counts
	Routes int    `json:"routes"`
	IPv4   Family `json:"ipv4"`
	IPv6   Family `json:"ipv6"`

	ASPathLength     map[int]int `json:"as_path_length"`
	Communities      map[int]int `json:"communities"`
	LargeCommunities map[int]int `json:"large_communities"`
	Origin           map[int]int `json:"origin"` // 0 IGP, 1 EGP, 2 incomplete

	MEDRoutes     int `json:"med_routes"`
	AttributeSets int `json:"attribute_sets"`
}

// Family is the prefixes of one address family.
type Family struct {
	Prefixes int         `json:"prefixes"`
	Length   map[int]int `json:"length"`
}

// SetsPerMillion is the distinct attribute sets per million routes.
func (s Shape) SetsPerMillion() float64 {
	return float64(s.AttributeSets) * 1e6 / float64(s.Routes)
}

// Pool adds the counts of several peers' views. Attribute sets are distinct
// within a peer, so the pool keeps the per-route ratio of one peer.
func Pool(source, collected string, parts []Shape) Shape {
	out := NewAccumulator().s
	out.Source, out.Collected = source, collected
	for _, p := range parts {
		out.Peers++
		out.Routes += p.Routes
		out.IPv4.Prefixes += p.IPv4.Prefixes
		out.IPv6.Prefixes += p.IPv6.Prefixes
		out.MEDRoutes += p.MEDRoutes
		out.AttributeSets += p.AttributeSets
		for _, m := range [][2]map[int]int{
			{out.IPv4.Length, p.IPv4.Length}, {out.IPv6.Length, p.IPv6.Length},
			{out.ASPathLength, p.ASPathLength}, {out.Communities, p.Communities},
			{out.LargeCommunities, p.LargeCommunities}, {out.Origin, p.Origin},
		} {
			for k, v := range m[1] {
				m[0][k] += v
			}
		}
	}
	return out
}

//go:embed shape.json
var embedded []byte

// Default is the checked-in shape. It is validated by a test, so a bad file
// fails the build's tests rather than a load run.
var Default = sync.OnceValue(func() Shape {
	s, err := Parse(embedded)
	if err != nil {
		panic("lab/soak/shape: shape.json: " + err.Error())
	}
	return s
})

// Parse decodes and validates a shape file. Unknown fields are an error, so
// a field that could carry a prefix or an AS number cannot be added unseen.
func Parse(b []byte) (Shape, error) {
	var s Shape
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Shape{}, err
	}
	return s, s.Validate()
}

// plainText has no dot or colon, so no address fits, and no run of five
// digits, so no AS number does.
var (
	plainText = regexp.MustCompile(`^[A-Za-z0-9 ,_-]{1,80}$`)
	longDigit = regexp.MustCompile(`\d{5}`)
)

// Validate checks that the histograms add up and that the free text is a
// plain label. The text fields are the only strings in the file.
func (s Shape) Validate() error {
	for _, t := range []string{s.Source, s.Collected} {
		if !plainText.MatchString(t) || longDigit.MatchString(t) {
			return fmt.Errorf("text %q is not a plain label", t)
		}
	}
	checks := []struct {
		name  string
		h     map[int]int
		max   int
		total int
	}{
		{"ipv4.length", s.IPv4.Length, 32, s.IPv4.Prefixes},
		{"ipv6.length", s.IPv6.Length, 128, s.IPv6.Prefixes},
		{"as_path_length", s.ASPathLength, MaxASPath, s.Routes},
		{"communities", s.Communities, MaxCommunities, s.Routes},
		{"large_communities", s.LargeCommunities, MaxLargeCommunities, s.Routes},
		{"origin", s.Origin, 2, s.Routes},
	}
	for _, c := range checks {
		sum := 0
		for k, v := range c.h {
			if k < 0 || k > c.max || v <= 0 {
				return fmt.Errorf("%s: bad bin %d: %d", c.name, k, v)
			}
			sum += v
		}
		if sum != c.total {
			return fmt.Errorf("%s adds up to %d, want %d", c.name, sum, c.total)
		}
	}
	if s.IPv4.Prefixes+s.IPv6.Prefixes != s.Routes || s.Routes <= 0 {
		return errors.New("routes is not the sum of both families")
	}
	if s.Peers <= 0 {
		return errors.New("peers must be positive")
	}
	if s.IPv6.Prefixes == 0 {
		return errors.New("no IPv6 prefixes")
	}
	if s.MEDRoutes < 0 || s.MEDRoutes > s.Routes {
		return errors.New("med_routes out of range")
	}
	if s.AttributeSets <= 0 || s.AttributeSets > s.Routes {
		return errors.New("attribute_sets out of range")
	}
	return nil
}

// Dist draws from a histogram.
type Dist struct {
	vals  []int
	cum   []uint64
	total uint64
}

// NewDist builds a distribution from a histogram of positive counts.
func NewDist(h map[int]int) Dist {
	d := Dist{}
	for k := range h {
		d.vals = append(d.vals, k)
	}
	sort.Ints(d.vals)
	for _, k := range d.vals {
		d.total += uint64(h[k])
		d.cum = append(d.cum, d.total)
	}
	return d
}

// Pick maps a uniform 64-bit random value to a bin, weighted by count.
func (d Dist) Pick(r uint64) int {
	hi, _ := bits.Mul64(r, d.total)
	return d.vals[sort.Search(len(d.cum), func(i int) bool { return d.cum[i] > hi })]
}
