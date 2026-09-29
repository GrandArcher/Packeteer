// Package geoip reads a MaxMind-format country database (for example
// GeoLite2-Country.mmdb) that the operator mounts into the container, and
// lists the networks of a country. Threat mitigation (#28) uses it to turn
// a FlowSpec rule's source countries into source prefixes. No database is
// shipped, and nothing is downloaded.
package geoip

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"

	"github.com/oschwald/maxminddb-golang/v2"
)

// DB is an open country database.
type DB struct {
	db *maxminddb.Reader
}

type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Registered struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

var countryCode = regexp.MustCompile(`^[A-Z]{2}$`)

// ValidCountry reports whether c is two upper-case letters.
func ValidCountry(c string) bool { return countryCode.MatchString(c) }

// Open reads the database at path into memory.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("geoip: no database path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}
	db, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, fmt.Errorf("geoip %s: %w", path, err)
	}
	return &DB{db: db}, nil
}

// Networks lists the networks of country (ISO code) in one address family,
// sorted, with adjacent siblings merged so the list is as short as the
// data allows. The country is the network's country, else its registered
// country, as in the rules policy.
func (d *DB) Networks(country string, v4 bool) ([]netip.Prefix, error) {
	if d == nil || d.db == nil {
		return nil, errors.New("geoip: no database")
	}
	var out []netip.Prefix
	for res := range d.db.Networks() {
		if err := res.Err(); err != nil {
			return nil, fmt.Errorf("geoip: %w", err)
		}
		p := res.Prefix()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if !p.IsValid() || p.Addr().Is4() != v4 {
			continue
		}
		var r record
		if err := res.Decode(&r); err != nil {
			continue
		}
		c := r.Country.ISOCode
		if c == "" {
			c = r.Registered.ISOCode
		}
		if c == country {
			out = append(out, p.Masked())
		}
	}
	return Aggregate(out), nil
}

// Aggregate sorts ps, drops prefixes covered by another, and merges
// sibling pairs into their parent until nothing changes.
func Aggregate(ps []netip.Prefix) []netip.Prefix {
	out := slices.Clone(ps)
	for {
		slices.SortFunc(out, func(a, b netip.Prefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})
		out = slices.Compact(out)
		changed := false
		var next []netip.Prefix
		for i := 0; i < len(out); i++ {
			p := out[i]
			if len(next) > 0 {
				last := next[len(next)-1]
				if last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
					changed = true
					continue
				}
				if last.Bits() == p.Bits() && last.Bits() > 0 {
					parent, _ := last.Addr().Prefix(last.Bits() - 1)
					if parent.Contains(p.Addr()) && parent.Addr() == last.Addr() {
						next[len(next)-1] = parent
						changed = true
						continue
					}
				}
			}
			next = append(next, p)
		}
		out = next
		if !changed {
			return out
		}
	}
}
