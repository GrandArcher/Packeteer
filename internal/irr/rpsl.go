// Package irr is the shared IRR origin check (#214): an RPSL parser, the
// as-set expander, and the cache that answers per-path lookups from an
// ordered list of IRR sources without waiting on the network. It is
// read-only: it never announces and never changes the learned RIB.
package irr

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Attr is one RPSL attribute.
type Attr struct {
	Name  string
	Value string
}

// Object is one RPSL object (RFC 2622): its attributes in order. The
// first attribute is the class and the primary key.
type Object []Attr

// Class is the object class, lower case.
func (o Object) Class() string {
	if len(o) == 0 {
		return ""
	}
	return o[0].Name
}

// Get is the first value of the attribute, empty when absent.
func (o Object) Get(name string) string {
	for _, a := range o {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}

// All is every value of the attribute, in order.
func (o Object) All(name string) []string {
	var out []string
	for _, a := range o {
		if a.Name == name {
			out = append(out, a.Value)
		}
	}
	return out
}

// Bounds on one object and one line, so a broken or hostile server or file
// cannot exhaust memory.
const (
	maxLine  = 1 << 20
	maxAttrs = 100_000
)

// ParseRPSL reads RPSL objects separated by blank lines and calls fn for
// each. Lines starting with % (whois server remarks) are skipped, a # starts
// a comment, and a line starting with a space, a tab, or + continues the
// attribute before it. Attribute names are lower-cased.
func ParseRPSL(r io.Reader, fn func(Object) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	var obj Object
	flush := func() error {
		if len(obj) == 0 {
			return nil
		}
		o := obj
		obj = nil
		return fn(o)
	}
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "%") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if c := line[0]; c == ' ' || c == '\t' || c == '+' {
			if len(obj) == 0 {
				continue
			}
			if v := uncomment(line[1:]); v != "" {
				last := &obj[len(obj)-1]
				last.Value = strings.TrimSpace(last.Value + " " + v)
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("rpsl: line without an attribute name: %.80q", line)
		}
		if len(obj) >= maxAttrs {
			return fmt.Errorf("rpsl: object has more than %d attributes", maxAttrs)
		}
		obj = append(obj, Attr{Name: strings.ToLower(strings.TrimSpace(name)), Value: uncomment(value)})
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("rpsl: %w", err)
	}
	return flush()
}

func uncomment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// rpkiDatabase is the pseudo-source IRRd builds from ROAs. Its objects are
// RPKI data, which the rpki block already covers, so they are not IRR
// registration.
const rpkiDatabase = "RPKI"

// Route reads a route or route6 object. ok is false for another class, a
// malformed object, or an object of IRRd's RPKI pseudo-source.
func Route(o Object) (plugin.IRRRoute, bool) {
	if c := o.Class(); c != "route" && c != "route6" {
		return plugin.IRRRoute{}, false
	}
	p, err := netip.ParsePrefix(o[0].Value)
	if err != nil {
		return plugin.IRRRoute{}, false
	}
	origin, ok := netpfx.ParseASN(o.Get("origin"))
	db := strings.ToUpper(o.Get("source"))
	if !ok || db == rpkiDatabase {
		return plugin.IRRRoute{}, false
	}
	return plugin.IRRRoute{Prefix: p.Masked(), Origin: origin, Database: db}, true
}

// Members splits the members attributes of an as-set into AS numbers and
// nested set names. Other tokens (a route-set, AS-ANY) are dropped.
func Members(o Object) (asns []uint32, sets []string) {
	for _, v := range o.All("members") {
		for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if asn, ok := netpfx.ParseASN(tok); ok && strings.HasPrefix(strings.ToUpper(tok), "AS") {
				asns = append(asns, asn)
			} else if ValidASSetName(tok) {
				sets = append(sets, tok)
			}
		}
	}
	return asns, sets
}

var (
	setComponent = regexp.MustCompile(`^AS-[A-Z0-9_-]+$`)
	asnComponent = regexp.MustCompile(`^AS[0-9]+$`)
)

// ValidASSetName reports whether s is an as-set name (RFC 2622 section
// 5.1): AS- names and AS numbers joined by colons, at least one of them a
// set name. AS-ANY is a keyword, not a set.
func ValidASSetName(s string) bool {
	u := strings.ToUpper(s)
	if len(u) > 255 || u == "AS-ANY" {
		return false
	}
	set := false
	for _, c := range strings.Split(u, ":") {
		switch {
		case setComponent.MatchString(c):
			set = true
		case !asnComponent.MatchString(c):
			return false
		}
	}
	return set
}

// Bounds on one as-set expansion.
const (
	maxSetDepth = 8
	maxSets     = 1000
	maxMembers  = 100_000
)

// ErrSetTooLarge is returned when an expansion passes its bounds.
var ErrSetTooLarge = errors.New("irr: as-set expansion too large")

// Expand resolves an as-set to its AS numbers by following nested sets,
// each visited once, up to maxSetDepth levels. members returns one set's
// direct members and false when it does not exist; a missing nested set
// adds nothing.
func Expand(name string, members func(name string) (asns []uint32, sets []string, found bool, err error)) ([]uint32, error) {
	seen := map[string]bool{}
	got := map[uint32]bool{}
	var out []uint32
	var walk func(string, int) error
	walk = func(set string, depth int) error {
		key := strings.ToUpper(set)
		if seen[key] {
			return nil
		}
		seen[key] = true
		if len(seen) > maxSets || depth > maxSetDepth {
			return ErrSetTooLarge
		}
		asns, sets, found, err := members(set)
		if err != nil || !found {
			return err
		}
		for _, a := range asns {
			if !got[a] {
				got[a] = true
				out = append(out, a)
			}
		}
		if len(out) > maxMembers {
			return ErrSetTooLarge
		}
		for _, s := range sets {
			if err := walk(s, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(name, 0); err != nil {
		return nil, err
	}
	return out, nil
}
