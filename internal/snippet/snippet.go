// Package snippet prints the router side of a Packeteer setup: the iBGP
// session to Packeteer, the import filter that accepts only Packeteer's
// community, and the export deny for every eBGP neighbor (#221). It reads the
// config and prints text for review. It never connects to a router and
// applies nothing.
package snippet

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"text/template"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// Router vendors.
const (
	FRR      = "frr"
	BIRD     = "bird"
	Junos    = "junos"
	IOSXR    = "iosxr"
	Arista   = "arista"
	MikroTik = "mikrotik"
)

// Vendors lists the supported vendors in help order.
var Vendors = []string{FRR, BIRD, Junos, IOSXR, Arista, MikroTik}

//go:embed templates/*.tmpl
var files embed.FS

var templates = template.Must(template.ParseFS(files, "templates/*.tmpl"))

// Params is what the templates read. It comes from the config, so the
// operator answers each question once.
type Params struct {
	ASN uint32
	// Router is the router's own address on the Packeteer session
	// (bgp.neighbors[].address).
	Router string
	// Packeteer is Packeteer's address as the router sees it:
	// bgp.neighbors[].local_address, else router_id.
	Packeteer string
	// Community is packeteer_community in canonical form: asn:value, or a
	// large community global:data1:data2.
	Community string
	// AddPath is true when the neighbor asks the router for add-path.
	AddPath bool
	// IPv6 is true when the session or a provider is IPv6.
	IPv6 bool
}

// Large reports whether Community is a large community (RFC 8092).
func (p Params) Large() bool { return strings.Count(p.Community, ":") == 2 }

// BirdMatch is the BIRD condition that matches Community.
func (p Params) BirdMatch() string {
	if p.Large() {
		return "(" + strings.ReplaceAll(p.Community, ":", ", ") + ") ~ bgp_large_community"
	}
	return "(" + strings.ReplaceAll(p.Community, ":", ", ") + ") ~ bgp_community"
}

// ErrUnsupported is returned for a vendor and community the template
// cannot express.
var ErrUnsupported = errors.New("unsupported")

// ForConfig returns one Params per bgp.neighbors entry: each neighbor is a
// router that needs its own snippet.
func ForConfig(cfg *config.Config) ([]Params, error) {
	if len(cfg.BGP.Neighbors) == 0 {
		return nil, errors.New("no bgp.neighbors: a snippet is for the router Packeteer peers with")
	}
	if cfg.PacketeerCommunity == "" {
		return nil, errors.New("packeteer_community is not set: the router filters match it")
	}
	community, err := config.CommunityText(cfg.PacketeerCommunity)
	if err != nil {
		return nil, fmt.Errorf("packeteer_community: %w", err)
	}
	v6 := false
	for _, p := range cfg.Providers {
		if a, err := netip.ParseAddr(p.NextHop); err == nil && a.Is6() && !a.Is4In6() {
			v6 = true
		}
	}
	var out []Params
	for _, n := range cfg.BGP.Neighbors {
		router, err := netip.ParseAddr(n.Address)
		if err != nil {
			return nil, fmt.Errorf("bgp.neighbors address %q: %w", n.Address, err)
		}
		self := n.LocalAddress
		if self == "" {
			self = cfg.RouterID
		}
		pk, err := netip.ParseAddr(self)
		if err != nil {
			return nil, fmt.Errorf("the router needs Packeteer's address: set router_id or bgp.neighbors local_address (got %q)", self)
		}
		out = append(out, Params{
			ASN: cfg.ASN, Router: router.Unmap().String(), Packeteer: pk.Unmap().String(), Community: community,
			AddPath: n.AddPath, IPv6: v6 || router.Is6() && !router.Is4In6(),
		})
	}
	return out, nil
}

// Generate renders the snippet for one vendor.
func Generate(vendor string, p Params) (string, error) {
	if vendor == Arista && p.Large() {
		return "", fmt.Errorf("%w: the arista template has no large community match; use a standard packeteer_community or write the match by hand", ErrUnsupported)
	}
	t := templates.Lookup(vendor + ".tmpl")
	if t == nil {
		return "", fmt.Errorf("unknown vendor %q (want %s)", vendor, strings.Join(Vendors, ", "))
	}
	var b bytes.Buffer
	if err := t.Execute(&b, p); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Join renders the snippet for every router, one after the other.
func Join(vendor string, ps []Params) (string, error) {
	var b strings.Builder
	for i, p := range ps {
		text, err := Generate(vendor, p)
		if err != nil {
			return "", err
		}
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(text)
	}
	return b.String(), nil
}
