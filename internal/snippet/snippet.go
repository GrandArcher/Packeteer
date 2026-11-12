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
	"net"
	"net/netip"
	"strconv"
	"strings"
	"text/template"

	"github.com/GrandArcher/Packeteer/internal/config"
	"gopkg.in/yaml.v3"
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
	// FlowHost and FlowPort are where the router sends flow records: the
	// flow source's listen address. FlowPort is 0 when no flow source
	// listens.
	FlowHost string
	FlowPort int
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

// MissingError lists, in plain words, the answers a snippet still needs and
// where to give each one. It is not an internal error: the operator is
// part-way through setup.
type MissingError struct{ Hints []string }

func (e *MissingError) Error() string { return strings.Join(e.Hints, "\n") }

const (
	hintASN    = "AS number: enter it as ASN in setup step 1 (Edge), or set asn in the file."
	hintEdge   = "Router address: enter the Edge address in setup step 1 (Edge), or set bgp.neighbors in the file. The snippet is for that router."
	hintSelf   = "Packeteer's address: enter the Router ID in setup step 1 (Edge), or set router_id or the neighbor's local_address in the file. The router needs it to peer with Packeteer."
	hintNoComm = "Packeteer community: the router filters match it. Press Generate in setup step 4 (Flow) to fill it as %d:666, or set packeteer_community in the file."
	hintBigASN = "Packeteer community: setup leaves it empty for an AS number above 65535, because the standard community has 16 bits. Set packeteer_community in the settings form or the file as a large community, for example 65536:666:1."
)

func communityHint(asn uint32) string {
	if asn > 0xffff {
		return hintBigASN
	}
	if asn == 0 {
		return "Packeteer community: set packeteer_community in the file, or enter the ASN in setup step 1 (Edge) so setup can fill it."
	}
	return fmt.Sprintf(hintNoComm, asn)
}

// ForConfig returns one Params per bgp.neighbors entry: each neighbor is a
// router that needs its own snippet. When answers are missing it returns a
// *MissingError naming every one, not just the first.
func ForConfig(cfg *config.Config) ([]Params, error) {
	var miss []string
	if cfg.ASN == 0 {
		miss = append(miss, hintASN)
	}
	if len(cfg.BGP.Neighbors) == 0 {
		miss = append(miss, hintEdge)
	}
	if cfg.PacketeerCommunity == "" {
		miss = append(miss, communityHint(cfg.ASN))
	}
	if cfg.RouterID == "" && !allHaveLocalAddress(cfg.BGP.Neighbors) {
		miss = append(miss, hintSelf)
	}
	if len(miss) > 0 {
		return nil, &MissingError{Hints: miss}
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
	listen := flowListen(cfg)
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
			return nil, fmt.Errorf("the router needs Packeteer's address, and %q is not an IP address: fix the Router ID in setup step 1, or router_id and the neighbor's local_address in the file", self)
		}
		p := Params{
			ASN: cfg.ASN, Router: router.Unmap().String(), Packeteer: pk.Unmap().String(), Community: community,
			AddPath: n.AddPath, IPv6: v6 || router.Is6() && !router.Is4In6(),
		}
		p.FlowHost, p.FlowPort = p.collector(listen)
		out = append(out, p)
	}
	return out, nil
}

// allHaveLocalAddress is false when a neighbor has no local_address, or
// there is none, so router_id is Packeteer's address.
func allHaveLocalAddress(ns []config.BGPNeighbor) bool {
	for _, n := range ns {
		if n.LocalAddress == "" {
			return false
		}
	}
	return len(ns) > 0
}

// flowListen is the first usable host:port a configured flow source
// listens on, or "" when there is none (no flow source, or an eBPF-only one).
func flowListen(cfg *config.Config) string {
	for _, s := range cfg.Sources {
		if s.Type != "flow" {
			continue
		}
		var c struct {
			Listen yaml.Node `yaml:"listen"`
		}
		if s.Config.Decode(&c) != nil {
			continue
		}
		var list []string
		switch c.Listen.Kind {
		case yaml.ScalarNode:
			list = []string{c.Listen.Value}
		case yaml.SequenceNode:
			_ = c.Listen.Decode(&list)
		}
		for _, l := range list {
			if _, port, err := net.SplitHostPort(l); err == nil && port != "0" {
				return l
			}
		}
	}
	return ""
}

// collector is where the router sends flow records: the flow source's
// listen address, or Packeteer's own address when it listens on every one.
func (p Params) collector(listen string) (string, int) {
	if listen == "" {
		return "", 0
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", 0
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", 0
	}
	if a, err := netip.ParseAddr(host); err != nil || a.IsUnspecified() {
		host = p.Packeteer
	}
	return host, n
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
