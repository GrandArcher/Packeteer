package configedit

import (
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// The exchanges section (#181) edits the `exchanges` block: each exchange's
// name, peering LANs, bmp use, group, and peers (name, ASN, next hop, probe
// source, cost). Like the other sections, a nil list in a request leaves the
// block alone and applying edits the YAML text only. Save runs the loader's
// checks, which include the route check requirements (add_path or bmp). A
// peer's exclude and precedence (#330) are fields. No session or
// route-server credential is a field.

// MaxFormPeers bounds the peers of one exchange in the form.
const MaxFormPeers = 256

// FormExchange is one entry of `exchanges`. Key is its name in the file when
// the form was loaded; empty means a new exchange.
type FormExchange struct {
	Key   string             `json:"key"`
	Name  string             `json:"name"`
	LANs  []string           `json:"lans"`
	BMP   string             `json:"bmp"`
	Group string             `json:"group"`
	Peers []FormExchangePeer `json:"peers"`
}

// FormExchangePeer is one peer. Key is its name in the file when the form
// was loaded; empty means a new peer. SourceIP may be empty in a draft row;
// Save refuses the file until it is set. Draft marks a row filled from a
// discovered LAN member (#155); it is display only and Apply never writes it.
type FormExchangePeer struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	ASN      string `json:"asn"`
	NextHop  string `json:"next_hop"`
	SourceIP string `json:"source_ip"`
	Cost     string `json:"cost"`
	// Exclude keeps the peer measured but never chosen. Precedence is the
	// commit-control preference, lower first (empty is the default).
	Exclude    bool   `json:"exclude"`
	Precedence string `json:"precedence"`
	Draft      bool   `json:"draft,omitempty"`
}

func readExchanges(root *yaml.Node, f *Form) error {
	f.Exchanges = []FormExchange{}
	seq, ok := sequenceChild(root, "exchanges")
	if !ok {
		return nil
	}
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			return fmt.Errorf("%w: exchanges must be a list of mappings", ErrForm)
		}
		name := scalar(item, "name")
		if name == "" {
			return fmt.Errorf("%w: an exchange is missing its name", ErrForm)
		}
		ex := FormExchange{Key: name, Name: name, LANs: scalarList(item, "lans"), BMP: scalar(item, "bmp"),
			Group: scalar(item, "group"), Peers: []FormExchangePeer{}}
		if peers, ok := sequenceChild(item, "peers"); ok {
			for _, p := range peers.Content {
				if p.Kind != yaml.MappingNode {
					return fmt.Errorf("%w: exchange %s: peers must be a list of mappings", ErrForm, name)
				}
				pn := scalar(p, "name")
				if pn == "" {
					return fmt.Errorf("%w: exchange %s: a peer is missing its name", ErrForm, name)
				}
				ex.Peers = append(ex.Peers, FormExchangePeer{Key: pn, Name: pn, ASN: scalar(p, "asn"),
					NextHop: scalar(p, "next_hop"), SourceIP: scalar(p, "source_ip"), Cost: scalar(p, "cost"),
					Exclude: boolScalar(p, "exclude"), Precedence: scalar(p, "precedence")})
			}
		}
		f.Exchanges = append(f.Exchanges, ex)
	}
	return nil
}

func (f *Form) normalizeExchanges() {
	for i := range f.Exchanges {
		ex := &f.Exchanges[i]
		ex.Key = strings.TrimSpace(ex.Key)
		ex.Name = strings.TrimSpace(ex.Name)
		ex.BMP = strings.TrimSpace(ex.BMP)
		ex.Group = strings.TrimSpace(ex.Group)
		ex.LANs = trimAll(ex.LANs)
		if ex.Peers == nil {
			ex.Peers = []FormExchangePeer{}
		}
		for j := range ex.Peers {
			p := &ex.Peers[j]
			for _, s := range []*string{&p.Key, &p.Name, &p.ASN, &p.NextHop, &p.SourceIP, &p.Cost, &p.Precedence} {
				*s = strings.TrimSpace(*s)
			}
			p.Draft = false
		}
	}
}

// fillExchanges gives a nil list the file's current value and every inner
// list a non-nil value, so a round trip compares equal.
func (f *Form) fillExchanges(cur Form) {
	if f.Exchanges == nil {
		f.Exchanges = cur.Exchanges
	}
	for i := range f.Exchanges {
		if f.Exchanges[i].LANs == nil {
			f.Exchanges[i].LANs = []string{}
		}
	}
}

func (f Form) peerCount() int {
	n := 0
	for _, ex := range f.Exchanges {
		n += len(ex.Peers)
	}
	return n
}

func (f Form) validateExchanges() error {
	if err := validateEntryCount("exchanges", len(f.Exchanges)); err != nil {
		return err
	}
	taken := map[string]string{}
	for _, p := range f.Providers {
		taken[p.Name] = "a provider"
	}
	var keys []string
	for i, ex := range f.Exchanges {
		keys = append(keys, ex.Key)
		if err := validateOneExchange(i, ex, taken); err != nil {
			return err
		}
	}
	return checkKeys("exchange", keys)
}

func validateOneExchange(i int, ex FormExchange, taken map[string]string) error {
	label := fmt.Sprintf("exchanges[%d]", i)
	if !instanceName.MatchString(ex.Name) {
		return fmt.Errorf("%w: %s: name %q must be 1 to 64 letters, digits, dot, dash, or underscore", ErrForm, label, ex.Name)
	}
	label += " (" + ex.Name + ")"
	if what, dup := taken[ex.Name]; dup {
		return fmt.Errorf("%w: %s: name is already used by %s", ErrForm, label, what)
	}
	taken[ex.Name] = "an exchange"
	if len(ex.LANs) == 0 {
		return fmt.Errorf("%w: %s: at least one peering LAN prefix is required", ErrForm, label)
	}
	if err := validPrefixList(label+" lans", ex.LANs); err != nil {
		return err
	}
	switch ex.BMP {
	case "", config.BMPOff, config.BMPPrefer, config.BMPOnly:
	default:
		return fmt.Errorf("%w: %s: bmp %q is invalid (want off, prefer, or only)", ErrForm, label, ex.BMP)
	}
	if ex.Group != "" && !instanceName.MatchString(ex.Group) {
		return fmt.Errorf("%w: %s: group %q must be 1 to 64 letters, digits, dot, dash, or underscore", ErrForm, label, ex.Group)
	}
	if len(ex.Peers) == 0 {
		return fmt.Errorf("%w: %s: at least one peer is required", ErrForm, label)
	}
	if len(ex.Peers) > MaxFormPeers {
		return fmt.Errorf("%w: %s: at most %d peers in the form", ErrForm, label, MaxFormPeers)
	}
	lans := make([]netip.Prefix, 0, len(ex.LANs))
	for _, s := range ex.LANs {
		lans = append(lans, netip.MustParsePrefix(s))
	}
	var keys []string
	for j, p := range ex.Peers {
		keys = append(keys, p.Key)
		if err := validateOnePeer(fmt.Sprintf("%s: peers[%d]", label, j), p, lans, taken); err != nil {
			return err
		}
	}
	return checkKeys("peer of "+ex.Name, keys)
}

func validateOnePeer(label string, p FormExchangePeer, lans []netip.Prefix, taken map[string]string) error {
	if p.Name == "" || strings.ContainsAny(p.Name, "\n\r") {
		return fmt.Errorf("%w: %s: name is required", ErrForm, label)
	}
	label += " (" + p.Name + ")"
	if what, dup := taken[p.Name]; dup {
		return fmt.Errorf("%w: %s: name is already used by %s", ErrForm, label, what)
	}
	taken[p.Name] = "a peer"
	if n, err := strconv.ParseUint(p.ASN, 10, 32); err != nil || n == 0 {
		return fmt.Errorf("%w: %s: asn %q must be a non-zero AS number (the first AS on the peer's paths)", ErrForm, label, p.ASN)
	}
	nh, err := netip.ParseAddr(p.NextHop)
	if err != nil {
		return fmt.Errorf("%w: %s: next_hop %q is not an IP address", ErrForm, label, p.NextHop)
	}
	if !slices.ContainsFunc(lans, func(l netip.Prefix) bool { return l.Contains(nh) }) {
		return fmt.Errorf("%w: %s: next_hop %s is not inside the exchange's LANs", ErrForm, label, nh)
	}
	if p.SourceIP != "" {
		if _, err := netip.ParseAddr(p.SourceIP); err != nil {
			return fmt.Errorf("%w: %s: source_ip %q is not an IP address", ErrForm, label, p.SourceIP)
		}
	}
	if p.Cost != "" {
		v, err := strconv.ParseFloat(p.Cost, 64)
		if err != nil || math.IsNaN(v) || v < 0 || v > 1e9 {
			return fmt.Errorf("%w: %s: cost %q must be between 0 and 1000000000", ErrForm, label, p.Cost)
		}
	}
	return validInt(label+": precedence", p.Precedence, 0, 10000)
}

// applyExchanges rewrites the changed exchanges. An exchange the form did not
// change keeps its text, and a kept exchange or peer keeps the keys the form
// does not show.
func applyExchanges(root *yaml.Node, cur, next Form) error {
	if reflect.DeepEqual(cur.Exchanges, next.Exchanges) {
		return nil
	}
	seq, has := sequenceChild(root, "exchanges")
	old := map[string]*yaml.Node{}
	if has {
		for _, item := range seq.Content {
			old[scalar(item, "name")] = item
		}
	}
	var out []*yaml.Node
	used := map[*yaml.Node]bool{}
	for _, ex := range next.Exchanges {
		node := old[ex.Key]
		switch {
		case ex.Key == "":
			node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		case node == nil:
			return fmt.Errorf("%w: exchange %s is not in the file anymore; reload the form", ErrForm, ex.Key)
		case used[node]:
			return fmt.Errorf("%w: exchange %s is listed twice", ErrForm, ex.Key)
		}
		used[node] = true
		if !slices.ContainsFunc(cur.Exchanges, func(c FormExchange) bool { return c.Key == ex.Key && ex.Key != "" && reflect.DeepEqual(c, ex) }) {
			writeExchange(node, ex)
		}
		out = append(out, node)
	}
	if len(out) == 0 {
		deleteKey(root, "exchanges")
		return nil
	}
	if !has {
		seq = ensureSequence(root, "exchanges")
	}
	seq.Content = out
	return nil
}

func writeExchange(node *yaml.Node, ex FormExchange) {
	setOrDelete(node, "name", ex.Name, "!!str")
	setStringList(node, "lans", ex.LANs, "!!str")
	setOrDelete(node, "bmp", ex.BMP, "!!str")
	setOrDelete(node, "group", ex.Group, "!!str")
	peers := ensureSequence(node, "peers")
	old := map[string]*yaml.Node{}
	for _, item := range peers.Content {
		old[scalar(item, "name")] = item
	}
	var next []*yaml.Node
	used := map[*yaml.Node]bool{}
	for _, p := range ex.Peers {
		pn := old[p.Key]
		if p.Key == "" || pn == nil || used[pn] {
			pn = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		used[pn] = true
		setOrDelete(pn, "name", p.Name, "!!str")
		setOrDelete(pn, "asn", p.ASN, "!!int")
		setOrDelete(pn, "next_hop", p.NextHop, "!!str")
		setOrDelete(pn, "source_ip", p.SourceIP, "!!str")
		setOrDelete(pn, "cost", p.Cost, "!!float")
		setOrDelete(pn, "precedence", p.Precedence, "!!int")
		if p.Exclude {
			setOrDelete(pn, "exclude", "true", "!!bool")
		} else {
			deleteKey(pn, "exclude")
		}
		next = append(next, pn)
	}
	peers.Content = next
}
