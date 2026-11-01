// Package pbr prints the policy routing that makes each provider's probes
// leave through that provider (#157): Linux ip rule and ip route commands,
// and policy-based routing snippets for FRR, Junos, Cisco IOS, and
// MikroTik RouterOS. It only generates text for an operator to review.
// Nothing is applied and nothing is sent to a router.
package pbr

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// Output formats.
const (
	Linux    = "linux"
	FRR      = "frr"
	Junos    = "junos"
	Cisco    = "cisco"
	MikroTik = "mikrotik"
)

// Formats lists the output formats in help order.
var Formats = []string{Linux, FRR, Junos, Cisco, MikroTik}

// Linux table ids start at tableBase, clear of the reserved tables 253-255
// and of the table ids in docs/policy-routing.md. Rule priorities start at
// prioBase, clear of the priorities the doc's hand-written rules use.
const (
	tableBase = 1000
	prioBase  = 2000
)

// maxFRRSeq is the highest pbr-map sequence number FRR accepts.
const maxFRRSeq = 700

// Entry is one provider's probe path: packets from Source, tagged with
// FwMark and DSCP when those are set, go to NextHop.
type Entry struct {
	// N is the 1-based position among the local providers. It numbers the
	// tables and sequences, so a regenerated file keeps the numbers while
	// the provider list is unchanged.
	N       int
	Name    string
	Source  netip.Addr
	NextHop netip.Addr
	FwMark  uint32
	DSCP    int
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// Ident is a router-safe identifier for the entry. Provider names are not
// restricted by the config, so only a sanitized form reaches the output.
func (e Entry) Ident() string {
	name := strings.Trim(unsafeChars.ReplaceAllString(e.Name, "_"), "_.-")
	if len(name) > 20 {
		name = strings.Trim(name[:20], "_.-")
	}
	if name == "" {
		return fmt.Sprintf("pk%d", e.N)
	}
	return fmt.Sprintf("pk%d-%s", e.N, name)
}

// Entries lists the providers measured from this instance. A provider in
// another domain has no source here and is left out.
func Entries(cfg *config.Config) []Entry {
	var out []Entry
	for _, p := range cfg.Providers {
		if !cfg.LocalProbe(p) {
			continue
		}
		src, serr := netip.ParseAddr(p.SourceIP)
		nh, nerr := netip.ParseAddr(p.NextHop)
		if serr != nil || nerr != nil {
			continue // Validate rejects it
		}
		out = append(out, Entry{N: len(out) + 1, Name: p.Name, Source: src.Unmap(), NextHop: nh.Unmap(), FwMark: p.FwMark, DSCP: p.DSCP})
	}
	return out
}

// Generate renders the entries in the given format.
func Generate(format string, entries []Entry) (string, error) {
	if len(entries) == 0 {
		return "", fmt.Errorf("no provider is measured from this instance")
	}
	var b strings.Builder
	var err error
	switch format {
	case Linux:
		err = genLinux(&b, entries)
	case FRR:
		err = genFRR(&b, entries)
	case Junos:
		err = genJunos(&b, entries)
	case Cisco:
		err = genCisco(&b, entries)
	case MikroTik:
		err = genMikroTik(&b, entries)
	default:
		return "", fmt.Errorf("unknown format %q (want %s)", format, strings.Join(Formats, ", "))
	}
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

// routerEntries rejects an entry a router cannot select. A Linux fwmark
// exists only inside the probe host, so the router must see the DSCP.
func routerEntries(entries []Entry) error {
	for _, e := range entries {
		if e.FwMark != 0 && e.DSCP == 0 {
			return fmt.Errorf("provider %s sets fwmark but no dscp: a router cannot match a Linux fwmark (set dscp as well, or use format %s)", e.Name, Linux)
		}
	}
	return nil
}

func hostPrefix(a netip.Addr) string { return netip.PrefixFrom(a, a.BitLen()).String() }

func defaultRoute(a netip.Addr) string {
	if a.Is4() {
		return "0.0.0.0/0"
	}
	return "::/0"
}

// linuxMarkClash rejects a configured fwmark that equals the mark nftables
// sets for a DSCP-only provider on the same source: both rules would match
// and the lower priority one would route probes through the wrong table.
func linuxMarkClash(entries []Entry) error {
	for _, d := range entries {
		if d.FwMark != 0 || d.DSCP == 0 {
			continue
		}
		for _, e := range entries {
			if e.FwMark == uint32(tableBase+d.N) && e.Source == d.Source {
				return fmt.Errorf("provider %s fwmark %d equals the mark generated for dscp-only provider %s on source %s: change its fwmark", e.Name, e.FwMark, d.Name, d.Source)
			}
		}
	}
	return nil
}

// pick returns v4 for an IPv4 address and v6 for an IPv6 one.
func pick(a netip.Addr, v4, v6 string) string {
	if a.Is4() {
		return v4
	}
	return v6
}

// families reports which address families the entries use.
func families(entries []Entry) (v4, v6 bool) {
	for _, e := range entries {
		if e.Source.Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	return v4, v6
}

func genLinux(b *strings.Builder, entries []Entry) error {
	if err := linuxMarkClash(entries); err != nil {
		return err
	}
	b.WriteString("# Packeteer probe policy routing for the Linux host that sends the probes.\n")
	b.WriteString("# Generated for review. Nothing is applied. Run as root, then check with\n")
	b.WriteString("# ip route get <host> from <source> [mark <fwmark>].\n")
	nft := false
	for _, e := range entries {
		table := tableBase + e.N
		prio := prioBase + e.N
		fam := pick(e.Source, "", " -6")
		fmt.Fprintf(b, "\n# %s: source %s via %s", e.Ident(), e.Source, e.NextHop)
		if e.FwMark != 0 {
			fmt.Fprintf(b, ", fwmark %d", e.FwMark)
		} else if e.DSCP != 0 {
			fmt.Fprintf(b, ", dscp %d", e.DSCP)
		}
		fmt.Fprintf(b, "\nip%s route add default via %s table %d\n", fam, e.NextHop, table)
		switch {
		case e.FwMark != 0:
			fmt.Fprintf(b, "ip%s rule add from %s fwmark %d lookup %d priority %d\n", fam, e.Source, e.FwMark, table, prio)
		case e.DSCP != 0:
			// The kernel rule selector for DSCP is not available everywhere,
			// so nftables turns the DSCP into a mark that equals the table.
			if !nft {
				b.WriteString("nft add table inet packeteer\n")
				b.WriteString("nft add chain inet packeteer probes '{ type route hook output priority mangle ; }'\n")
				nft = true
			}
			ip := pick(e.Source, "ip", "ip6")
			fmt.Fprintf(b, "nft add rule inet packeteer probes %s saddr %s %s dscp %d meta mark set %d\n", ip, e.Source, ip, e.DSCP, table)
			fmt.Fprintf(b, "ip%s rule add from %s fwmark %d lookup %d priority %d\n", fam, e.Source, table, table, prio)
		default:
			fmt.Fprintf(b, "ip%s rule add from %s lookup %d priority %d\n", fam, e.Source, table, prio)
		}
	}
	return nil
}

func genFRR(b *strings.Builder, entries []Entry) error {
	if err := routerEntries(entries); err != nil {
		return err
	}
	if len(entries) > maxFRRSeq {
		return fmt.Errorf("frr pbr-map sequence numbers stop at %d; %d providers are measured here", maxFRRSeq, len(entries))
	}
	b.WriteString("! Packeteer probe policy routing for FRR pbrd. Generated for review.\n")
	b.WriteString("! Nothing is applied. pbrd must be running.\n")
	for _, e := range entries {
		fmt.Fprintf(b, "!\n! %s\npbr-map PACKETEER seq %d\n match src-ip %s\n", e.Ident(), e.N, hostPrefix(e.Source))
		if e.DSCP != 0 {
			fmt.Fprintf(b, " match dscp %d\n", e.DSCP)
		}
		fmt.Fprintf(b, " set nexthop %s\nexit\n", e.NextHop)
	}
	b.WriteString("!\n! Apply it on the interface that faces the probe host:\n")
	b.WriteString("! interface <probe-facing-interface>\n!  pbr-policy PACKETEER\n")
	return nil
}

func genJunos(b *strings.Builder, entries []Entry) error {
	if err := routerEntries(entries); err != nil {
		return err
	}
	b.WriteString("# Packeteer probe policy routing for Junos filter-based forwarding.\n")
	b.WriteString("# Generated for review. Nothing is applied. The next hops must be in inet.0 / inet6.0.\n")
	for _, e := range entries {
		fam := pick(e.Source, "inet", "inet6")
		dscp := pick(e.Source, "dscp", "traffic-class")
		action := pick(e.Source, "next-ip", "next-ip6")
		prefix := fmt.Sprintf("set firewall family %s filter PACKETEER-PROBES term %s", fam, e.Ident())
		fmt.Fprintf(b, "%s from source-address %s\n", prefix, hostPrefix(e.Source))
		if e.DSCP != 0 {
			fmt.Fprintf(b, "%s from %s %d\n", prefix, dscp, e.DSCP)
		}
		fmt.Fprintf(b, "%s then %s %s\n", prefix, action, e.NextHop)
	}
	have4, have6 := families(entries)
	for _, fam := range []string{"inet", "inet6"} {
		if (fam == "inet" && !have4) || (fam == "inet6" && !have6) {
			continue
		}
		fmt.Fprintf(b, "set firewall family %s filter PACKETEER-PROBES term rest then accept\n", fam)
		fmt.Fprintf(b, "# Apply it: set interfaces <probe-facing-interface> unit 0 family %s filter input PACKETEER-PROBES\n", fam)
	}
	return nil
}

func genCisco(b *strings.Builder, entries []Entry) error {
	if err := routerEntries(entries); err != nil {
		return err
	}
	b.WriteString("! Packeteer probe policy routing for Cisco IOS / IOS XE. Generated for review.\n")
	b.WriteString("! Nothing is applied.\n")
	for _, e := range entries {
		v4 := e.Source.Is4()
		acl := "ACL-" + e.Ident()
		dscp := ""
		if e.DSCP != 0 {
			dscp = fmt.Sprintf(" dscp %d", e.DSCP)
		}
		if v4 {
			fmt.Fprintf(b, "!\nip access-list extended %s\n permit ip host %s any%s\n", acl, e.Source, dscp)
			fmt.Fprintf(b, "route-map PACKETEER-PROBES permit %d\n match ip address %s\n set ip next-hop %s\n", e.N, acl, e.NextHop)
		} else {
			fmt.Fprintf(b, "!\nipv6 access-list %s\n permit ipv6 host %s any%s\n", acl, e.Source, dscp)
			fmt.Fprintf(b, "route-map PACKETEER-PROBES permit %d\n match ipv6 address %s\n set ipv6 next-hop %s\n", e.N, acl, e.NextHop)
		}
	}
	b.WriteString("!\n! Apply it on the interface that faces the probe host:\n! interface <probe-facing-interface>\n")
	have4, have6 := families(entries)
	if have4 {
		b.WriteString("!  ip policy route-map PACKETEER-PROBES\n")
	}
	if have6 {
		b.WriteString("!  ipv6 policy route-map PACKETEER-PROBES\n")
	}
	return nil
}

func genMikroTik(b *strings.Builder, entries []Entry) error {
	if err := routerEntries(entries); err != nil {
		return err
	}
	b.WriteString("# Packeteer probe policy routing for RouterOS 7. Generated for review.\n")
	b.WriteString("# Nothing is applied.\n")
	for _, e := range entries {
		ip := pick(e.Source, "/ip", "/ipv6")
		id := e.Ident()
		fmt.Fprintf(b, "\n/routing table add name=%s fib\n", id)
		fmt.Fprintf(b, "%s route add dst-address=%s gateway=%s routing-table=%s\n", ip, defaultRoute(e.NextHop), e.NextHop, id)
		if e.DSCP != 0 {
			fmt.Fprintf(b, "%s firewall mangle add chain=prerouting src-address=%s dscp=%d action=mark-routing new-routing-mark=%s passthrough=no\n",
				ip, hostPrefix(e.Source), e.DSCP, id)
			continue
		}
		fmt.Fprintf(b, "/routing rule add src-address=%s action=lookup-only-in-table table=%s\n", hostPrefix(e.Source), id)
	}
	return nil
}
