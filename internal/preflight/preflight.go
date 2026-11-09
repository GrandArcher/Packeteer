// Package preflight runs the checks that must pass before the setup wizard
// offers to turn injection on (#221). A check reads facts the controller
// gathers from the running process (sessions, RIB size, probe paths, timers,
// the leak watch) and returns a plain-language result with a fix. Nothing
// here announces, probes, or writes config: Packeteer in observe mode
// announces nothing, so the checks that need the router's own filters are
// confirmed by an administrator after they read the router.
package preflight

import (
	"fmt"
	"strings"
	"time"
)

// Status is the outcome of one check.
type Status string

// Check outcomes. Fail and Unverified block injection from the editor;
// Warn does not.
const (
	Pass       Status = "pass"
	Warn       Status = "warn"
	Fail       Status = "fail"
	Unverified Status = "unverified"
)

// Check ids.
const (
	CheckSession    = "bgp_session"
	CheckFilters    = "import_filter"
	CheckEgress     = "probe_egress"
	CheckTimers     = "timers"
	CheckWithdrawal = "withdrawal"
)

// MaxHoldTime is the longest negotiated hold time the timers check accepts
// without a warning. After a crash a router keeps Packeteer's routes for up
// to this long.
const MaxHoldTime = 180 * time.Second

// MinLearned is the learned prefix count below which the session check warns
// that the table looks too small to be a full edge feed.
const MinLearned = 10

// Result is one check's outcome. Fix is set unless the check passed.
type Result struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
	// Confirmable is true when an administrator can confirm the check after
	// reading the router. Only a check that has no failing evidence is.
	Confirmable bool `json:"confirmable,omitempty"`
}

// Blocking reports whether the result keeps injection off.
func (r Result) Blocking() bool { return r.Status == Fail || r.Status == Unverified }

// Report is one run of every check.
type Report struct {
	RanAt   time.Time `json:"ran_at"`
	Ready   bool      `json:"ready"`
	Results []Result  `json:"results"`
}

// Blocking lists the ids of the checks that keep injection off.
func (r Report) Blocking() []string {
	var ids []string
	for _, res := range r.Results {
		if res.Blocking() {
			ids = append(ids, res.ID)
		}
	}
	return ids
}

// Neighbor is one configured iBGP neighbor.
type Neighbor struct {
	Address     string
	Established bool
}

// Timers is what one established session negotiated.
type Timers struct {
	Address  string
	Hold     time.Duration
	LocalGR  bool
	RouterGR bool
}

// Egress is the outcome of the first-hop check of one provider's probe path.
type Egress string

// Egress outcomes.
const (
	EgressOK        Egress = "ok"
	EgressMismatch  Egress = "mismatch"
	EgressNoReply   Egress = "no_reply"
	EgressUnchecked Egress = "unchecked"
)

// Provider is one provider measured from this instance.
type Provider struct {
	Name     string
	SourceIP string
	NextHop  string
	Egress   Egress
	// FirstHop is the address that answered the TTL-limited probe, when one did.
	FirstHop string
	// Why says why the path is unchecked, or the error of a failed check.
	Why string
}

// Confirmation is an administrator's confirmation of a check that needs a
// look at the router.
type Confirmation struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

// Facts is everything the checks read.
type Facts struct {
	Neighbors []Neighbor
	// RIBReady is false until the learned view finished its first load.
	RIBReady bool
	Learned  int
	// Timers has one entry per established session; TimersErr is set when
	// the speaker could not be read.
	Timers    []Timers
	TimersErr string
	Providers []Provider
	// Community is packeteer_community as written in the config.
	Community string
	// Announcer is true when an announcer plugin is configured.
	Announcer bool
	// Leaks is the number of prefixes the leak watch holds out because a
	// Packeteer route was seen outside the AS.
	Leaks int
	// Fingerprint identifies the setup the confirmations were made for: the
	// AS number, the community, and the neighbors.
	Fingerprint string
	// Confirmed holds the confirmations that still apply to this config.
	Confirmed map[string]Confirmation
}

// Run evaluates every check against f.
func Run(f Facts, now time.Time) Report {
	rep := Report{RanAt: now.UTC(), Results: []Result{
		session(f), filters(f), egress(f), timers(f), withdrawal(f),
	}}
	rep.Ready = len(rep.Blocking()) == 0
	return rep
}

// Confirmable lists the check ids an administrator may confirm.
func Confirmable() []string { return []string{CheckFilters} }

func session(f Facts) Result {
	r := Result{ID: CheckSession, Title: "BGP session and learned routes"}
	if len(f.Neighbors) == 0 {
		r.Status = Fail
		r.Detail = "No BGP neighbor is configured."
		r.Fix = "Add your edge router under bgp.neighbors (wizard step 1) and put the session snippet from Router snippets on the router. Packeteer learns routes from it over iBGP."
		return r
	}
	var down []string
	for _, n := range f.Neighbors {
		if !n.Established {
			down = append(down, n.Address)
		}
	}
	switch {
	case len(down) > 0:
		r.Status = Fail
		r.Detail = "Not established: " + strings.Join(down, ", ") + "."
		r.Fix = "On the router, add a neighbor for Packeteer's router_id with the same AS number as yours, and allow TCP 179 between them. Router snippets has the session lines for your vendor."
	case !f.RIBReady:
		r.Status = Fail
		r.Detail = "The session is up and the first routes are still loading."
		r.Fix = "Wait a minute and run the checks again."
	case f.Learned == 0:
		r.Status = Fail
		r.Detail = fmt.Sprintf("%d session(s) established, but no routes learned.", len(f.Neighbors))
		r.Fix = "The router sends Packeteer nothing. Check its export policy toward Packeteer: it must send the routes you want measured (normally the best path of the full table)."
	case f.Learned < MinLearned:
		r.Status = Warn
		r.Detail = fmt.Sprintf("%d session(s) established, only %d prefixes learned.", len(f.Neighbors), f.Learned)
		r.Fix = fmt.Sprintf("Fewer than %d prefixes is fine for a lab. On a real edge it usually means the router sends only a default route or a filter hides the table.", MinLearned)
	default:
		r.Status = Pass
		r.Detail = fmt.Sprintf("%d session(s) established, %d prefixes learned.", len(f.Neighbors), f.Learned)
	}
	return r
}

func filters(f Facts) Result {
	r := Result{ID: CheckFilters, Title: "Router filters keep Packeteer routes inside your AS"}
	community := f.Community
	if community == "" {
		community = "your packeteer_community"
	}
	if f.Leaks > 0 {
		r.Status = Fail
		r.Detail = fmt.Sprintf("The leak watch holds %d prefix(es): a Packeteer route was seen outside your AS.", f.Leaks)
		r.Fix = "Reject " + community + " in the outbound policy of every eBGP neighbor, then clear the held prefixes on the Leaks page."
		return r
	}
	if c, ok := f.Confirmed[CheckFilters]; ok {
		r.Status = Pass
		r.Detail = fmt.Sprintf("Confirmed by %s at %s. Packeteer cannot read the router's filters in observe mode.", c.By, c.At.UTC().Format(time.RFC3339))
		return r
	}
	r.Status = Unverified
	r.Confirmable = true
	r.Detail = "Packeteer announces nothing in observe mode, so it cannot test the router's filters itself."
	r.Fix = "On the router, check that (1) the import policy from Packeteer accepts only routes carrying " + community + " and rejects everything else, and (2) the outbound policy of every eBGP neighbor, customers included, rejects " + community + ". Router snippets has both for your vendor. Then press Confirm."
	return r
}

func egress(f Facts) Result {
	r := Result{ID: CheckEgress, Title: "Probes leave through the intended provider"}
	if len(f.Providers) == 0 {
		r.Status = Fail
		r.Detail = "No provider is measured from this instance."
		r.Fix = "Add a provider with its probe source_ip and next_hop (wizard step 2)."
		return r
	}
	var lines []string
	worst := Pass
	for _, p := range f.Providers {
		switch p.Egress {
		case EgressOK:
			lines = append(lines, fmt.Sprintf("%s: probes from %s left through %s.", p.Name, p.SourceIP, p.NextHop))
		case EgressMismatch:
			worst = Fail
			lines = append(lines, fmt.Sprintf("%s: probes from %s left through %s, expected %s.", p.Name, p.SourceIP, p.FirstHop, p.NextHop))
		case EgressNoReply:
			worst = Fail
			lines = append(lines, fmt.Sprintf("%s: probes from %s got no answer from %s (%s).", p.Name, p.SourceIP, p.NextHop, p.Why))
		default:
			if worst == Pass {
				worst = Warn
			}
			lines = append(lines, fmt.Sprintf("%s: not verified (%s).", p.Name, p.Why))
		}
	}
	r.Status = worst
	r.Detail = strings.Join(lines, "\n")
	switch worst {
	case Fail:
		r.Fix = "Make traffic from each provider's source_ip leave through that provider's next_hop. `packeteer -pbr linux` prints the ip rule and ip route lines; `packeteer -pbr linux -apply` shows a diff and applies them. Behind a router, `-pbr` also prints its policy routing."
	case Warn:
		r.Fix = "Check these by hand: traceroute -s <source_ip> <host> must show the provider's next_hop as the first hop."
	}
	return r
}

func timers(f Facts) Result {
	r := Result{ID: CheckTimers, Title: "Hold time and graceful restart"}
	if f.TimersErr != "" {
		r.Status = Fail
		r.Detail = "The session timers could not be read: " + f.TimersErr + "."
		r.Fix = "Run the checks again once the session is established."
		return r
	}
	if len(f.Timers) == 0 {
		r.Status = Fail
		r.Detail = "No session is established, so its timers are unknown."
		r.Fix = "Bring the BGP session up first."
		return r
	}
	status := Pass
	var lines, fixes []string
	for _, t := range f.Timers {
		switch {
		case t.LocalGR:
			status = Fail
			lines = append(lines, t.Address+": graceful restart is on for the Packeteer session.")
			fixes = append(fixes, "Packeteer never enables graceful restart; a stale router keeps its routes after a crash. Restart Packeteer and report this.")
		case t.Hold == 0:
			status = Fail
			lines = append(lines, t.Address+": the hold timer is off.")
			fixes = append(fixes, "With no hold timer the router keeps Packeteer's routes after a crash until someone notices. Set hold time 90 and keepalive 30 on the router's neighbor for Packeteer.")
		case t.Hold > MaxHoldTime:
			if status == Pass {
				status = Warn
			}
			lines = append(lines, fmt.Sprintf("%s: hold time %s.", t.Address, t.Hold))
			fixes = append(fixes, fmt.Sprintf("After a crash the router keeps Packeteer's routes for %s. Set the hold time on the router's neighbor for Packeteer to %s or less (90 is usual).", t.Hold, MaxHoldTime))
		case t.RouterGR:
			lines = append(lines, fmt.Sprintf("%s: hold time %s. The router offers graceful restart, which does nothing here because Packeteer does not.", t.Address, t.Hold))
		default:
			lines = append(lines, fmt.Sprintf("%s: hold time %s, graceful restart off.", t.Address, t.Hold))
		}
	}
	r.Status = status
	r.Detail = strings.Join(lines, "\n")
	r.Fix = strings.Join(fixes, "\n")
	return r
}

func withdrawal(f Facts) Result {
	r := Result{ID: CheckWithdrawal, Title: "Routes are withdrawn when Packeteer stops"}
	if !f.Announcer {
		r.Status = Fail
		r.Detail = "No announcer is configured."
		r.Fix = "Add `announcer: {type: gobgp}` to the config. It publishes on the same iBGP session and withdraws everything on shutdown."
		return r
	}
	for _, t := range f.Timers {
		if t.Hold > MaxHoldTime || t.Hold == 0 || t.LocalGR {
			r.Status = Fail
			r.Detail = "Session " + t.Address + " would keep Packeteer's routes after a crash (see the timers check)."
			r.Fix = "Set a hold time between 1 and 180 s and turn graceful restart off for this session on both sides."
			return r
		}
	}
	if len(f.Timers) == 0 {
		r.Status = Fail
		r.Detail = "No session is established, so the crash withdrawal time is unknown."
		r.Fix = "Bring the BGP session up first."
		return r
	}
	var longest time.Duration
	for _, t := range f.Timers {
		longest = max(longest, t.Hold)
	}
	r.Status = Pass
	r.Detail = fmt.Sprintf("An announcer is configured and graceful restart is off. A stopped Packeteer withdraws at once; a crash drops its routes within %s, the longest negotiated hold time. Checked here: configuration and negotiated timers. Not checked: a live test route, which would announce in observe mode.", longest)
	return r
}
