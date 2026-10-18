package httpapi

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/internal/syshealth"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Component states on the System page. idle is a component that is
// configured but has nothing to do or nothing to report yet (an announcer
// in observe, a notifier that has not fired); it is not a fault.
const (
	StateOK       = "ok"
	StateDegraded = "degraded"
	StateDown     = "down"
	StateIdle     = "idle"
)

// Component kinds, in the order the page lists them.
const (
	KindVersion     = "version"
	KindHA          = "ha"
	KindBGP         = "bgp_session"
	KindRIBSource   = "rib_source"
	KindProbeSource = "probe_source"
	KindProber      = "prober"
	KindSource      = "source"
	KindScorer      = "scorer"
	KindAnnouncer   = "announcer"
	KindStorage     = "storage"
	KindNotifier    = "notifier"
	KindTelemetry   = "telemetry"
	KindFederation  = "federation_peer"
)

// Component is one row of the System page. Since is when the state last
// changed, for the components that record it; Error is the last error.
type Component struct {
	Kind   string     `json:"kind"`
	Name   string     `json:"name"`
	Type   string     `json:"type,omitempty"`
	State  string     `json:"state"`
	Since  *time.Time `json:"since,omitempty"`
	Error  string     `json:"error,omitempty"`
	Detail string     `json:"detail,omitempty"`
}

// SystemSummary counts components by state. The overview tile shows it.
type SystemSummary struct {
	Total    int `json:"total"`
	OK       int `json:"ok"`
	Degraded int `json:"degraded"`
	Down     int `json:"down"`
	Idle     int `json:"idle"`
}

// System is the body of GET /api/system.
type System struct {
	meta
	Summary    SystemSummary `json:"summary"`
	Components []Component   `json:"components"`
}

// PluginFact names one configured plugin instance.
type PluginFact struct {
	Name string
	Type string
}

// SourceFact is a target source and the outcome of its latest call. Seen
// is false until it has answered once.
type SourceFact struct {
	PluginFact
	Seen    bool
	Targets int
	Err     string
	Since   time.Time
}

// StorageFact is the storage plugin and its latest write. Last is nil
// until something was written.
type StorageFact struct {
	PluginFact
	Last *syshealth.Outcome
}

// NotifierFact is a notifier and its latest delivery. Last is nil until
// one was attempted.
type NotifierFact struct {
	PluginFact
	Last *syshealth.Outcome
}

// RIBSourceFact is a RIB source (BMP) and the routers whose monitoring
// session it has seen, by router address.
type RIBSourceFact struct {
	PluginFact
	Routers map[string]syshealth.Outcome
}

// TelemetryFact is a telemetry plugin and its latest poll. Err is the
// first binding error, or the snapshot error.
type TelemetryFact struct {
	PluginFact
	Bindings int
	Err      string
	Polled   time.Time
}

// SystemFacts is what the controller knows about its configured plugins
// and their latest results. Everything else on the page comes from the
// snapshot, the elector, and the federation view. It holds no secrets and
// the page changes nothing.
type SystemFacts struct {
	Probers    []PluginFact
	Sources    []SourceFact
	Scorer     *PluginFact
	Announcer  *PluginFact
	Storage    *StorageFact
	Notifiers  []NotifierFact
	Telemetry  []TelemetryFact
	RIBSources []RIBSourceFact
}

func (s *Server) handleSystem(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.system(s.snapshot()))
}

func (s *Server) system(snap Snapshot) System {
	var facts SystemFacts
	if s.sysFacts != nil {
		facts = s.sysFacts()
	}
	var ha *plugin.ElectorStatus
	if s.ha != nil {
		st := s.ha()
		ha = &st
	}
	var fed *federation.Status
	if s.federation != nil {
		st := s.federation()
		fed = &st
	}
	return BuildSystem(snap, facts, ha, fed)
}

// BuildSystem is pure: it turns a snapshot, the plugin facts, the elector
// status (nil without ha), and the federation view (nil when standalone)
// into one row per component.
func BuildSystem(snap Snapshot, facts SystemFacts, ha *plugin.ElectorStatus, fed *federation.Status) System {
	snap.zeroNil()
	var rows []Component
	add := func(c Component) { rows = append(rows, c) }

	add(Component{Kind: KindVersion, Name: "packeteer", State: StateOK, Detail: snap.Version + ", mode " + snap.Mode})
	add(haRow(ha))
	rows = append(rows, bgpRows(snap)...)
	for _, src := range facts.RIBSources {
		add(ribSourceRow(src))
	}
	for _, p := range snap.Providers {
		add(probeSourceRow(p))
	}
	for _, p := range facts.Probers {
		add(proberRow(p, snap))
	}
	for _, src := range facts.Sources {
		add(sourceRow(src))
	}
	if facts.Scorer != nil {
		add(Component{Kind: KindScorer, Name: facts.Scorer.Name, Type: facts.Scorer.Type, State: StateOK})
	}
	add(announcerRow(facts.Announcer, snap, ha))
	add(storageRow(facts.Storage))
	for _, n := range facts.Notifiers {
		add(notifierRow(n))
	}
	for _, t := range facts.Telemetry {
		add(telemetryRow(t))
	}
	rows = append(rows, federationRows(fed)...)

	out := System{meta: snap.meta(), Components: rows}
	for i := range out.Components {
		c := &out.Components[i]
		c.Error = redactURLs(c.Error)
		c.Detail = redactURLs(c.Detail)
		out.Summary.Total++
		switch c.State {
		case StateOK:
			out.Summary.OK++
		case StateDegraded:
			out.Summary.Degraded++
		case StateDown:
			out.Summary.Down++
		default:
			out.Summary.Idle++
		}
	}
	return out
}

func ptrTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

func haRow(ha *plugin.ElectorStatus) Component {
	if ha == nil {
		return Component{Kind: KindHA, Name: "role", State: StateOK, Detail: "active (single instance, no ha configured)"}
	}
	c := Component{Kind: KindHA, Name: ha.ID, Type: ha.Type, State: StateOK, Since: ptrTime(ha.Since),
		Detail: ha.Role + ", takeovers " + fmt.Sprint(ha.Takeovers)}
	if ha.Holder != "" {
		c.Detail += ", lease held by " + ha.Holder
	}
	switch {
	case !ha.Eligible:
		c.State, c.Error = StateDegraded, ha.Detail
	case ha.Role == plugin.RoleStandby && ha.Holder == "":
		c.State, c.Error = StateDegraded, "standby and nobody holds the lease"
		if ha.Detail != "" {
			c.Error += ": " + ha.Detail
		}
	case ha.Detail != "":
		c.Detail += ". " + ha.Detail
	}
	return c
}

func bgpRows(snap Snapshot) []Component {
	if !snap.BGPConfigured {
		return []Component{{Kind: KindBGP, Name: "iBGP", State: StateIdle, Detail: "no bgp.neighbors: the current exit of a prefix is unknown"}}
	}
	var rows []Component
	for _, p := range snap.Peers {
		c := Component{Kind: KindBGP, Name: p.Address, State: StateOK, Since: ptrTime(p.Since), Detail: p.State}
		if p.Description != "" {
			c.Detail = p.Description + ", " + p.State
		}
		if p.AddPath {
			c.Detail += ", add-path"
		}
		if !p.Established {
			c.State, c.Error = StateDown, "session is "+p.State+", not established"
		}
		rows = append(rows, c)
	}
	return rows
}

func ribSourceRow(src RIBSourceFact) Component {
	c := Component{Kind: KindRIBSource, Name: src.Name, Type: src.Type}
	if len(src.Routers) == 0 {
		c.State, c.Detail = StateDegraded, "no router has reported a BGP peer yet"
		return c
	}
	var up, down int
	var since time.Time
	var errs []string
	for _, router := range slices.Sorted(maps.Keys(src.Routers)) {
		o := src.Routers[router]
		if o.OK {
			up++
		} else {
			down++
			errs = append(errs, router+": "+o.Err)
		}
		if since.IsZero() || o.Since.After(since) {
			since = o.Since
		}
	}
	c.Since = ptrTime(since)
	c.Detail = fmt.Sprintf("%d routers up, %d down", up, down)
	switch {
	case up == 0:
		c.State = StateDown
	case down > 0:
		c.State = StateDegraded
	default:
		c.State = StateOK
	}
	c.Error = strings.Join(errs, "; ")
	return c
}

func probeSourceRow(p Provider) Component {
	c := Component{Kind: KindProbeSource, Name: p.Name, State: StateOK, Since: ptrTime(p.Since)}
	switch {
	case p.Up:
		c.Detail = "probe source address usable"
	case p.Domain != "" && strings.HasPrefix(p.Reason, ReasonMeasuredByPeer):
		c.State, c.Detail = StateIdle, p.Reason
	case p.Reason == ReasonStarting:
		c.State, c.Detail = StateIdle, ReasonStarting
	default:
		c.State, c.Error = StateDown, p.Reason
	}
	if p.Exclude {
		c.Detail = strings.TrimSpace(c.Detail + " (excluded from improvements)")
	}
	return c
}

// proberRow judges a prober from the latest probe results of providers
// whose probe source is up. A result names the prober that measured it,
// and an error lists "name: message" for each prober that failed.
func proberRow(p PluginFact, snap Snapshot) Component {
	c := Component{Kind: KindProber, Name: p.Name, Type: p.Type}
	up := map[string]bool{}
	for _, pr := range snap.Providers {
		up[pr.Name] = pr.Up
	}
	var answered, failed int
	for _, pb := range snap.Probes {
		if !up[pb.Provider] {
			continue
		}
		if pb.OK && pb.Prober == p.Name {
			answered++
		}
		for _, line := range strings.Split(pb.Error, "\n") {
			if msg, ok := strings.CutPrefix(line, p.Name+": "); ok {
				failed++
				c.Error = msg
			}
		}
	}
	switch {
	case answered > 0:
		c.State, c.Detail, c.Error = StateOK, fmt.Sprintf("measured %d provider paths", answered), ""
	case failed > 0:
		c.State = StateDown
	default:
		c.State, c.Detail = StateIdle, "no probe has used this prober yet, or an earlier prober in the chain answered"
	}
	return c
}

func sourceRow(src SourceFact) Component {
	c := Component{Kind: KindSource, Name: src.Name, Type: src.Type}
	switch {
	case !src.Seen:
		c.State, c.Detail = StateIdle, "not called yet"
	case src.Err != "":
		c.State, c.Error, c.Since = StateDown, src.Err, ptrTime(src.Since)
	default:
		c.State, c.Since = StateOK, ptrTime(src.Since)
		c.Detail = fmt.Sprintf("%d targets", src.Targets)
	}
	return c
}

// announcerRow says whether the announcer may announce in this mode. It
// reads state only: the announcer is bound, and routes are withdrawn, by
// the controller.
func announcerRow(a *PluginFact, snap Snapshot, ha *plugin.ElectorStatus) Component {
	c := Component{Kind: KindAnnouncer, Name: "announcer", State: StateIdle}
	if a != nil {
		c.Name, c.Type = a.Name, a.Type
	}
	switch {
	case snap.Mode != "inject":
		c.Detail = "announces nothing in " + snap.Mode + " mode"
	case a == nil:
		c.State, c.Error = StateDown, "mode is inject but no announcer is configured"
	case ha != nil && ha.Role == plugin.RoleStandby:
		c.Detail = "announces nothing while this instance is standby"
	case !snap.RIBReady:
		c.State, c.Error = StateDegraded, "no iBGP session is established: injected routes are withdrawn"
	default:
		c.State = StateOK
		c.Detail = "may announce allowlisted prefixes that are in the learned RIB"
	}
	return c
}

func storageRow(s *StorageFact) Component {
	if s == nil {
		return Component{Kind: KindStorage, Name: "storage", State: StateIdle,
			Detail: "no storage plugin: report history is off and events stay in memory"}
	}
	c := Component{Kind: KindStorage, Name: s.Name, Type: s.Type, State: StateIdle, Detail: "no write yet"}
	if o := s.Last; o != nil {
		c.Since = ptrTime(o.Since)
		if o.OK {
			c.State, c.Detail = StateOK, "last write "+o.At.Format(time.RFC3339)
		} else {
			c.State, c.Detail, c.Error = StateDown, "last write failed "+o.At.Format(time.RFC3339), o.Err
		}
	}
	return c
}

func notifierRow(n NotifierFact) Component {
	c := Component{Kind: KindNotifier, Name: n.Name, Type: n.Type, State: StateIdle, Detail: "no delivery yet"}
	if o := n.Last; o != nil {
		c.Since = ptrTime(o.Since)
		if o.OK {
			c.State, c.Detail = StateOK, "last delivery "+o.At.Format(time.RFC3339)
		} else {
			c.State, c.Detail, c.Error = StateDown, "last delivery failed "+o.At.Format(time.RFC3339), o.Err
		}
	}
	return c
}

func telemetryRow(t TelemetryFact) Component {
	c := Component{Kind: KindTelemetry, Name: t.Name, Type: t.Type, State: StateOK}
	c.Detail = fmt.Sprintf("%d interface bindings", t.Bindings)
	if !t.Polled.IsZero() {
		c.Detail += ", last poll " + t.Polled.UTC().Format(time.RFC3339)
	}
	if t.Err != "" {
		c.State, c.Error = StateDown, t.Err
	}
	return c
}

func federationRows(fed *federation.Status) []Component {
	if fed == nil || !fed.Enabled {
		return []Component{{Kind: KindFederation, Name: "federation", State: StateIdle, Detail: "standalone: no federation configured"}}
	}
	var rows []Component
	for _, p := range fed.Peers {
		c := Component{Kind: KindFederation, Name: p.Name, State: StateOK, Detail: "snapshot is fresh"}
		if !p.LastSeen.IsZero() {
			c.Detail += ", last seen " + p.LastSeen.UTC().Format(time.RFC3339)
		}
		if !p.Fresh {
			c.State, c.Detail, c.Error = StateDown, "snapshot is stale", p.Error
			if p.LastSeen.IsZero() {
				c.Detail = "never seen"
			}
		}
		rows = append(rows, c)
	}
	if len(rows) == 0 {
		rows = append(rows, Component{Kind: KindFederation, Name: "federation", State: StateIdle, Detail: "enabled with no peers"})
	}
	return rows
}

// urlPattern matches a URL up to the next space or quote. Errors from
// webhooks, federation peers, and storage can carry one, and the path or
// query of a hook URL is a credential.
var urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"']+`)

// redactURLs keeps only scheme and host of every URL in s.
func redactURLs(s string) string {
	return urlPattern.ReplaceAllStringFunc(s, func(m string) string {
		if u, err := url.Parse(m); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
		scheme, _, _ := strings.Cut(m, "://")
		return scheme + "://"
	})
}
