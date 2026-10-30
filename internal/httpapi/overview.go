package httpapi

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/probe"
)

// Setup is what the dashboard needs to know about the loaded config to
// explain a first run (#49). It holds no secrets and nothing that could
// change routing.
type Setup struct {
	// Sources are the configured target source types, in config order.
	Sources []string
	// MaxImprovements is the cap on active improvements.
	MaxImprovements int
	// DegradedLossPct and DownLossPct are probe.degraded_loss_pct and
	// probe.down_loss_pct (#343).
	DegradedLossPct float64
	DownLossPct     float64
	// SynthesizeWarning is config.SynthesizeWarning while synthesize is
	// on (#122), else empty.
	SynthesizeWarning string
	// SimulatedProbes is config.SimulatedProbesNotice while a sim prober
	// is configured (#103), else empty.
	SimulatedProbes string
}

// Hint levels: todo is a step the operator still has to take before the
// dashboard is useful, warn is something that looks broken, info explains.
const (
	HintTodo = "todo"
	HintWarn = "warn"
	HintInfo = "info"
)

// Hint is one line of the dashboard's setup checklist.
type Hint struct {
	ID     string `json:"id"`
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Doc    string `json:"doc,omitempty"`
	// DocURL is Doc under DocBase, for a link (#347).
	DocURL string `json:"doc_url,omitempty"`
	// Fix is the anchor on the Settings page where the config editor
	// changes what the hint is about (#351). The page links to it only
	// when the editor is on.
	Fix string `json:"fix,omitempty"`
}

// Settings page anchors a Hint.Fix may name.
const (
	FixBGP       = "/settings.html#form-bgp"
	FixProviders = "/settings.html#form-providers"
	FixTargets   = "/settings.html#form-targets"
	FixPlugins   = "/settings.html#form-plugins"
)

// Provider health states (#343), derived from what was measured.
const (
	HealthUp       = "up"
	HealthDegraded = "degraded"
	HealthDown     = "down"
	// HealthUnknown is a provider with no probe result yet, or one that a
	// federation peer measures.
	HealthUnknown = "unknown"
)

// ProviderHealth counts one provider's latest probe results. OK counts
// probes that got a reply; Failed counts probes that errored or got none.
// State follows the measured loss, not only whether the probe source runs.
type ProviderHealth struct {
	Name    string  `json:"name"`
	Up      bool    `json:"up"`
	State   string  `json:"state"`
	LossPct float64 `json:"loss_pct"`
	// Detail says why the state is down or degraded.
	Detail    string `json:"detail,omitempty"`
	Excluded  bool   `json:"excluded,omitempty"`
	OK        int    `json:"ok"`
	Failed    int    `json:"failed"`
	LastError string `json:"last_error,omitempty"`

	reason  string
	silent  int
	lossSum float64
}

// Problem is a provider that is down or degraded, for the Overview
// headline.
type Problem struct {
	Provider string `json:"provider"`
	State    string `json:"state"`
	Detail   string `json:"detail"`
}

// Feature is an optional capability and whether this instance has it on.
type Feature struct {
	Name string `json:"name"`
	On   bool   `json:"on"`
}

// Overview is the dashboard's summary: counts, per-provider probe health,
// optional features, and a setup checklist. Read-only.
type Overview struct {
	meta
	Started   bool             `json:"started"`
	Sources   []string         `json:"sources"`
	Providers []ProviderHealth `json:"providers"`
	// Problems lists the down providers, then the degraded ones.
	Problems []Problem      `json:"problems"`
	Counts   OverviewCounts `json:"counts"`
	BGP      OverviewBGP    `json:"bgp"`
	Features []Feature      `json:"features"`
	Setup    []Hint         `json:"setup"`
	// System counts the System page's components by state (#184).
	System SystemSummary `json:"system"`
	// Auth is "rbac", "basic", or "off". The UI warns on off (#328).
	Auth string `json:"auth"`
	// SynthesizeWarning is set while synthesize is on (#122); every page
	// shows it.
	SynthesizeWarning string `json:"synthesize_warning,omitempty"`
	// SimulatedProbes is set while a sim prober is configured (#103);
	// every page shows it so no probe number reads as measured.
	SimulatedProbes string `json:"simulated_probes,omitempty"`
}

// OverviewCounts are the headline numbers.
type OverviewCounts struct {
	ProvidersUp int `json:"providers_up"`
	// ProvidersHealthy counts providers measured up. One with no result
	// yet is neither healthy nor a problem.
	ProvidersHealthy int `json:"providers_healthy"`
	Providers        int `json:"providers"`
	// Warnings is the number of warn-level lines in the setup checklist.
	Warnings        int `json:"warnings"`
	Prefixes        int `json:"prefixes"`
	Measured        int `json:"measured"`
	InRIB           int `json:"in_rib"`
	Recommended     int `json:"recommended"`
	Improvements    int `json:"improvements"`
	MaxImprovements int `json:"max_improvements"`
}

// OverviewBGP summarizes the learn-only iBGP sessions.
type OverviewBGP struct {
	Configured  bool `json:"configured"`
	Ready       bool `json:"ready"`
	Established int  `json:"established"`
	Peers       int  `json:"peers"`
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.overview())
}

func (s *Server) overview() Overview {
	snap := s.snapshot()
	features := []Feature{
		{"history", s.reports != nil},
		{"troubleshoot", s.tools != nil && s.tools.Status().Enabled},
		{"config_editor", s.editor != nil},
		{"dashboards", s.dashboards != nil},
		{"inbound", s.inbound != nil},
		{"mitigation", s.mitigation != nil},
		{"anomaly", s.anomaly != nil},
		{"federation", s.federation != nil && s.federation().Enabled},
		{"ha", s.ha != nil},
	}
	out := BuildOverview(snap, *s.setup.Load(), features)
	out.System = s.system(snap).Summary
	out.Auth = s.authMode()
	return out
}

// BuildOverview is pure: it reads a snapshot, the setup facts, and the
// feature list, and returns the summary and checklist.
func BuildOverview(snap Snapshot, setup Setup, features []Feature) Overview {
	snap.zeroNil()
	out := Overview{
		meta:     snap.meta(),
		Started:  snap.Started,
		Sources:  nz(append([]string(nil), setup.Sources...)),
		Features: nz(features),
		BGP:      OverviewBGP{Configured: snap.BGPConfigured, Ready: snap.RIBReady, Peers: len(snap.Peers)},

		SynthesizeWarning: setup.SynthesizeWarning,
		SimulatedProbes:   setup.SimulatedProbes,
	}
	for _, p := range snap.Peers {
		if p.Established {
			out.BGP.Established++
		}
	}
	health := map[string]*ProviderHealth{}
	for _, p := range snap.Providers {
		out.Providers = append(out.Providers, ProviderHealth{Name: p.Name, Up: p.Up, Excluded: p.Exclude, reason: p.Reason})
	}
	for i := range out.Providers {
		health[out.Providers[i].Name] = &out.Providers[i]
		if out.Providers[i].Up {
			out.Counts.ProvidersUp++
		}
	}
	out.Providers = nz(out.Providers)
	out.Counts.Providers = len(out.Providers)
	for _, pr := range snap.Prefixes {
		out.Counts.Prefixes++
		measured := false
		for _, p := range pr.Probes {
			if h := health[p.Provider]; h != nil {
				h.tally(p.OK, p.Received, p.LossPct, p.Error)
			}
			if p.OK && p.Received > 0 {
				measured = true
			}
		}
		if measured {
			out.Counts.Measured++
		}
		if pr.InRIB {
			out.Counts.InRIB++
		}
		if pr.Current != "" && pr.Recommended != "" && pr.Recommended != pr.Current {
			out.Counts.Recommended++
		}
	}
	out.Counts.Improvements = len(snap.Improvements)
	out.Counts.MaxImprovements = setup.MaxImprovements
	out.Problems = judgeProviders(&out, setup)
	out.Setup = setupHints(out)
	for _, h := range out.Setup {
		if h.Level == HintWarn {
			out.Counts.Warnings++
		}
	}
	return out
}

// tally adds one probe result to the provider's counts. A probe that errored or got no reply counts as full loss.
func (h *ProviderHealth) tally(ok bool, received int, lossPct float64, errText string) {
	switch {
	case ok && received > 0:
		h.OK++
		h.lossSum += lossPct
	case ok:
		h.Failed++
		h.silent++
		h.lossSum += 100
	default:
		h.Failed++
		h.lossSum += 100
		if errText != "" {
			h.LastError = errText
		}
	}
}

// judge sets the provider's loss, state, and detail from its tallies. A
// provider is down when its probe source failed, nothing came back, or its
// mean loss reaches downAt; it is degraded at degradedAt. A provider not
// probed here (starting, or measured by a federation peer) is unknown.
func (h *ProviderHealth) judge(degradedAt, downAt float64) {
	total := h.OK + h.Failed
	if total > 0 {
		h.LossPct = h.lossSum / float64(total)
	}
	h.Detail = ""
	switch {
	case !h.Up && notProbedHere(h.reason):
		h.State = HealthUnknown
	case !h.Up:
		h.State = HealthDown
		h.Detail = "probe source down"
		if h.reason != "" {
			h.Detail += ": " + h.reason
		}
	case total == 0:
		h.State = HealthUnknown
	case h.OK == 0:
		h.State = HealthDown
		h.Detail = "100% loss"
		if h.silent == 0 {
			h.Detail = "no answer"
		}
	case h.LossPct >= downAt:
		h.State = HealthDown
		h.Detail = formatLoss(h.LossPct)
	case h.LossPct >= degradedAt:
		h.State = HealthDegraded
		h.Detail = formatLoss(h.LossPct)
	default:
		h.State = HealthUp
	}
}

// MeasureProviders judges each probe-source status from the latest
// results with the same rules as the Overview (#343), for the events
// (#347). Thresholds are probe.degraded_loss_pct and probe.down_loss_pct.
func MeasureProviders(status []probe.ProviderStatus, results []probe.Result, degradedAt, downAt float64) []ProviderHealth {
	out := make([]ProviderHealth, len(status))
	byName := make(map[string]*ProviderHealth, len(status))
	for i, st := range status {
		out[i] = ProviderHealth{Name: st.Name, Up: st.Up, reason: st.Reason}
		byName[st.Name] = &out[i]
	}
	for _, r := range results {
		if h := byName[r.Provider]; h != nil {
			h.tally(r.OK(), r.Stats.Received, jsonFloat(r.Stats.LossPct), r.Err)
		}
	}
	for i := range out {
		out[i].judge(degradedAt, downAt)
	}
	return out
}

// judgeProviders judges every provider of the overview and returns the
// problems: down ones first, then degraded ones.
func judgeProviders(o *Overview, setup Setup) []Problem {
	problems := []Problem{}
	var degraded []Problem
	for i := range o.Providers {
		h := &o.Providers[i]
		h.judge(setup.DegradedLossPct, setup.DownLossPct)
		switch h.State {
		case HealthDown:
			problems = append(problems, Problem{Provider: h.Name, State: h.State, Detail: h.Detail})
		case HealthDegraded:
			degraded = append(degraded, Problem{Provider: h.Name, State: h.State, Detail: h.Detail})
		case HealthUp:
			o.Counts.ProvidersHealthy++
		}
	}
	return append(problems, degraded...)
}

// notProbedHere is true for the reasons Assemble gives a provider that has
// no probe status without a failure: before the first round, measured by a
// federation peer, or not reported yet.
func notProbedHere(reason string) bool {
	return reason == ReasonStarting || reason == ReasonUnknown || strings.HasPrefix(reason, ReasonMeasuredByPeer)
}

func formatLoss(pct float64) string {
	return strconv.FormatFloat(float64(int(pct*10+0.5))/10, 'f', -1, 64) + "% loss"
}

// setupHints is the first-run checklist, most urgent first. An empty list
// means the instance is measuring, has a RIB view, and keeps history.
func setupHints(o Overview) []Hint {
	var h []Hint
	add := func(id, level, title, detail, doc, fix string) {
		hint := Hint{ID: id, Level: level, Title: title, Detail: detail, Doc: doc, Fix: fix}
		if doc != "" {
			hint.DocURL = DocBase + doc
		}
		h = append(h, hint)
	}
	if !o.Started {
		add("starting", HintInfo, "Starting",
			"The controller is still starting. This page fills in after the first probe round.", "", "")
	}
	if len(o.Sources) == 0 {
		add("sources", HintTodo, "Nothing to probe yet",
			"Add a sources: entry: a static list of prefixes you send traffic to, or the flow source fed by your router's NetFlow/IPFIX/sFlow.",
			"docs/CONFIG.md#source-static", FixTargets)
	} else if o.Started && o.Counts.Prefixes == 0 {
		add("first-round", HintInfo, "Waiting for the first probe round",
			"Sources are configured but nothing has been measured yet. The first round starts at once; a flow source lists prefixes only after it has seen traffic.",
			"docs/CONFIG.md#probe", "")
	}
	if o.Counts.Providers > 0 && o.Counts.ProvidersUp == 0 {
		add("providers-down", HintWarn, "Every provider is down",
			"No probe source works. Check that each providers[].source_ip is an address on this host (run the container with --network host) and that the container has --cap-add NET_RAW.",
			"docs/policy-routing.md", FixProviders)
	}
	for _, p := range o.Providers {
		if p.Up && p.OK == 0 && p.Failed > 0 {
			detail := "Every probe through this provider failed."
			if p.LastError != "" {
				detail += " Last error: " + p.LastError + "."
			}
			detail += " Check its source_ip and that traffic from it leaves through this provider (policy routing)."
			add("provider-"+p.Name, HintWarn, "No answer through "+p.Name, detail, "docs/policy-routing.md", FixProviders)
		}
	}
	switch {
	case !o.BGP.Configured:
		add("bgp", HintInfo, "No edge router session",
			"Providers are ranked, but the current exit of each prefix is unknown and nothing could ever be injected. Add bgp.neighbors for a learn-only iBGP session to your edge router.",
			"docs/routers.md", FixBGP)
	case o.BGP.Established == 0:
		add("bgp-down", HintWarn, "No iBGP session is established",
			"bgp.neighbors is set but no session is up, so the RIB view is empty and the instance is not ready. Check the router's neighbor config, the AS number, and that TCP port 179 is reachable.",
			"docs/routers.md", FixBGP)
	case o.Counts.Measured > 0 && o.Counts.InRIB == 0:
		add("rib", HintWarn, "No probed prefix is in the learned RIB",
			"The edge router does not advertise any probed prefix exactly. Probe the exact prefixes your edge learns; only those can be compared with the current exit or ever be steered.",
			"docs/CONFIG.md#source-static", FixTargets)
	}
	history := false
	for _, f := range o.Features {
		if f.Name == "history" && f.On {
			history = true
		}
	}
	if !history {
		add("history", HintInfo, "Report history is off",
			"Add storage: {type: sqlite} and mount a volume on /var/lib/packeteer to keep reports across restarts.",
			"docs/CONFIG.md#storage-sqlite", FixPlugins)
	}
	order := map[string]int{HintTodo: 0, HintWarn: 1, HintInfo: 2}
	sort.SliceStable(h, func(i, j int) bool { return order[h[i].Level] < order[h[j].Level] })
	return nz(h)
}
