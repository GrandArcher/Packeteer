package httpapi

import (
	"net/http"
	"sort"
)

// Setup is what the dashboard needs to know about the loaded config to
// explain a first run (#49). It holds no secrets and nothing that could
// change routing.
type Setup struct {
	// Sources are the configured target source types, in config order.
	Sources []string
	// MaxImprovements is the cap on active improvements.
	MaxImprovements int
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
}

// ProviderHealth counts one provider's latest probe results.
type ProviderHealth struct {
	Name      string `json:"name"`
	Up        bool   `json:"up"`
	Excluded  bool   `json:"excluded,omitempty"`
	OK        int    `json:"ok"`
	Failed    int    `json:"failed"`
	LastError string `json:"last_error,omitempty"`
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
	Counts    OverviewCounts   `json:"counts"`
	BGP       OverviewBGP      `json:"bgp"`
	Features  []Feature        `json:"features"`
	Setup     []Hint           `json:"setup"`
}

// OverviewCounts are the headline numbers.
type OverviewCounts struct {
	ProvidersUp     int `json:"providers_up"`
	Providers       int `json:"providers"`
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
	return BuildOverview(snap, *s.setup.Load(), features)
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
	}
	for _, p := range snap.Peers {
		if p.Established {
			out.BGP.Established++
		}
	}
	health := map[string]*ProviderHealth{}
	for _, p := range snap.Providers {
		out.Providers = append(out.Providers, ProviderHealth{Name: p.Name, Up: p.Up, Excluded: p.Exclude})
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
			h := health[p.Provider]
			if p.OK {
				measured = true
			}
			if h == nil {
				continue
			}
			if p.OK {
				h.OK++
			} else {
				h.Failed++
				if p.Error != "" {
					h.LastError = p.Error
				}
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
	out.Setup = setupHints(out)
	return out
}

// setupHints is the first-run checklist, most urgent first. An empty list
// means the instance is measuring, has a RIB view, and keeps history.
func setupHints(o Overview) []Hint {
	var h []Hint
	add := func(id, level, title, detail, doc string) {
		h = append(h, Hint{ID: id, Level: level, Title: title, Detail: detail, Doc: doc})
	}
	if !o.Started {
		add("starting", HintInfo, "Starting",
			"The controller is still starting. This page fills in after the first probe round.", "")
	}
	if len(o.Sources) == 0 {
		add("sources", HintTodo, "Nothing to probe yet",
			"Add a sources: entry to the mounted config file: a static list of prefixes you send traffic to, or the flow source fed by your router's NetFlow/IPFIX/sFlow. Restart the container to apply.",
			"docs/CONFIG.md#source-static")
	} else if o.Started && o.Counts.Prefixes == 0 {
		add("first-round", HintInfo, "Waiting for the first probe round",
			"Sources are configured but nothing has been measured yet. The first round starts at once; a flow source lists prefixes only after it has seen traffic.",
			"docs/CONFIG.md#probe")
	}
	if o.Counts.Providers > 0 && o.Counts.ProvidersUp == 0 {
		add("providers-down", HintWarn, "Every provider is down",
			"No probe source works. Check that each providers[].source_ip is an address on this host (run the container with --network host) and that the container has --cap-add NET_RAW.",
			"docs/policy-routing.md")
	}
	for _, p := range o.Providers {
		if p.Up && p.OK == 0 && p.Failed > 0 {
			detail := "Every probe through this provider failed."
			if p.LastError != "" {
				detail += " Last error: " + p.LastError + "."
			}
			detail += " Check its source_ip and that traffic from it leaves through this provider (policy routing)."
			add("provider-"+p.Name, HintWarn, "No answer through "+p.Name, detail, "docs/policy-routing.md")
		}
	}
	switch {
	case !o.BGP.Configured:
		add("bgp", HintInfo, "No edge router session",
			"Providers are ranked, but the current exit of each prefix is unknown and nothing could ever be injected. Add bgp.neighbors for a learn-only iBGP session to your edge router.",
			"docs/routers.md")
	case o.BGP.Established == 0:
		add("bgp-down", HintWarn, "No iBGP session is established",
			"bgp.neighbors is set but no session is up, so the RIB view is empty and the instance is not ready. Check the router's neighbor config, the AS number, and that TCP port 179 is reachable.",
			"docs/routers.md")
	case o.Counts.Measured > 0 && o.Counts.InRIB == 0:
		add("rib", HintWarn, "No probed prefix is in the learned RIB",
			"The edge router does not advertise any probed prefix exactly. Probe the exact prefixes your edge learns; only those can be compared with the current exit or ever be steered.",
			"docs/CONFIG.md#source-static")
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
			"docs/CONFIG.md#storage-sqlite")
	}
	order := map[string]int{HintTodo: 0, HintWarn: 1, HintInfo: 2}
	sort.SliceStable(h, func(i, j int) bool { return order[h[i].Level] < order[h[j].Level] })
	return nz(h)
}
