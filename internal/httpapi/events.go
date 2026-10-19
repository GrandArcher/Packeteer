package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Bounds for GET /api/events.
const (
	defaultEventRows = 200
	maxEventRows     = 1000
	maxEventText     = 200
)

// DocBase is where the dashboard links documentation. The container image
// carries no docs, so a doc name opens its page in the project repository.
const DocBase = "https://github.com/GrandArcher/Packeteer/blob/main/"

// eventHelp is the next step for each catalog group (#347): a dashboard
// page, or a doc path under DocBase. Every group in the catalog has one.
var eventHelp = map[string]string{
	"bgp":             "/system.html",
	"announce":        "/system.html",
	"controller":      "/system.html",
	"provider":        "docs/troubleshooting.md#probes-fail",
	"improvement":     "docs/operating.md#suggest-then-inject",
	"commit":          "docs/CONFIG.md#scorer-commit",
	"outage":          "docs/troubleshooting.md",
	"notifier":        "docs/EVENTS.md#testing-delivery",
	"inbound":         "docs/inbound.md",
	"mitigation":      "docs/mitigation.md",
	"anomaly":         "docs/anomaly.md",
	"leak":            "docs/leak-watch.md",
	"ha":              "docs/ha.md",
	"audit":           "docs/auth.md#audit-log",
	"flap":            "docs/CONFIG.md#flap_quarantine",
	"exchange":        "docs/CONFIG.md#exchanges",
	"exchange_peer":   "docs/CONFIG.md#exchanges",
	"exchange_prefix": "docs/CONFIG.md#exchanges",
	"herd":            "docs/herd.md",

	"ixp_api_key":         "docs/design/ixp.md",
	"ixp_fabric":          "docs/design/ixp.md",
	"ixp_member":          "docs/design/ixp.md",
	"ixp_rs":              "docs/design/ixp.md",
	"ixp_rs_filtered":     "docs/design/ixp.md",
	"ixp_rs_morespecific": "docs/design/ixp.md",
	"ixp_rs_origin":       "docs/design/ixp.md",
	"ixp_rs_prefix":       "docs/design/ixp.md",
	"ixp_rs_session":      "docs/design/ixp.md",
	"ixp_rs_spike":        "docs/design/ixp.md",
}

// helpURL is the "What to do" link of an event kind: an in-app path, or a
// full URL for a doc. An unknown kind has none.
func helpURL(kind string) string {
	spec, ok := plugin.LookupEvent(kind)
	if !ok {
		return ""
	}
	target := eventHelp[spec.Group]
	if target == "" || strings.HasPrefix(target, "/") {
		return target
	}
	return DocBase + target
}

// eventRow is one event as the Events page shows it. HelpURL is the
// "What to do" link.
type eventRow struct {
	plugin.Event
	Source  string `json:"source"`
	HelpURL string `json:"help_url,omitempty"`
}

// handleEvents lists recent controller events (#173), newest first. It
// reads the event log and nothing else.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.events == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the event log is off"})
		return
	}
	var q plugin.EventQuery
	var ok bool
	if q.Limit, q.From, q.To, ok = parseRowsAndRange(w, r, defaultEventRows, maxEventRows); !ok {
		return
	}
	v := r.URL.Query()
	if sev := v.Get("severity"); sev != "" {
		if _, ok := plugin.SeverityRank(plugin.Severity(sev)); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "severity must be info, warning, or critical"})
			return
		}
		q.MinSeverity = plugin.Severity(sev)
	}
	if q.Text = v.Get("q"); len(q.Text) > maxEventText {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "q must be at most " + strconv.Itoa(maxEventText) + " bytes"})
		return
	}
	evs, err := s.events.Query(r.Context(), q)
	if err != nil {
		s.log.Error("event read", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "event store unavailable"})
		return
	}
	rows := make([]eventRow, len(evs))
	for i, e := range evs {
		rows[i] = eventRow{Event: e, Source: e.Source(), HelpURL: helpURL(e.Kind)}
	}
	body := map[string]any{"events": rows, "stored": s.events.Stored(), "now": time.Now().UTC(), "doc_base": DocBase}
	if !s.events.Stored() {
		body["since"] = s.events.Started().UTC()
	}
	writeJSON(w, http.StatusOK, body)
}
