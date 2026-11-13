package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/eventlog"
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
	"steer":           "docs/CONFIG.md#verify",
	"overload":        "docs/CONFIG.md#providers",
	"med":             "docs/CONFIG.md#thresholds",
	"exchange":        "docs/CONFIG.md#exchanges",
	"exchange_peer":   "docs/CONFIG.md#exchanges",
	"exchange_prefix": "docs/CONFIG.md#exchanges",
	"herd":            "docs/herd.md",
	"rpki":            "docs/CONFIG.md#rpki",

	"rpki_only_invalid": "docs/only-invalid.md",
	"rpki_slurm":        "docs/only-invalid.md#slurm-exceptions",

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
// "What to do" link. DedupKey names the alert, for POST /api/alerts/ack;
// Ack is set on a problem event of an acknowledged alert (#558).
type eventRow struct {
	plugin.Event
	Source   string        `json:"source"`
	HelpURL  string        `json:"help_url,omitempty"`
	DedupKey string        `json:"dedup_key"`
	Ack      *eventlog.Ack `json:"ack,omitempty"`
}

// handleEvents lists recent controller events (#173), newest first. With
// open=1 it lists only the open alerts: the newest event of each alert,
// when that event is a problem (#579). It reads the event log and nothing
// else.
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
	open := false
	switch v.Get("open") {
	case "", "0":
	case "1":
		open = true
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "open must be 0 or 1"})
		return
	}
	query := q
	if open {
		// Resolving events are info and may not match q or the floor, so
		// read the whole window and filter once each alert's last state is known.
		query = plugin.EventQuery{From: q.From, To: q.To, Limit: maxEventRows}
	}
	evs, err := s.events.Query(r.Context(), query)
	if err == nil && open {
		evs = openAlerts(evs, q)
	}
	if err != nil {
		s.log.Error("event read", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "event store unavailable"})
		return
	}
	rows := make([]eventRow, len(evs))
	for i, e := range evs {
		rows[i] = eventRow{Event: e, Source: e.Source(), HelpURL: helpURL(e.Kind), DedupKey: e.DedupKey()}
		if a, ok := s.events.AckOf(e); ok {
			rows[i].Ack = &a
		}
	}
	body := map[string]any{"events": rows, "stored": s.events.Stored(), "now": time.Now().UTC(), "doc_base": DocBase}
	if !s.events.Stored() {
		body["since"] = s.events.Started().UTC()
	}
	writeJSON(w, http.StatusOK, body)
}

// openAlerts keeps, from evs (newest first), the events of q whose alert is
// still open: the newest event of its dedup key is not a resolving one. An
// alert that recovered drops out of the badge but stays in the plain list.
func openAlerts(evs []plugin.Event, q plugin.EventQuery) []plugin.Event {
	latest := map[string]bool{}
	var out []plugin.Event
	for _, e := range evs {
		k := e.DedupKey()
		if latest[k] {
			continue
		}
		latest[k] = true
		if e.Resolves() || !q.Match(e) {
			continue
		}
		if out = append(out, e); q.Limit > 0 && len(out) == q.Limit {
			break
		}
	}
	return out
}

// Bounds for POST /api/alerts/ack.
const (
	maxAckKey  = 256
	maxAckNote = 200
)

// handleAlertAck acknowledges an open alert by its dedup key (#558). It
// is a note on the alert: notifications and routing are unchanged.
func (s *Server) handleAlertAck(w http.ResponseWriter, r *http.Request) {
	if !s.steerWritable(w, "acknowledging an alert") {
		return
	}
	if s.events == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the event log is off"})
		return
	}
	var req struct {
		Key  string `json:"key"`
		Note string `json:"note"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Key == "" || len(req.Key) > maxAckKey || len(req.Note) > maxAckNote {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key is required (an event's dedup_key, at most " + strconv.Itoa(maxAckKey) + " bytes); note is at most " + strconv.Itoa(maxAckNote) + " bytes"})
		return
	}
	a, err := s.events.Acknowledge(r.Context(), req.Key, principalFrom(r.Context()).User, req.Note, time.Now())
	switch {
	case errors.Is(err, eventlog.ErrNoAlert):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	case errors.Is(err, eventlog.ErrResolved):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	case err != nil:
		s.log.Error("event read", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "event store unavailable"})
		return
	}
	noteAudit(r, req.Key, "note="+req.Note)
	writeJSON(w, http.StatusOK, a)
}
