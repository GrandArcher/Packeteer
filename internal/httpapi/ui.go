package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/subscribe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Remaining UI features (#34): the config editor and first-run wizard
// (admin), custom dashboards (each signed-in user's own), and report
// subscriptions (status for viewers, send-now for operators). None of
// them announces. The editor writes the mounted file only after the same
// checks the controller runs at start, and the running controller does
// not change until it restarts (or SIGHUPs, for bgp.neighbors).

// ConfigEditor is the validated config editor. *configedit.Editor
// implements it. Nil when http.config_editor is off.
type ConfigEditor interface {
	Read() (configedit.File, error)
	Check(data []byte) configedit.Result
	Save(data []byte, base string, confirmInject bool) (configedit.File, configedit.Result, error)
}

// Subscriptions is the report subscription scheduler.
// *subscribe.Scheduler implements it. Nil when none are configured.
type Subscriptions interface {
	Status() []subscribe.Status
	SendNow(ctx context.Context, name string) error
}

// decodeLarge reads a JSON body up to limit bytes with no unknown fields.
func decodeLarge(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "content type must be application/json"})
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("body is larger than %d bytes", limit)})
			return false
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body: one JSON object expected"})
		return false
	}
	return true
}

// ---- Config editor and wizard (admin) ----

// configBodyLimit leaves room for JSON escaping of a MaxSize file.
const configBodyLimit = 3*configedit.MaxSize + 4096

func (s *Server) editorOn(w http.ResponseWriter) bool {
	if s.editor == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the config editor is off (set http.config_editor: true, with auth or basic auth)"})
		return false
	}
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "the config editor needs auth or basic auth"})
		return false
	}
	return true
}

func (s *Server) handleConfig(w http.ResponseWriter, _ *http.Request) {
	if !s.editorOn(w) {
		return
	}
	f, err := s.editor.Read()
	if err != nil {
		s.log.Error("config editor read", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot read the config file"})
		return
	}
	writeJSON(w, http.StatusOK, f)
}

type configRequest struct {
	YAML          string `json:"yaml"`
	Base          string `json:"base"`
	ConfirmInject bool   `json:"confirm_inject"`
}

func (s *Server) handleConfigValidate(w http.ResponseWriter, r *http.Request) {
	if !s.editorOn(w) {
		return
	}
	var req configRequest
	if !decodeLarge(w, r, &req, configBodyLimit) {
		return
	}
	writeJSON(w, http.StatusOK, s.editor.Check([]byte(req.YAML)))
}

func (s *Server) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	if !s.editorOn(w) {
		return
	}
	var req configRequest
	if !decodeLarge(w, r, &req, configBodyLimit) {
		return
	}
	next := configedit.Hash([]byte(req.YAML))
	noteAudit(r, "config", "base="+short(req.Base)+" new="+short(next))
	f, res, err := s.editor.Save([]byte(req.YAML), req.Base, req.ConfirmInject)
	body := map[string]any{"result": res}
	switch {
	case err == nil:
		noteAudit(r, "config", "base="+short(req.Base)+" new="+short(next)+" mode="+res.Mode+" changed="+strings.Join(res.Changed, ","))
		s.log.Warn("config file written through the editor; it applies on restart (or SIGHUP for bgp.neighbors)",
			"user", principalFrom(r.Context()).User, "path", f.Path, "sha256", f.SHA256, "changed", strings.Join(res.Changed, ","))
		body["file"] = f
		writeJSON(w, http.StatusOK, body)
		return
	case errors.Is(err, configedit.ErrConflict):
		body["error"] = err.Error()
		writeJSON(w, http.StatusConflict, body)
	case errors.Is(err, configedit.ErrConfirmInject):
		body["error"] = err.Error()
		writeJSON(w, http.StatusPreconditionRequired, body)
	case errors.Is(err, configedit.ErrInvalid) || !res.Valid:
		body["error"] = configedit.ErrInvalid.Error()
		writeJSON(w, http.StatusUnprocessableEntity, body)
	default:
		s.log.Error("config editor write", "err", err)
		body["error"] = "cannot write the config file (is it mounted read-only?): " + err.Error()
		writeJSON(w, http.StatusInternalServerError, body)
	}
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// handleWizard renders a setup-wizard observe config (#106). It writes
// nothing; the UI shows the result in the editor for review. Inject is
// not accepted. It is part of the editor: off unless http.config_editor
// is on.
func (s *Server) handleWizard(w http.ResponseWriter, r *http.Request) {
	if !s.editorOn(w) {
		return
	}
	var in configedit.WizardInput
	if !decodeLarge(w, r, &in, 256<<10) {
		return
	}
	out, err := configedit.Wizard(in)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "wizard input is invalid", "errors": strings.Split(err.Error(), "\n")})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"yaml": string(out), "mode": "observe", "editor": true})
}

// Suggestion is a next hop seen on iBGP or BMP that is not a configured
// provider and not on an exchange LAN (#102). Accepting it is a draft row
// in the settings form. This list is not a write: it does not add a
// provider, start a probe, or announce.
type Suggestion struct {
	NextHop  string `json:"next_hop"`
	ASN      uint32 `json:"asn,omitempty"`
	Prefixes int    `json:"prefixes"`
}

type formRequest struct {
	YAML  string          `json:"yaml"`
	Apply bool            `json:"apply"`
	Form  configedit.Form `json:"form"`
}

// handleConfigForm reads the settings form from YAML, or merges a form
// back into YAML. Neither path writes the file. Save is still PUT
// /api/config, with the same checks as a start and confirm_inject when
// the text turns inject on.
func (s *Server) handleConfigForm(w http.ResponseWriter, r *http.Request) {
	if !s.editorOn(w) {
		return
	}
	var req formRequest
	if !decodeLarge(w, r, &req, configBodyLimit) {
		return
	}
	if !req.Apply {
		f, err := configedit.ParseForm([]byte(req.YAML))
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"form": f})
		return
	}
	out, err := configedit.ApplyForm([]byte(req.YAML), req.Form)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	f, err := configedit.ParseForm(out)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"yaml": string(out), "form": f})
}

// handleSuggestions returns next hops the operator may drop into a draft
// provider row. It does not write the config file.
func (s *Server) handleSuggestions(w http.ResponseWriter, _ *http.Request) {
	if !s.editorOn(w) {
		return
	}
	var list []Suggestion
	if fn, ok := s.suggest.Load().(func() []Suggestion); ok && fn != nil {
		list = fn()
	}
	if list == nil {
		list = []Suggestion{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"suggestions": list})
}

// ---- Custom dashboards (each user's own) ----

// Dashboard limits.
const (
	MaxDashboards       = 20
	MaxDashboardWidgets = 24
	dashboardBodyLimit  = 16 << 10
)

// WidgetTypes are the widgets a dashboard may hold, with the endpoint
// each one reads. Every one is a read the viewer role may already make.
var WidgetTypes = []struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	API   string `json:"api"`
}{
	{"status", "Readiness", "/readyz"},
	{"providers", "Providers", "/api/providers"},
	{"prefixes", "Prefixes", "/api/prefixes"},
	{"improvements", "Active improvements", "/api/improvements"},
	{"decisions", "Decisions", "/api/decisions"},
	{"telemetry", "Provider usage", "/api/telemetry"},
	{"inbound", "Inbound steers", "/api/inbound"},
	{"mitigations", "Threat mitigation", "/api/mitigations"},
	{"anomalies", "Anomalies", "/api/anomalies"},
	{"federation", "POPs", "/api/federation"},
	{"ha", "High availability", "/api/ha"},
	{"subscriptions", "Report subscriptions", "/api/subscriptions"},
	{"report", "Report", "/api/reports/{report}"},
}

func knownWidget(t string) bool {
	for _, w := range WidgetTypes {
		if w.Type == t {
			return true
		}
	}
	return false
}

// DashboardSpec is a dashboard's layout.
type DashboardSpec struct {
	Title   string   `json:"title,omitempty"`
	Widgets []Widget `json:"widgets"`
}

// Widget is one panel. Report and Days are for type report.
type Widget struct {
	Type   string `json:"type"`
	Title  string `json:"title,omitempty"`
	Report string `json:"report,omitempty"`
	Days   int    `json:"days,omitempty"`
	// Wide spans the full row.
	Wide bool `json:"wide,omitempty"`
}

var dashboardName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$`)

func validText(s string, n int) bool {
	return len(s) <= n && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// Validate checks a dashboard spec.
func (d DashboardSpec) Validate() error {
	if !validText(d.Title, 100) {
		return errors.New("title must be one line of at most 100 bytes")
	}
	if len(d.Widgets) > MaxDashboardWidgets {
		return fmt.Errorf("at most %d widgets", MaxDashboardWidgets)
	}
	for i, w := range d.Widgets {
		if !knownWidget(w.Type) {
			return fmt.Errorf("widgets[%d]: type %q is unknown (see /api/dashboards widget_types)", i, w.Type)
		}
		if !validText(w.Title, 100) {
			return fmt.Errorf("widgets[%d]: title must be one line of at most 100 bytes", i)
		}
		if w.Type == "report" {
			if !history.Known(w.Report) {
				return fmt.Errorf("widgets[%d]: report %q is unknown", i, w.Report)
			}
			if w.Days < 0 || w.Days > MaxReportDays {
				return fmt.Errorf("widgets[%d]: days must be 0-%d", i, MaxReportDays)
			}
		} else if w.Report != "" || w.Days != 0 {
			return fmt.Errorf("widgets[%d]: report and days are only for type report", i)
		}
	}
	return nil
}

// DashboardView is a stored dashboard.
type DashboardView struct {
	Name    string        `json:"name"`
	Spec    DashboardSpec `json:"spec"`
	Updated time.Time     `json:"updated"`
}

// dashboardOwner is whose dashboards the caller sees: the signed-in
// user, or the basic-auth account. Without any auth there is no owner.
func (s *Server) dashboardOwner(w http.ResponseWriter, r *http.Request) (string, bool) {
	if s.dashboards == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "custom dashboards need a storage plugin that keeps them (sqlite)"})
		return "", false
	}
	p := principalFrom(r.Context())
	if !s.writesEnabled() || p.User == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "custom dashboards need auth or basic auth (they are kept per user)"})
		return "", false
	}
	return p.User, true
}

func (s *Server) handleDashboards(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"enabled": s.dashboards != nil && s.writesEnabled(), "widget_types": WidgetTypes,
		"reports": history.Reports, "dashboards": []DashboardView{}}
	if !out["enabled"].(bool) {
		writeJSON(w, http.StatusOK, out)
		return
	}
	owner, ok := s.dashboardOwner(w, r)
	if !ok {
		return
	}
	ds, err := s.dashboards.Dashboards(r.Context(), owner)
	if err != nil {
		s.log.Error("dashboards read", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dashboard store unavailable"})
		return
	}
	views := make([]DashboardView, 0, len(ds))
	for _, d := range ds {
		var spec DashboardSpec
		if err := json.Unmarshal(d.Spec, &spec); err != nil || spec.Validate() != nil {
			s.log.Warn("dashboard skipped: stored layout is invalid", "owner", owner, "name", d.Name)
			continue
		}
		views = append(views, DashboardView{Name: d.Name, Spec: spec, Updated: d.Updated})
	}
	out["dashboards"] = views
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDashboardPut(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.dashboardOwner(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !dashboardName.MatchString(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be 1-63 of letters, digits, space, _ . -"})
		return
	}
	var spec DashboardSpec
	if !decodeLarge(w, r, &spec, dashboardBodyLimit) {
		return
	}
	if err := spec.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	existing, err := s.dashboards.Dashboards(r.Context(), owner)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dashboard store unavailable"})
		return
	}
	replace := false
	for _, d := range existing {
		replace = replace || d.Name == name
	}
	if !replace && len(existing) >= MaxDashboards {
		writeJSON(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("at most %d dashboards per user", MaxDashboards)})
		return
	}
	raw, _ := json.Marshal(spec)
	now := time.Now().UTC()
	if err := s.dashboards.PutDashboard(r.Context(), plugin.Dashboard{Owner: owner, Name: name, Spec: raw, Updated: now}); err != nil {
		s.log.Error("dashboard write", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dashboard store unavailable"})
		return
	}
	noteAudit(r, name, fmt.Sprintf("widgets=%d", len(spec.Widgets)))
	writeJSON(w, http.StatusOK, DashboardView{Name: name, Spec: spec, Updated: now})
}

func (s *Server) handleDashboardDelete(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.dashboardOwner(w, r)
	if !ok {
		return
	}
	found, err := s.dashboards.DeleteDashboard(r.Context(), owner, r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dashboard store unavailable"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such dashboard"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Report subscriptions ----

func (s *Server) handleSubscriptions(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"enabled": s.subs != nil, "subscriptions": []subscribe.Status{}}
	if s.subs != nil {
		out["subscriptions"] = nz(s.subs.Status())
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSubscriptionSend(w http.ResponseWriter, r *http.Request) {
	if s.subs == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no report subscriptions are configured (report_subscriptions)"})
		return
	}
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "sending a report needs auth or basic auth"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), subscribe.SendTimeout)
	defer cancel()
	err := s.subs.SendNow(ctx, r.PathValue("name"))
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
	case errors.Is(err, subscribe.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	default:
		s.log.Warn("report subscription send now", "name", r.PathValue("name"), "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed: " + err.Error()})
	}
}
