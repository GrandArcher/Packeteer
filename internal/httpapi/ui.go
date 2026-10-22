package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/commitview"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/subscribe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Remaining UI features (#34): the config editor and first-run wizard
// (admin), custom dashboards (each signed-in user's own), and report
// subscriptions (status for viewers, send-now for operators). None of
// them announces. The editor writes the mounted file only after the same
// checks the controller runs at start. When every change can apply
// online, the controller applies it on the write (#128). Anything else
// waits for a restart.

// ConfigEditor is the validated config editor. *configedit.Editor
// implements it. Nil when http.config_editor is off.
type ConfigEditor interface {
	Read() (configedit.File, error)
	Check(data []byte) configedit.Result
	Preview(data []byte) (configedit.Preview, error)
	Save(data []byte, base string, confirmInject bool) (configedit.File, configedit.Result, error)
}

// FirstRun is the persisted first-run setup state (#416). Setup is pending
// until a config is saved through the editor or Complete is called.
type FirstRun interface {
	Pending() bool
	Complete() error
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

// setupPendingFor is true when the caller is an admin on an instance whose
// editor is on only for the first-run setup, and setup is still pending.
func (s *Server) setupPendingFor(p auth.Principal) bool {
	return s.firstRun != nil && s.writesEnabled() && !p.MustChange && p.Role.Allows(plugin.RoleAdmin) && s.firstRun.Pending()
}

// handleSetupSkip ends the first-run setup without saving a config. The
// editor stays on until the next start; a restart then applies the
// default (off unless http.config_editor is true).
func (s *Server) handleSetupSkip(w http.ResponseWriter, r *http.Request) {
	if s.firstRun == nil || !s.writesEnabled() || !s.firstRun.Pending() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "first-run setup is not pending on this instance"})
		return
	}
	if err := s.firstRun.Complete(); err != nil {
		s.log.Warn("first-run setup: cannot remove the pending file; setup shows again after a restart", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "setup is skipped for now, but the pending file cannot be removed, so it shows again after a restart: " + err.Error()})
		return
	}
	noteAudit(r, "setup", "first-run setup skipped")
	writeJSON(w, http.StatusOK, map[string]bool{"pending": false})
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

// handleConfigPreview checks a candidate and diffs it against the file on
// disk: what Save would change, and which keys need a restart. It writes
// nothing.
func (s *Server) handleConfigPreview(w http.ResponseWriter, r *http.Request) {
	if !s.editorOn(w) {
		return
	}
	var req configRequest
	if !decodeLarge(w, r, &req, configBodyLimit) {
		return
	}
	p, err := s.editor.Preview([]byte(req.YAML))
	if err != nil {
		s.log.Error("config editor preview", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot read the config file"})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// configSchema describes the form blocks the page renders: each block's
// fields, and the plugin types the add-a-plugin picker offers.
type configSchema struct {
	Blocks      []configedit.Block  `json:"blocks"`
	FlowExtras  []configedit.Field  `json:"flow_extras"`
	PluginLists []string            `json:"plugin_lists"`
	PluginTypes map[string][]string `json:"plugin_types"`
	SNMP        map[string][]string `json:"snmp"`
}

func (s *Server) handleConfigSchema(w http.ResponseWriter, _ *http.Request) {
	if !s.editorOn(w) {
		return
	}
	writeJSON(w, http.StatusOK, configSchema{
		Blocks:      configedit.Blocks(),
		FlowExtras:  configedit.FlowExtras(),
		PluginLists: configedit.PluginLists(),
		PluginTypes: configedit.PluginTypes(),
		SNMP: map[string][]string{
			"security_levels": configedit.SNMPSecurityLevels(),
			"auth_protocols":  configedit.SNMPAuthProtocols(),
			"priv_protocols":  configedit.SNMPPrivProtocols(),
		},
	})
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
	if !s.preflightGate(w, r, s.editor.Check([]byte(req.YAML)).EnablesInject) {
		return
	}
	f, res, err := s.editor.Save([]byte(req.YAML), req.Base, req.ConfirmInject)
	body := map[string]any{"result": res}
	switch {
	case err == nil:
		detail := "base=" + short(req.Base) + " new=" + short(next) + " mode=" + res.Mode + " changed=" + strings.Join(res.Changed, ",")
		msg := "config file written through the editor; it applies on restart"
		if res.ReloadOnline {
			if fn, ok := s.apply.Load().(OnlineApplier); ok && fn != nil {
				// The apply starts sources and policies that must outlive this
				// request, so it never runs on a context the request cancels.
				applied, refused, fatal := fn(context.WithoutCancel(r.Context()))
				if len(applied) > 0 {
					body["applied"] = applied
					detail += " applied=" + strings.Join(applied, ",")
				}
				switch {
				case fatal != nil:
					body["apply_error"] = fatal.Error()
					detail += " apply_error=" + fatal.Error()
					msg = "config file written and the online apply failed after changing the BGP speaker"
				case refused != nil:
					body["apply_error"] = refused.Error()
					detail += " apply_error=" + refused.Error()
					msg = "config file written; the online apply was refused and the running config stays"
				default:
					msg = "config file written and applied online"
				}
			} else {
				msg = "config file written through the editor; SIGHUP applies it"
			}
		}
		noteAudit(r, "config", detail)
		s.log.Warn(msg, "user", principalFrom(r.Context()).User, "path", f.Path, "sha256", f.SHA256, "changed", strings.Join(res.Changed, ","))
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
// nothing; the UI shows the result in the editor for review. Over a
// current config it keeps auth, http, storage and unknown blocks and
// returns a diff and what is lost (#345). Inject is not accepted. It is
// part of the editor: off unless http.config_editor is on or the first-run
// setup is pending (#416).
func (s *Server) handleWizard(w http.ResponseWriter, r *http.Request) {
	if !s.editorOn(w) {
		return
	}
	var req struct {
		configedit.WizardInput
		Current string `json:"current"`
	}
	if !decodeLarge(w, r, &req, configBodyLimit) {
		return
	}
	plan, err := configedit.WizardOver(req.WizardInput, []byte(req.Current))
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "wizard input is invalid", "errors": strings.Split(err.Error(), "\n")})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"yaml": plan.YAML, "mode": "observe", "editor": true,
		"existing": plan.Existing, "diff": plan.Diff, "removes": plan.Removes})
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
	{"timeseries", "Before/after graphs", "/api/reports/timeseries"},
	{"commit", "Provider usage vs commit", "/api/commit"},
	{"causes", "Improvements by cause", "/api/reports/causes"},
}

func knownWidget(t string) bool {
	for _, w := range WidgetTypes {
		if w.Type == t {
			return true
		}
	}
	return false
}

// Grid limits for widgets (#182): a row has GridColumns columns and a
// widget may be up to MaxWidgetRows rows tall.
const (
	GridColumns   = 12
	MaxWidgetRows = 8
)

// WidgetRefreshes are the seconds a widget may wait between reads; 0 is
// the default, the first of them.
var WidgetRefreshes = []int{15, 30, 60, 300}

// DashboardSpec is a dashboard's layout. The widgets are in reading order;
// a widget's place is its position in the list and its W and H. Favorite
// marks the one a user's dashboards page opens first; the server keeps at
// most one per user.
type DashboardSpec struct {
	Title    string   `json:"title,omitempty"`
	Favorite bool     `json:"favorite,omitempty"`
	Widgets  []Widget `json:"widgets"`
}

// Widget is one panel. Report, Days, and Query are for type report; Query
// is the filters, sort, and limit (or a from/to range instead of Days) of
// /api/reports/{report} as a URL query string (#178). Days and Bucket (one
// of history.Buckets, default all) are for type timeseries. Days is also
// the time window of types causes and commit (commit: 1, 7, or 30).
type Widget struct {
	Type   string `json:"type"`
	Title  string `json:"title,omitempty"`
	Report string `json:"report,omitempty"`
	Days   int    `json:"days,omitempty"`
	Query  string `json:"query,omitempty"`
	Bucket string `json:"bucket,omitempty"`
	// Wide is the pre-#182 way to span the full row. It is read from stored
	// layouts and means W 12; the page saves W instead.
	Wide bool `json:"wide,omitempty"`
	// W is the width in columns of GridColumns (0 is 6) and H the height in
	// rows (0 fits the content). Refresh is the seconds between reads, one
	// of WidgetRefreshes (0 is 15).
	W       int `json:"w,omitempty"`
	H       int `json:"h,omitempty"`
	Refresh int `json:"refresh,omitempty"`
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
		if w.W < 0 || w.W > GridColumns || (w.Wide && w.W != 0) {
			return fmt.Errorf("widgets[%d]: w must be 1-%d, and not together with wide", i, GridColumns)
		}
		if w.H < 0 || w.H > MaxWidgetRows {
			return fmt.Errorf("widgets[%d]: h must be 1-%d", i, MaxWidgetRows)
		}
		if w.Refresh != 0 && !slices.Contains(WidgetRefreshes, w.Refresh) {
			return fmt.Errorf("widgets[%d]: refresh must be one of %v seconds", i, WidgetRefreshes)
		}
		switch w.Type {
		case "causes", "commit":
			if w.Report != "" || w.Query != "" || w.Bucket != "" {
				return fmt.Errorf("widgets[%d]: report, query, and bucket are not for type %s", i, w.Type)
			}
			if _, ok := commitview.Steps[w.Days]; w.Type == "commit" && w.Days != 0 && !ok {
				return fmt.Errorf("widgets[%d]: days must be 1, 7, or 30 for type commit", i)
			}
			if w.Days < 0 || w.Days > MaxReportDays {
				return fmt.Errorf("widgets[%d]: days must be 0-%d", i, MaxReportDays)
			}
		case "report":
			if !history.Known(w.Report) {
				return fmt.Errorf("widgets[%d]: report %q is unknown", i, w.Report)
			}
			if w.Days < 0 || w.Days > MaxReportDays {
				return fmt.Errorf("widgets[%d]: days must be 0-%d", i, MaxReportDays)
			}
			if w.Bucket != "" {
				return fmt.Errorf("widgets[%d]: bucket is only for type timeseries", i)
			}
			if err := w.checkQuery(); err != nil {
				return fmt.Errorf("widgets[%d]: query: %w", i, err)
			}
		case "timeseries":
			if w.Report != "" || w.Query != "" {
				return fmt.Errorf("widgets[%d]: report and query are only for type report", i)
			}
			if w.Days < 0 || w.Days > MaxReportDays {
				return fmt.Errorf("widgets[%d]: days must be 0-%d", i, MaxReportDays)
			}
			if w.Bucket != "" && !slices.Contains(history.Buckets, w.Bucket) {
				return fmt.Errorf("widgets[%d]: bucket %q is unknown (want %s)", i, w.Bucket, strings.Join(history.Buckets, ", "))
			}
		default:
			if w.Report != "" || w.Days != 0 || w.Bucket != "" || w.Query != "" {
				return fmt.Errorf("widgets[%d]: report, days, bucket, and query are only for type report or timeseries", i)
			}
		}
	}
	return nil
}

// checkQuery runs the report's own parameter checks on a widget's query, so
// a stored widget can never ask for a filter the report refuses.
func (w Widget) checkQuery() error {
	if w.Query == "" {
		return nil
	}
	if !validText(w.Query, 512) {
		return errors.New("must be one line of at most 512 bytes")
	}
	v, err := url.ParseQuery(w.Query)
	if err != nil {
		return err
	}
	if v.Has("format") || v.Has("days") {
		return errors.New("format and days are not allowed (days is its own field)")
	}
	if w.Days > 0 {
		v.Set("days", strconv.Itoa(w.Days))
	}
	_, err = reportQueryValues(v, w.Report, time.Now())
	return err
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
	now := time.Now().UTC()
	if spec.Favorite && !s.clearFavorites(w, r, owner, name, existing) {
		return
	}
	raw, _ := json.Marshal(spec)
	if err := s.dashboards.PutDashboard(r.Context(), plugin.Dashboard{Owner: owner, Name: name, Spec: raw, Updated: now}); err != nil {
		s.log.Error("dashboard write", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dashboard store unavailable"})
		return
	}
	noteAudit(r, name, fmt.Sprintf("widgets=%d", len(spec.Widgets)))
	writeJSON(w, http.StatusOK, DashboardView{Name: name, Spec: spec, Updated: now})
}

// clearFavorites drops the favorite mark from the owner's other dashboards,
// so a user has one. It runs before the new favorite is written: if a write
// fails halfway the user is left with none, never two. The layouts and their
// update times are kept.
func (s *Server) clearFavorites(w http.ResponseWriter, r *http.Request, owner, keep string, existing []plugin.Dashboard) bool {
	for _, d := range existing {
		var spec DashboardSpec
		if d.Name == keep || json.Unmarshal(d.Spec, &spec) != nil || !spec.Favorite {
			continue
		}
		spec.Favorite = false
		raw, _ := json.Marshal(spec)
		d.Spec = raw
		if err := s.dashboards.PutDashboard(r.Context(), d); err != nil {
			s.log.Error("dashboard write", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dashboard store unavailable"})
			return false
		}
	}
	return true
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
