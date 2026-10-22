package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/preflight"
	"github.com/GrandArcher/Packeteer/internal/snippet"
)

// PreflightControl is the preflight runner (#221) as the API sees it. Run
// sends a TTL-limited probe per provider and reads the sessions; nothing is
// announced or written.
type PreflightControl interface {
	Run(ctx context.Context) preflight.Report
	Latest() (preflight.Report, bool)
	Confirm(ctx context.Context, id, by string) (preflight.Report, error)
	Gate(ctx context.Context, candidate []byte) error
	Snippet(vendor string) (string, error)
}

// SetPreflight installs the preflight runner. It may be called after New,
// once the RIB view exists.
func (s *Server) SetPreflight(p PreflightControl) {
	if s == nil {
		return
	}
	s.preflight.Store(&p)
}

func (s *Server) preflightControl() PreflightControl {
	if p := s.preflight.Load(); p != nil {
		return *p
	}
	return nil
}

// handlePreflight serves the latest report. It runs nothing.
func (s *Server) handlePreflight(w http.ResponseWriter, _ *http.Request) {
	body := struct {
		meta
		Available bool `json:"available"`
		// Report is absent until the checks have run once.
		Report  *preflight.Report `json:"report,omitempty"`
		Vendors []string          `json:"vendors"`
	}{meta: s.snapshot().meta(), Vendors: snippet.Vendors}
	if p := s.preflightControl(); p != nil {
		body.Available = true
		if rep, ok := p.Latest(); ok {
			body.Report = &rep
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// handlePreflightRun runs every check now.
func (s *Server) handlePreflightRun(w http.ResponseWriter, r *http.Request) {
	p := s.preflightControl()
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the preflight checks are not available on this instance"})
		return
	}
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "running the checks needs auth or basic auth"})
		return
	}
	rep := p.Run(r.Context())
	noteAudit(r, "preflight", "ready="+boolText(rep.Ready)+" blocking="+strings.Join(rep.Blocking(), ","))
	writeJSON(w, http.StatusOK, rep)
}

// handlePreflightConfirm records an administrator's confirmation of a check
// that needs a look at the router.
func (s *Server) handlePreflightConfirm(w http.ResponseWriter, r *http.Request) {
	p := s.preflightControl()
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the preflight checks are not available on this instance"})
		return
	}
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "confirming a check needs auth or basic auth"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeLarge(w, r, &req, 1024) {
		return
	}
	by := principalFrom(r.Context()).User
	if by == "" {
		by = "admin"
	}
	rep, err := p.Confirm(r.Context(), req.ID, by)
	switch {
	case errors.Is(err, preflight.ErrNotConfirmable):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
	case errors.Is(err, preflight.ErrFailing):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case err != nil:
		s.log.Error("preflight confirm", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	default:
		noteAudit(r, "preflight", "confirmed "+req.ID)
		writeJSON(w, http.StatusOK, rep)
	}
}

// handleSnippets renders the router config for one vendor from the running
// config. It is text for an operator to review; nothing is sent anywhere.
func (s *Server) handleSnippets(w http.ResponseWriter, r *http.Request) {
	p := s.preflightControl()
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "router snippets are not available on this instance"})
		return
	}
	vendor := r.URL.Query().Get("vendor")
	text, err := p.Snippet(vendor)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"vendor": vendor, "text": text})
}

// handleInjectPlan renders the inject config for a small allowlist, once the
// preflight checks pass. It writes nothing: the result goes to the editor,
// and Save asks for the inject confirmation and runs the checks again.
func (s *Server) handleInjectPlan(w http.ResponseWriter, r *http.Request) {
	if !s.editorOn(w) {
		return
	}
	if s.preflightControl() == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the preflight checks are not available on this instance, so the guided inject step is off"})
		return
	}
	var req struct {
		configedit.InjectInput
		Current string `json:"current"`
	}
	if !decodeLarge(w, r, &req, configBodyLimit) {
		return
	}
	if !s.preflightGate(w, r, true, []byte(req.Current)) {
		return
	}
	plan, err := configedit.EnableInject(req.InjectInput, []byte(req.Current))
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	body := map[string]any{"yaml": plan.YAML, "diff": plan.Diff, "explain": plan.Explain}
	if missing, ok := s.notLearned(req.Allowlist); ok {
		body["not_learned"] = missing
	}
	noteAudit(r, "config", "inject plan for "+strings.Join(req.Allowlist, ","))
	writeJSON(w, http.StatusOK, body)
}

// notLearned lists the requested prefixes the learned RIB does not hold now.
// Such a prefix is never announced, so the page warns about it. ok is false
// when there is no RIB to ask.
func (s *Server) notLearned(requested []string) (missing []string, ok bool) {
	rv := s.searchRIB.Load()
	if rv == nil {
		return nil, false
	}
	for _, text := range requested {
		if p, err := netip.ParsePrefix(strings.TrimSpace(text)); err == nil {
			if _, found := (*rv).Exact(p); !found {
				missing = append(missing, p.Masked().String())
			}
		}
	}
	return missing, true
}

// preflightGate refuses a config save that turns inject on while a check
// blocks it, or that changes the setup the checks describe. candidate is the
// YAML about to be saved. It reports whether the save may go on.
func (s *Server) preflightGate(w http.ResponseWriter, r *http.Request, enablesInject bool, candidate []byte) bool {
	p := s.preflightControl()
	if p == nil || !enablesInject {
		return true
	}
	err := p.Gate(r.Context(), candidate)
	var nr *preflight.NotReadyError
	switch {
	case err == nil:
		return true
	case errors.Is(err, preflight.ErrSetupChanged):
		writeJSON(w, http.StatusPreconditionFailed, map[string]any{"error": err.Error(), "code": "setup_changed"})
	case errors.As(err, &nr):
		writeJSON(w, http.StatusPreconditionFailed, map[string]any{
			"error": nr.Error(), "code": "preflight_required", "preflight": nr.Report,
		})
	default:
		s.log.Error("preflight gate", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the preflight gate failed: " + err.Error()})
	}
	return false
}

// PreflightMetrics renders the latest preflight report. Each check has one
// series per status, and 1 marks the current one.
func PreflightMetrics(rep preflight.Report) []byte {
	var b strings.Builder
	writeGauge(&b, "packeteer_preflight_ready", "1 when every preflight check passed or warned, so the setup may turn inject on.", sample{value: boolFloat(rep.Ready)})
	var checks []sample
	for _, res := range rep.Results {
		for _, st := range []preflight.Status{preflight.Pass, preflight.Warn, preflight.Fail, preflight.Unverified} {
			checks = append(checks, sample{labels: []lbl{{"check", res.ID}, {"status", string(st)}}, value: boolFloat(res.Status == st)})
		}
	}
	writeGauge(&b, "packeteer_preflight_check", "The status of a preflight check: 1 on the series that names its current status.", checks...)
	writeGauge(&b, "packeteer_preflight_last_run_timestamp_seconds", "When the preflight checks last ran.", sample{value: float64(rep.RanAt.Unix())})
	return []byte(b.String())
}
