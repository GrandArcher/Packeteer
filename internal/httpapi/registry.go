package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/GrandArcher/Packeteer/internal/registry"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// RegistryControl is registry hygiene (#289) as the API sees it: the last
// scan, and the push of one confirmed change.
type RegistryControl interface {
	Report() registry.Report
	Push(ctx context.Context, id, digest string) (plugin.RegistryChange, error)
}

type registryHolder struct{ RegistryControl }

// SetRegistry installs registry hygiene. Nil leaves /api/registry reporting
// that the scan is off.
func (s *Server) SetRegistry(c RegistryControl) {
	if s == nil || c == nil {
		return
	}
	s.registry.Store(&registryHolder{c})
}

func (s *Server) registryControl() RegistryControl {
	if h := s.registry.Load(); h != nil {
		return h.RegistryControl
	}
	return nil
}

// handleRegistry serves the last scan: each finding with its severity,
// the diff to submit, and, when a push is possible, the digest to confirm.
// Writable says whether this server accepts a push at all.
func (s *Server) handleRegistry(w http.ResponseWriter, _ *http.Request) {
	body := struct {
		meta
		Enabled  bool `json:"enabled"`
		Writable bool `json:"writable"`
		registry.Report
	}{meta: s.snapshot().meta(), Report: registry.Report{Sections: []registry.Section{}, Findings: []registry.Finding{}}}
	if c := s.registryControl(); c != nil {
		body.Enabled = true
		body.Report = c.Report()
		body.Writable = body.PushEnabled && s.writesEnabled()
	}
	writeJSON(w, http.StatusOK, body)
}

// handleRegistryPush applies one change the operator confirmed. The body
// names the finding and quotes the digest of the diff that was shown. The
// outcome, failures included, is audit-logged with the change.
func (s *Server) handleRegistryPush(w http.ResponseWriter, r *http.Request) {
	c := s.registryControl()
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "pushing a registry change requires auth (auth.enabled) or PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD"})
		return
	}
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "registry is not enabled"})
		return
	}
	var req struct {
		ID     string `json:"id"`
		Digest string `json:"digest"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ch, err := c.Push(r.Context(), req.ID, req.Digest)
	target := "registry"
	if ch.Class != "" {
		target = ch.Registry + " " + ch.Class + " " + ch.Key
	}
	if err != nil {
		noteAudit(r, target, "registry push refused or failed: "+err.Error())
		code := http.StatusBadGateway
		switch {
		case errors.Is(err, registry.ErrPushOff):
			code = http.StatusForbidden
		case errors.Is(err, registry.ErrNotFound):
			code = http.StatusNotFound
		case errors.Is(err, registry.ErrNotPushable), errors.Is(err, registry.ErrDigestChanged), errors.Is(err, registry.ErrAlreadyPushed), errors.Is(err, plugin.ErrRegistryNoPush):
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	detail := fmt.Sprintf("registry push %s", ch.Op)
	if ch.Field != "" {
		detail = fmt.Sprintf("registry push %s %s: %s -> %s", ch.Op, ch.Field, ch.Old, ch.New)
	}
	noteAudit(r, target, detail)
	s.log.Info("registry change pushed through the API", "registry", ch.Registry, "op", ch.Op, "class", ch.Class, "key", ch.Key, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"pushed": true, "change": ch})
}
