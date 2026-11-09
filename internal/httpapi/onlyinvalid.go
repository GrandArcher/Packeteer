package httpapi

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/onlyinvalid"
)

// SetOnlyInvalid installs the RPKI-invalid only path report (#401). Nil
// leaves /api/rpki/only-invalid reporting that it is off.
func (s *Server) SetOnlyInvalid(svc *onlyinvalid.Service) {
	if s == nil || svc == nil {
		return
	}
	s.onlyInvalid.Store(svc)
}

// slurmView is the exceptions part of /api/rpki/only-invalid.
type slurmView struct {
	Enabled bool `json:"enabled"`
	// Writable says whether this server accepts a proposal or approval
	// at all (auth or basic auth on).
	Writable   bool                    `json:"writable"`
	Path       string                  `json:"path,omitempty"`
	Prefixes   []netip.Prefix          `json:"prefixes"`
	Exceptions []onlyinvalid.Exception `json:"exceptions"`
	Error      string                  `json:"error,omitempty"`
}

// handleOnlyInvalid serves the open cases with their evidence and the
// SLURM exceptions. ?prefix= keeps the case of that one prefix.
func (s *Server) handleOnlyInvalid(w http.ResponseWriter, r *http.Request) {
	body := struct {
		meta
		Enabled bool `json:"enabled"`
		onlyinvalid.Status
		SLURM slurmView `json:"slurm"`
	}{meta: s.snapshot().meta(), Status: onlyinvalid.Status{Cases: []onlyinvalid.Case{}},
		SLURM: slurmView{Prefixes: []netip.Prefix{}, Exceptions: []onlyinvalid.Exception{}}}
	svc := s.onlyInvalid.Load()
	if svc != nil {
		body.Enabled = true
		body.Status = svc.Status()
	}
	if q := strings.TrimSpace(r.URL.Query().Get("prefix")); q != "" {
		p, err := netip.ParsePrefix(q)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prefix: " + err.Error()})
			return
		}
		keep := body.Cases[:0:0]
		for _, c := range body.Cases {
			if c.Prefix == p.Masked() {
				keep = append(keep, c)
			}
		}
		body.Cases = keep
	}
	if svc != nil && svc.Exceptions != nil {
		ex := svc.Exceptions
		body.SLURM.Enabled, body.SLURM.Path, body.SLURM.Prefixes = true, ex.Path(), ex.Prefixes()
		body.SLURM.Writable = s.writesEnabled()
		if list, err := ex.List(); err != nil {
			s.log.Error("rpki only_invalid: slurm file", "err", err)
			body.SLURM.Error = "the SLURM file is not valid RFC 8416; see the controller log"
		} else {
			body.SLURM.Exceptions = list
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// exceptions returns the SLURM exceptions, or writes why there are none
// to change.
func (s *Server) exceptions(w http.ResponseWriter) *onlyinvalid.Exceptions {
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "a SLURM exception requires auth (auth.enabled) or PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD"})
		return nil
	}
	svc := s.onlyInvalid.Load()
	if svc == nil || svc.Exceptions == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rpki.only_invalid.slurm is not configured"})
		return nil
	}
	return svc.Exceptions
}

func actorOf(r *http.Request) onlyinvalid.Actor {
	p := principalFrom(r.Context())
	who := p.User
	if who == "" {
		who = "anonymous"
	}
	return onlyinvalid.Actor{User: who, Role: p.Role, Method: p.Method, Remote: remoteString(r)}
}

// exceptionError maps a refusal to its status. A file error is logged and
// answered without its detail.
func (s *Server) exceptionError(w http.ResponseWriter, r *http.Request, target string, err error) {
	code := http.StatusConflict
	msg := err.Error()
	switch {
	case errors.Is(err, onlyinvalid.ErrNoCase), errors.Is(err, onlyinvalid.ErrNoException):
		code = http.StatusNotFound
	case errors.Is(err, onlyinvalid.ErrFile):
		s.log.Error("rpki only_invalid: slurm file", "err", err)
		code, msg = http.StatusInternalServerError, "the SLURM file cannot be read or written; see the controller log"
	}
	noteAudit(r, target, "SLURM exception refused or failed: "+msg)
	writeJSON(w, code, map[string]string{"error": msg})
}

// handleOnlyInvalidPropose builds the SLURM entries for one open case and
// returns them with the evidence and a digest. It writes nothing.
func (s *Server) handleOnlyInvalidPropose(w http.ResponseWriter, r *http.Request) {
	ex := s.exceptions(w)
	if ex == nil {
		return
	}
	var req struct {
		Prefix string `json:"prefix"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(req.Prefix))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prefix: " + err.Error()})
		return
	}
	prop, err := ex.Propose(r.Context(), actorOf(r), p.Masked())
	if err != nil {
		s.exceptionError(w, r, p.Masked().String(), err)
		return
	}
	noteAudit(r, prop.Prefix.String(), "SLURM exception proposed; audit "+prop.ID)
	writeJSON(w, http.StatusOK, prop)
}

// handleExceptionApprove writes the entries of a proposal. The body names
// the proposal and quotes the digest that was shown.
func (s *Server) handleExceptionApprove(w http.ResponseWriter, r *http.Request) {
	ex := s.exceptions(w)
	if ex == nil {
		return
	}
	var req struct {
		ID     string `json:"id"`
		Digest string `json:"digest"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	prop, err := ex.Approve(r.Context(), actorOf(r), req.ID, req.Digest)
	if err != nil {
		s.exceptionError(w, r, req.ID, err)
		return
	}
	noteAudit(r, prop.Prefix.String(), "SLURM exception approved and written; proposal "+prop.ID)
	writeJSON(w, http.StatusOK, map[string]any{"written": true, "path": ex.Path(), "proposal": prop})
}

// handleExceptionRemove deletes one entry from the SLURM file.
func (s *Server) handleExceptionRemove(w http.ResponseWriter, r *http.Request) {
	ex := s.exceptions(w)
	if ex == nil {
		return
	}
	gone, err := ex.Remove(r.Context(), actorOf(r), r.PathValue("id"))
	if err != nil {
		s.exceptionError(w, r, r.PathValue("id"), err)
		return
	}
	noteAudit(r, r.PathValue("id"), "SLURM exception removed")
	writeJSON(w, http.StatusOK, map[string]any{"removed": gone})
}

// handleSLURMFile serves the SLURM file for an operator who installs it by
// hand, or an empty RFC 8416 document before the first approval.
func (s *Server) handleSLURMFile(w http.ResponseWriter, _ *http.Request) {
	svc := s.onlyInvalid.Load()
	if svc == nil || svc.Exceptions == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rpki.only_invalid.slurm is not configured"})
		return
	}
	b, err := svc.Exceptions.File()
	if err != nil {
		s.log.Error("rpki only_invalid: slurm file", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the SLURM file is not valid RFC 8416; see the controller log"})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="slurm.json"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}
