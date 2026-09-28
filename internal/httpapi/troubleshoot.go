package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
)

// toolTimeout bounds one on-demand probe, trace, or lookup.
const toolTimeout = 2 * time.Minute

type toolRequest struct {
	Target   string `json:"target"`
	Provider string `json:"provider"`
	Query    string `json:"query"`
}

func (s *Server) handleToolStatus(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	st := troubleshoot.Status{Providers: []string{}}
	if s.tools != nil {
		st = s.tools.Status()
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		troubleshoot.Status
	}{meta: snap.meta(), Status: st})
}

func (s *Server) handleLookingGlass(w http.ResponseWriter, r *http.Request) {
	if s.tools == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": troubleshoot.ErrNoRIB.Error()})
		return
	}
	p, err := parsePrefixOrAddr(r.URL.Query().Get("prefix"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	g, err := s.tools.LookingGlass(p)
	if err != nil {
		writeToolError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func parsePrefixOrAddr(v string) (netip.Prefix, error) {
	v = strings.TrimSpace(v)
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked(), nil
	}
	if a, err := netip.ParseAddr(v); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, errors.New("prefix must be an IP prefix or address")
}

// readTool decodes a JSON tool request. POST with application/json keeps
// a cross-site page from triggering probes: that needs a CORS preflight,
// which this server never grants.
func (s *Server) readTool(w http.ResponseWriter, r *http.Request) (toolRequest, bool) {
	var req toolRequest
	if s.tools == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": troubleshoot.ErrDisabled.Error()})
		return req, false
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "content type must be application/json"})
		return req, false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return req, false
	}
	return req, true
}

func (s *Server) toolTarget(w http.ResponseWriter, req toolRequest) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(req.Target))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target must be an IP address"})
		return netip.Addr{}, false
	}
	if err := troubleshoot.CheckTarget(a); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return netip.Addr{}, false
	}
	return a, true
}

func (s *Server) handleToolProbe(w http.ResponseWriter, r *http.Request) {
	req, ok := s.readTool(w, r)
	if !ok {
		return
	}
	a, ok := s.toolTarget(w, req)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), toolTimeout)
	defer cancel()
	ans, err := s.tools.Probe(ctx, a)
	if err != nil {
		writeToolError(w, err)
		return
	}
	s.log.Info("on-demand probe", "target", a, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, ans)
}

func (s *Server) handleToolTrace(w http.ResponseWriter, r *http.Request) {
	req, ok := s.readTool(w, r)
	if !ok {
		return
	}
	a, ok := s.toolTarget(w, req)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), toolTimeout)
	defer cancel()
	ans, err := s.tools.Traceroute(ctx, a, req.Provider)
	if err != nil {
		writeToolError(w, err)
		return
	}
	s.log.Info("on-demand traceroute", "target", a, "provider", req.Provider, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, ans)
}

func (s *Server) handleToolWhois(w http.ResponseWriter, r *http.Request) {
	req, ok := s.readTool(w, r)
	if !ok {
		return
	}
	q := strings.TrimSpace(req.Query)
	if err := troubleshoot.CheckWhoisQuery(q); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), toolTimeout)
	defer cancel()
	res, err := s.tools.Whois(ctx, q)
	if err != nil {
		writeToolError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func writeToolError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, troubleshoot.ErrDisabled):
		status = http.StatusForbidden
	case errors.Is(err, troubleshoot.ErrNoRIB), errors.Is(err, troubleshoot.ErrNoWhois):
		status = http.StatusNotFound
	case errors.Is(err, troubleshoot.ErrBusy):
		w.Header().Set("Retry-After", "10")
		status = http.StatusTooManyRequests
	case strings.HasPrefix(err.Error(), "rdap:"):
		status = http.StatusBadGateway
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
