package httpapi

import (
	"bytes"
	"context"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/mcp"
)

// MCP is the Model Context Protocol endpoint (#302), POST /mcp. It is a
// thin layer over the routes above: each tool call is dispatched to the
// same handler a REST client reaches, as the caller, so the route's role
// check, validation, and audit record apply unchanged.

// MCPOptions turns the endpoint on. A nil *MCPOptions leaves POST /mcp out.
type MCPOptions struct {
	// WriteTools allows the write tools to callers whose token has the
	// mcp:write scope.
	WriteTools bool
	// RatePerMinute is the requests one caller may make per minute.
	RatePerMinute int
}

// mcpTimeout bounds one tool call.
const mcpTimeout = 30 * time.Second

// delegatedKey carries the principal the MCP endpoint already
// authenticated into the dispatched request, which has no credentials of
// its own. Only handleMCP sets it.
type delegatedKey struct{}

func delegated(ctx context.Context) (auth.Principal, bool) {
	p, ok := ctx.Value(delegatedKey{}).(auth.Principal)
	return p, ok
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	key := p.User
	if key == "" {
		key = remoteString(r)
	}
	if !s.mcpLimits.allow(key) {
		w.Header().Set("Retry-After", strconv.Itoa(int(time.Minute/time.Duration(s.mcpOpt.RatePerMinute)/time.Second)+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many MCP requests; try again shortly"})
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "content type must be application/json"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mcp.MaxRequest))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request too large"})
		return
	}
	// A write tool needs the option, an RBAC token with the mcp:write
	// scope, and (on the dispatched route) the role the REST call needs.
	access := mcp.Access{
		Write: s.mcpOpt.WriteTools && s.auth != nil && p.Method == auth.MethodToken && p.Scope == auth.ScopeMCPWrite,
		OnDenied: func(tool string) {
			// With no auth the caller is anonymous: recording its refusals
			// would let anyone who reaches the port fill the log (see guard).
			if p.Method != methodNone {
				s.record(r, p, "MCP tools/call "+tool, "", "write tools are off for this caller", http.StatusForbidden)
			}
		},
	}
	ctx, cancel := context.WithTimeout(r.Context(), mcpTimeout)
	defer cancel()
	srv := mcp.Server{Name: "packeteer", Version: s.snapshot().Version, Backend: mcpBackend{s: s, r: r, p: p}}
	ans := srv.Handle(ctx, body, access)
	if ans == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(ans)
}

// mcpBackend dispatches a tool call into the route table as p.
type mcpBackend struct {
	s *Server
	r *http.Request
	p auth.Principal
}

func (b mcpBackend) Do(ctx context.Context, c mcp.Call) (int, []byte, error) {
	target := c.Path
	if len(c.Query) > 0 {
		target += "?" + c.Query.Encode()
	}
	req, err := http.NewRequestWithContext(context.WithValue(ctx, delegatedKey{}, b.p), c.Method, target, bytes.NewReader(c.Body))
	if err != nil {
		return 0, nil, err
	}
	req.RemoteAddr, req.Host = b.r.RemoteAddr, b.r.Host
	if len(c.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	out := &sink{header: http.Header{}}
	b.s.mux.ServeHTTP(out, req)
	return out.status(), out.buf.Bytes(), nil
}

// sink collects a dispatched response, keeping at most the bytes a tool
// result can hold.
type sink struct {
	header http.Header
	code   int
	buf    bytes.Buffer
}

func (w *sink) Header() http.Header { return w.header }

func (w *sink) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}

func (w *sink) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	if room := mcp.MaxResult + 1 - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (w *sink) status() int {
	if w.code == 0 {
		return http.StatusOK
	}
	return w.code
}
