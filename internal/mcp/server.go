// Package mcp is a Model Context Protocol server for AI assistants (#302).
// It is a thin layer over the REST API: every tool is one fixed REST call
// made through a Backend that carries the caller's own authentication, so
// roles, validation, and the audit log are the API's. Read tools are the
// default; write tools exist only when the caller is given access to them.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// Versions of the protocol this server speaks, newest first.
var versions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// MaxResult caps the text one tool call returns, and MaxRequest the size
// of one request.
const (
	MaxResult  = 256 << 10
	MaxRequest = 64 << 10
)

// JSON-RPC error codes.
const (
	codeParse    = -32700
	codeRequest  = -32600
	codeMethod   = -32601
	codeParams   = -32602
	codeInternal = -32603
)

const instructions = "Packeteer is a BGP performance controller. These tools read its state through its REST API. Tools marked WRITE change state and need an explicit user request. Packeteer defaults to observe mode, which announces nothing."

// Backend runs one REST call for the caller and returns the status and
// body.
type Backend interface {
	Do(ctx context.Context, c Call) (status int, body []byte, err error)
}

// Server answers MCP requests.
type Server struct {
	Name    string
	Version string
	Backend Backend
}

// Access is what one caller may do.
type Access struct {
	// Write lists and allows the write tools.
	Write bool
	// OnDenied is called with the tool name when a write tool is asked for
	// without Write, so the refusal can be audited. May be nil.
	OnDenied func(tool string)
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func reply(id json.RawMessage, result any) []byte {
	b, err := json.Marshal(response{JSONRPC: "2.0", ID: id, Result: result})
	if err != nil {
		return replyErr(id, codeInternal, "encode result")
	}
	return b
}

func replyErr(id json.RawMessage, code int, msg string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
	return b
}

// Handle answers one JSON-RPC message. It returns nil for a notification,
// which has no answer.
func (s *Server) Handle(ctx context.Context, raw []byte, a Access) []byte {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '[' {
		return replyErr(nil, codeRequest, "batches are not supported")
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return replyErr(nil, codeParse, "parse error")
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return replyErr(req.ID, codeRequest, "invalid request")
	}
	if len(req.ID) == 0 {
		return nil
	}
	switch req.Method {
	case "initialize":
		return reply(req.ID, s.initialize(req.Params))
	case "ping":
		return reply(req.ID, map[string]any{})
	case "tools/list":
		return reply(req.ID, map[string]any{"tools": s.list(a)})
	case "tools/call":
		return s.call(ctx, req, a)
	}
	return replyErr(req.ID, codeMethod, "method not found")
}

func (s *Server) initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	v := versions[0]
	if contains(versions, p.ProtocolVersion) {
		v = p.ProtocolVersion
	}
	return map[string]any{
		"protocolVersion": v,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
		"instructions":    instructions,
	}
}

func (s *Server) list(a Access) []map[string]any {
	out := []map[string]any{}
	for _, t := range Catalog {
		if t.Write && !a.Write {
			continue
		}
		out = append(out, map[string]any{"name": t.Name, "description": t.Desc, "inputSchema": t.schema()})
	}
	return out
}

func toolResult(text string, isErr bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}
}

func (s *Server) call(ctx context.Context, req request, a Access) []byte {
	var p struct {
		Name      string                     `json:"name"`
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return replyErr(req.ID, codeParams, "invalid params")
	}
	t, ok := find(p.Name)
	if !ok {
		return replyErr(req.ID, codeParams, fmt.Sprintf("unknown tool %q", p.Name))
	}
	if t.Write && !a.Write {
		if a.OnDenied != nil {
			a.OnDenied(t.Name)
		}
		return reply(req.ID, toolResult("write tools are off for this caller: they need mcp.write_tools and an API token with the mcp:write scope", true))
	}
	c, err := t.build(p.Arguments)
	if err != nil {
		return reply(req.ID, toolResult(err.Error(), true))
	}
	status, body, err := s.Backend.Do(ctx, c)
	if err != nil {
		return reply(req.ID, toolResult("request failed: "+err.Error(), true))
	}
	text := string(body)
	if len(text) > MaxResult {
		cut := MaxResult
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = fmt.Sprintf("%s\n[truncated: %d bytes omitted]", text[:cut], len(text)-cut)
	}
	if status >= 400 {
		return reply(req.ID, toolResult(fmt.Sprintf("HTTP %d: %s", status, text), true))
	}
	if text == "" {
		text = fmt.Sprintf("ok (HTTP %d)", status)
	}
	return reply(req.ID, toolResult(text, false))
}
