package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestRunRefusesBadSetup(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"no token":      {map[string]string{}, "PACKETEER_MCP_TOKEN is not set"},
		"clear text":    {map[string]string{"PACKETEER_MCP_TOKEN": "pkt_x", "PACKETEER_MCP_URL": "http://192.0.2.10:8080/mcp"}, "PACKETEER_MCP_URL"},
		"url with user": {map[string]string{"PACKETEER_MCP_TOKEN": "pkt_x", "PACKETEER_MCP_URL": "https://u:p@example.net/mcp"}, "PACKETEER_MCP_URL"},
	} {
		var errOut bytes.Buffer
		if code := run(context.Background(), env(tc.env), strings.NewReader(""), io.Discard, &errOut); code != 2 || !strings.Contains(errOut.String(), tc.want) {
			t.Errorf("%s: code %d, stderr %q", name, code, errOut.String())
		}
	}
}

func TestRunForwardsToController(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Header.Get("Authorization") != "Bearer pkt_x" {
			http.Error(w, "bad", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer ts.Close()
	var out bytes.Buffer
	e := env(map[string]string{"PACKETEER_MCP_TOKEN": "pkt_x", "PACKETEER_MCP_URL": ts.URL + "/mcp"})
	if code := run(context.Background(), e, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out, io.Discard); code != 0 {
		t.Fatalf("code %d", code)
	}
	if strings.TrimSpace(out.String()) != `{"jsonrpc":"2.0","id":1,"result":{}}` {
		t.Errorf("stdout %q", out.String())
	}
}
