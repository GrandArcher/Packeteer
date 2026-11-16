package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/fieldreport"
)

// secretConfig sets credentials where a config can hold them. The report
// reads only counts and plugin types, so none may reach it.
const secretConfig = `mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  - {name: secret-transit-name, source_ip: 192.0.2.11, next_hop: 192.0.2.1, bmp: prefer}
bgp:
  neighbors:
    - {address: 192.0.2.254, description: secret-router-name, add_path: true}
rib_sources:
  - {type: bmp, config: {listen: "127.0.0.1:0", routers: [192.0.2.254]}}
sources:
  - {type: static, config: {targets: [{prefix: 198.51.100.0/24, host: 198.51.100.10}]}}
notifiers:
  - {type: webhook, config: {url: "https://hooks.example.net/T0KEN-in-url", headers: {Authorization: "Bearer hunter2-token"}}}
telemetry:
  - {type: snmp, config: {community: hunter2-community, password: hunter2-password}}
`

func TestReportFactsHoldNoSecrets(t *testing.T) {
	cfg, err := config.Parse([]byte(secretConfig))
	if err != nil {
		t.Fatal(err)
	}
	facts := reportFacts(cfg)
	if facts.Providers != 1 || facts.BGPNeighbors != 1 || !facts.AddPath || !facts.BMP || len(facts.SourceTypes) != 1 || facts.SourceTypes[0] != "static" {
		t.Errorf("facts %+v", facts)
	}
	if got := strings.Join(facts.ProbeTypes, ","); got != "icmp,tcp" {
		t.Errorf("probers %q, want the defaults", got)
	}
	text := fieldreport.Render(fieldreport.Input{Version: "test", Mode: cfg.Mode, Facts: facts})
	for _, secret := range []string{"hunter2", "T0KEN", "secret-transit-name", "secret-router-name", "64512:666", "hooks.example.net", "192.0.2.254", "198.51.100"} {
		if strings.Contains(text, secret) {
			t.Errorf("%q is in the report:\n%s", secret, text)
		}
	}
	if !strings.Contains(text, "mode: observe") {
		t.Errorf("the mode is missing:\n%s", text)
	}
}

// fakeController answers GET /api/report/share and records the credentials.
func fakeController(t *testing.T, report string, status int) (*httptest.Server, *http.Header) {
	t.Helper()
	var seen http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		if r.URL.Path != "/api/report/share" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"filename":"x","report":` + quote(report) + `}`))
	}))
	t.Cleanup(ts.Close)
	return ts, &seen
}

func quote(s string) string { return `"` + strings.NewReplacer("\n", `\n`, `"`, `\"`).Replace(s) + `"` }

const sampleReport = "Packeteer field report\nmode: observe\n"

func TestReportShowsThePreviewAndWritesOnlyAfterYes(t *testing.T) {
	ts, seen := fakeController(t, sampleReport, http.StatusOK)
	out := filepath.Join(t.TempDir(), "r.txt")
	args := []string{"--share", "-url", ts.URL, "-out", out}
	env := func(k string) string {
		return map[string]string{HTTPUserEnv: "u", HTTPPassEnv: "p"}[k]
	}

	var stdout, stderr bytes.Buffer
	if code := runReport(context.Background(), args, env, strings.NewReader("n\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("answer no: code %d, %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), sampleReport) || !strings.Contains(stdout.String(), "Nothing was written.") {
		t.Errorf("preview:\n%s", stdout.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("the file was written without a yes")
	}
	if u, p, ok := (&http.Request{Header: *seen}).BasicAuth(); !ok || u != "u" || p != "p" {
		t.Errorf("basic auth not sent: %v", *seen)
	}

	stdout.Reset()
	if code := runReport(context.Background(), args, env, strings.NewReader("y\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("answer yes: code %d, %s", code, stderr.String())
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != sampleReport {
		t.Fatalf("file %q, %v", got, err)
	}
	if strings.Index(stdout.String(), sampleReport) > strings.Index(stdout.String(), "Wrote ") {
		t.Error("the preview comes after the write")
	}

	stderr.Reset()
	if code := runReport(context.Background(), args, env, strings.NewReader("y\n"), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "exists") {
		t.Errorf("an existing file must not be overwritten: code %d, %s", code, stderr.String())
	}
	if got, _ := os.ReadFile(out); string(got) != sampleReport {
		t.Error("the existing file changed")
	}
}

func TestReportEndOfInputIsNo(t *testing.T) {
	ts, _ := fakeController(t, sampleReport, http.StatusOK)
	out := filepath.Join(t.TempDir(), "r.txt")
	var stdout, stderr bytes.Buffer
	if code := runReport(context.Background(), []string{"--share", "-url", ts.URL, "-out", out}, noEnv, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("code %d, %s", code, stderr.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("the file was written with no answer")
	}
}

func TestReportSendsTheTokenAndExplainsARefusal(t *testing.T) {
	ts, seen := fakeController(t, "", http.StatusUnauthorized)
	var stdout, stderr bytes.Buffer
	env := func(k string) string { return map[string]string{APITokenEnv: "pkt_abc"}[k] }
	code := runReport(context.Background(), []string{"--share", "-url", ts.URL}, env, strings.NewReader("y\n"), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), APITokenEnv) {
		t.Errorf("code %d, stderr %q", code, stderr.String())
	}
	if (*seen).Get("Authorization") != "Bearer pkt_abc" {
		t.Errorf("token not sent: %v", *seen)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout %q", stdout.String())
	}
}

func TestReportRefusesToSendCredentialsInTheClear(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := func(k string) string { return map[string]string{APITokenEnv: "pkt_abc"}[k] }
	code := runReport(context.Background(), []string{"--share", "-url", "http://192.0.2.1:8080"}, env, strings.NewReader("y\n"), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "https") {
		t.Errorf("code %d, stderr %q", code, stderr.String())
	}
}

func TestReportNeedsShare(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"report"}, noEnv, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "usage: packeteer report --share") {
		t.Errorf("code %d, stderr %q", code, stderr.String())
	}
}

func TestControllerURLFollowsHTTPListen(t *testing.T) {
	for listen, want := range map[string]string{
		"":               "http://127.0.0.1:8080",
		"0.0.0.0:9090":   "http://127.0.0.1:9090",
		"[::]:9091":      "http://127.0.0.1:9091",
		":9092":          "http://127.0.0.1:9092",
		"127.0.0.2:9093": "http://127.0.0.2:9093",
	} {
		yaml := onboardConfig
		if listen != "" {
			yaml += "http: {listen: \"" + listen + "\"}\n"
		}
		got, err := controllerURL(writeOnboardConfig(t, yaml), noEnv)
		if err != nil || got != want {
			t.Errorf("listen %q: %q, %v; want %q", listen, got, err, want)
		}
	}
	if got, err := controllerURL(writeOnboardConfig(t, onboardConfig+"http: {listen: \"192.0.2.10:9094\"}\n"), noEnv); err == nil || !strings.Contains(err.Error(), "give -url with an https") {
		t.Errorf("a listen address off loopback: %q, %v", got, err)
	}
	got, err := controllerURL(writeOnboardConfig(t, onboardConfig), func(k string) string { return map[string]string{HTTPListenEnv: "off"}[k] })
	if err == nil || !strings.Contains(err.Error(), "turns the HTTP server off") {
		t.Errorf("a disabled server: %q, %v", got, err)
	}
}
