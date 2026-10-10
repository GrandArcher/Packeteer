package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type captured struct{ events []plugin.Event }

func (c *captured) Emit(e plugin.Event) { c.events = append(c.events, e) }

func authConfig(t *testing.T, extra string) string {
	t.Helper()
	example, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(example), "  listen: \"127.0.0.1:8080\"\n", "  listen: \"127.0.0.1:8080\"\n  allow_from: [127.0.0.0/8, 192.0.2.0/24]\n", 1)
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(text+"\nauth:\n  enabled: true\n"+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestRunAuthCheck(t *testing.T) {
	path := authConfig(t, "")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{"mode: observe", "http auth: rbac (users, tokens, and audit in storage sqlite; sso off)", "http allow_from: 127.0.0.0/8,192.0.2.0/24"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	for name, env := range map[string]map[string]string{
		"basic user too": {HTTPUserEnv: "ops", HTTPPassEnv: "secret"},
		"short admin":    {AdminPassEnv: "short"},
		"bad admin name": {AdminUserEnv: "-root", AdminPassEnv: "a-long-enough-password"},
	} {
		out.Reset()
		errOut.Reset()
		if code := run(context.Background(), []string{"-check", "-config", path}, envOf(env), &out, &errOut); code != 1 {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	// SSO without its secret refuses to start.
	sso := "  sso:\n    type: oidc\n    config: {issuer: 'https://idp.example.net', client_id: packeteer, client_secret_env: PACKETEER_OIDC_CLIENT_SECRET, redirect_url: 'https://packeteer.example.net/auth/callback', default_role: viewer}\n"
	ssoPath := authConfig(t, sso)
	if code := run(context.Background(), []string{"-check", "-config", ssoPath}, noEnv, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "PACKETEER_OIDC_CLIENT_SECRET") {
		t.Fatalf("sso without secret: %d %s", code, errOut.String())
	}
	out.Reset()
	if code := run(context.Background(), []string{"-check", "-config", ssoPath}, envOf(map[string]string{"PACKETEER_OIDC_CLIENT_SECRET": "s"}), &out, &errOut); code != 0 || !strings.Contains(out.String(), "sso oidc") {
		t.Fatalf("sso: %d %s", code, out.String())
	}
}

// TestAuthBootstrapWithSQLite runs the daemon's auth wiring against the
// real sqlite store: the admin from the environment is created once, is
// never reset, and the audit log reaches the store and the notifiers.
func TestAuthBootstrapWithSQLite(t *testing.T) {
	auth.SetHashIterations(1000)
	dir := t.TempDir()
	cfg, err := config.Parse([]byte("mode: observe\nasn: 64512\nrouter_id: 192.0.2.10\nproviders:\n  - name: a\n    source_ip: 192.0.2.11\n    next_hop: 192.0.2.1\n" +
		"storage:\n  type: sqlite\n  config: {path: " + dir + "/p.db}\nauth:\n  enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	env := envOf(map[string]string{AdminUserEnv: "root", AdminPassEnv: "first-admin-password"})
	start := func() (*pluginhost.Set, *auth.Service, *auth.Auditor, *captured) {
		plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log})
		if err != nil {
			t.Fatal(err)
		}
		if err := checkAuth(cfg, plugins, "", env); err != nil {
			t.Fatal(err)
		}
		if err := plugins.Start(ctx); err != nil {
			t.Fatal(err)
		}
		out := &captured{}
		audit := newAuditor(plugins, out, log)
		svc, err := newAuthService(cfg, plugins, log)
		if err != nil || svc == nil {
			t.Fatalf("service: %v", err)
		}
		bootstrapAdmin(ctx, svc, audit, env, log)
		return plugins, svc, audit, out
	}
	plugins, svc, audit, out := start()
	users, _ := svc.Users(ctx)
	if len(users) != 1 || users[0].Name != "root" || users[0].Role != plugin.RoleAdmin {
		t.Fatalf("bootstrap: %+v", users)
	}
	pw := "changed-through-the-api"
	if _, err := svc.UpdateUser(ctx, "root", auth.UserUpdate{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	auditReload(ctx, audit, "/etc/packeteer/config.yaml", "SIGHUP", []string{"thresholds"}, nil, nil)
	if len(out.events) != 2 || out.events[0].Fields["action"] != "auth.bootstrap" || out.events[1].Fields["action"] != "config.reload" {
		t.Fatalf("events: %+v", out.events)
	}
	_ = plugins.Stop(ctx)

	// Restart: the API-set password survives, nothing new is created.
	plugins, _, audit, out = start()
	defer plugins.Stop(ctx)
	store := plugins.Storage.Plugin.(plugin.UserStore)
	u, _, _ := store.User(ctx, "root")
	if !auth.VerifyPassword(u.PasswordHash, pw) {
		t.Fatal("bootstrap reset the password on restart")
	}
	if len(out.events) != 0 {
		t.Fatalf("restart audited a bootstrap: %+v", out.events)
	}
	recs, err := audit.Query(ctx, plugin.AuditQuery{})
	if err != nil || len(recs) != 2 || recs[0].Action != "config.reload" || recs[1].Action != "auth.bootstrap" {
		t.Fatalf("stored audit: %+v %v", recs, err)
	}
	if !strings.Contains(recs[0].Detail, "SIGHUP applied thresholds") {
		t.Fatalf("reload detail: %q", recs[0].Detail)
	}
	// No auth: no service, but the auditor still stores.
	cfg.Auth = nil
	if svc, err := newAuthService(cfg, plugins, log); svc != nil || err != nil {
		t.Fatalf("auth off: %v %v", svc, err)
	}
}
