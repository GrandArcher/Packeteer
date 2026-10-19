package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/auth/authtest"
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
		bootstrapAdmin(ctx, svc, audit, plugins, env, log)
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

// firstRunStore builds the real sqlite store and the auth wiring for the
// first-run tests. It returns the data directory and the restart function.
func firstRunStore(t *testing.T, logs io.Writer, env func(string) string) (dir string, start func() (*pluginhost.Set, *auth.Service)) {
	t.Helper()
	auth.SetHashIterations(1000)
	dir = t.TempDir()
	cfg, err := config.Parse([]byte("mode: observe\nasn: 64512\nrouter_id: 192.0.2.10\nproviders:\n  - name: a\n    source_ip: 192.0.2.11\n    next_hop: 192.0.2.1\n" +
		"storage:\n  type: sqlite\n  config: {path: " + dir + "/p.db}\nauth:\n  enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(logs, nil))
	ctx := context.Background()
	return dir, func() (*pluginhost.Set, *auth.Service) {
		plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log})
		if err != nil {
			t.Fatal(err)
		}
		if err := plugins.Start(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = plugins.Stop(ctx) })
		svc, err := newAuthService(cfg, plugins, log)
		if err != nil {
			t.Fatal(err)
		}
		bootstrapAdmin(ctx, svc, newAuditor(plugins, nil, log), plugins, env, log)
		return plugins, svc
	}
}

// TestFirstRunGeneratesAdminPassword: with no user and no
// PACKETEER_ADMIN_PASSWORD the controller creates admin with a random
// password, logs it once, writes it to a 0600 file in the data directory,
// and the account must change it; the change removes the file (#328).
func TestFirstRunGeneratesAdminPassword(t *testing.T) {
	var logs bytes.Buffer
	dir, start := firstRunStore(t, &logs, noEnv)
	ctx := context.Background()
	plugins, _ := start()
	store := plugins.Storage.Plugin.(plugin.UserStore)
	u, found, _ := store.User(ctx, "admin")
	if !found || u.Role != plugin.RoleAdmin || !u.MustChange {
		t.Fatalf("generated admin: %+v %v", u, found)
	}
	path := filepath.Join(dir, firstRunPasswordFile)
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("password file: %v %v", st, err)
	}
	body, _ := os.ReadFile(path)
	var pw string
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, "password: "); ok {
			pw = v
		}
	}
	if len(pw) < 20 || !auth.VerifyPassword(u.PasswordHash, pw) {
		t.Fatalf("file %q does not hold the admin password", body)
	}
	if strings.Count(logs.String(), pw) != 1 || !strings.Contains(logs.String(), "generated admin password") {
		t.Fatalf("password must be logged exactly once:\n%s", logs.String())
	}

	// A restart before the change creates nothing new and does not log it again.
	_ = plugins.Stop(ctx)
	logs.Reset()
	plugins, svc := start()
	if strings.Contains(logs.String(), pw) {
		t.Fatalf("restart logged the password again:\n%s", logs.String())
	}
	if us, _ := svc.Users(ctx); len(us) != 1 {
		t.Fatalf("restart changed the users: %+v", us)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("restart before the change removed the password file: %v", err)
	}

	// The change clears the flag and removes the file.
	req := httptest.NewRequest("POST", "/api/account/password", nil)
	if err := svc.ChangePassword(httptest.NewRecorder(), req, auth.Principal{User: "admin", Role: plugin.RoleAdmin, Method: auth.MethodPassword}, pw, "a-new-long-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("password file kept after the change: %v", err)
	}
	store = plugins.Storage.Plugin.(plugin.UserStore)
	if u, _, _ := store.User(ctx, "admin"); u.MustChange || !auth.VerifyPassword(u.PasswordHash, "a-new-long-password") {
		t.Fatalf("after the change: %+v", u)
	}
}

// With PACKETEER_ADMIN_PASSWORD set the operator chose the password, so
// nothing is generated and no change is forced (#328).
func TestFirstRunKeepsOperatorChoice(t *testing.T) {
	var logs bytes.Buffer
	dir, start := firstRunStore(t, &logs, envOf(map[string]string{AdminPassEnv: "operator-chosen-password"}))
	plugins, _ := start()
	u, found, _ := plugins.Storage.Plugin.(plugin.UserStore).User(context.Background(), "admin")
	if !found || u.MustChange {
		t.Fatalf("env admin: %+v %v", u, found)
	}
	if _, err := os.Stat(filepath.Join(dir, firstRunPasswordFile)); !os.IsNotExist(err) {
		t.Fatalf("password file written for an operator password: %v", err)
	}
}

// DefaultAuth runs in preflight: a file with no auth block gets sign-in and
// sqlite; an explicit false stays off and warns; PACKETEER_HTTP_USER keeps
// its basic-auth account; an install with the HTTP server off is untouched (#328).
func TestSecureByDefault(t *testing.T) {
	base := "mode: observe\nasn: 64512\nrouter_id: 192.0.2.10\nproviders:\n  - name: a\n    source_ip: 192.0.2.11\n    next_hop: 192.0.2.1\n"
	check := func(t *testing.T, extra string, env map[string]string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(path, []byte(base+extra), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		if code := run(context.Background(), []string{"-check", "-config", path}, envOf(env), &out, &errOut); code != 0 {
			t.Fatalf("exit %d: %s", code, errOut.String())
		}
		return out.String()
	}
	if out := check(t, "", nil); !strings.Contains(out, "http auth: rbac (users, tokens, and audit in storage sqlite") {
		t.Errorf("no auth block should sign in:\n%s", out)
	}
	if out := check(t, "auth: {enabled: false}\n", nil); !strings.Contains(out, "http auth: off") {
		t.Errorf("explicit opt-out:\n%s", out)
	}
	if out := check(t, "", map[string]string{HTTPUserEnv: "ops", HTTPPassEnv: "secret"}); !strings.Contains(out, "http auth: basic (user ops)") {
		t.Errorf("basic auth install:\n%s", out)
	}
	if out := check(t, "", map[string]string{HTTPListenEnv: "off"}); !strings.Contains(out, "http: disabled") || strings.Contains(out, "rbac") {
		t.Errorf("http off:\n%s", out)
	}

	cfg, err := config.Parse([]byte(base + "auth: {enabled: false}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	warnAuthOff(cfg, "", log)
	if !strings.Contains(logs.String(), "auth.enabled is false") {
		t.Errorf("no warning for the opt-out: %q", logs.String())
	}
	logs.Reset()
	warnAuthOff(cfg, "ops", log)
	if logs.Len() != 0 {
		t.Errorf("warning although basic auth protects the server: %q", logs.String())
	}
}

// The password file goes away at start once no user has to change a
// generated password: here the store does not have the file's user, as
// when the storage file was replaced (#328).
func TestFirstRunPasswordFileSwept(t *testing.T) {
	var logs bytes.Buffer
	dir, start := firstRunStore(t, &logs, envOf(map[string]string{AdminPassEnv: "operator-chosen-password"}))
	ctx := context.Background()
	path := filepath.Join(dir, firstRunPasswordFile)
	if err := writeFirstRunPassword(path, "gone", "old-generated-password"); err != nil {
		t.Fatal(err)
	}
	plugins, _ := start()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stale password file kept: %v", err)
	}

	// A must-change user still in the store keeps the file.
	store := plugins.Storage.Plugin.(plugin.UserStore)
	if err := store.PutUser(ctx, plugin.User{Name: "pending", Role: plugin.RoleAdmin, Source: plugin.UserLocal, PasswordHash: "x", MustChange: true}); err != nil {
		t.Fatal(err)
	}
	if err := writeFirstRunPassword(path, "pending", "generated-password-1"); err != nil {
		t.Fatal(err)
	}
	_ = plugins.Stop(ctx)
	start()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file removed while its user still has to change: %v", err)
	}
}

// hiddenUsers lists no users, so a start sees an empty store while
// another start has already created the admin.
type hiddenUsers struct{ *authtest.Store }

func (hiddenUsers) Users(context.Context) ([]plugin.User, error) { return nil, nil }

// When another start created the admin first, the generated password is
// dropped and the log does not blame PACKETEER_ADMIN_PASSWORD (#328).
func TestFirstRunAdminCreatedConcurrently(t *testing.T) {
	ctx := context.Background()
	st := authtest.New()
	if err := st.PutUser(ctx, plugin.User{Name: "admin", Role: plugin.RoleAdmin, Source: plugin.UserLocal, PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	svc, err := auth.New(auth.Options{Users: hiddenUsers{st}, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	bootstrapAdmin(ctx, svc, auth.NewAuditor(nil, nil, log), nil, noEnv, log)
	if !strings.Contains(logs.String(), "admin already exists; no password generated") || strings.Contains(logs.String(), AdminPassEnv) || strings.Contains(logs.String(), "generated admin password") {
		t.Fatalf("log:\n%s", logs.String())
	}
	if u, _, _ := st.User(ctx, "admin"); u.MustChange || u.PasswordHash != "x" {
		t.Fatalf("existing admin changed: %+v", u)
	}
}
