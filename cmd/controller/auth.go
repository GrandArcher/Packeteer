package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// firstRunPasswordFile is written in the storage directory with the
// generated first-run admin password (#328). It is removed when that
// password no longer signs in.
const firstRunPasswordFile = "first-run-admin-password"

// storageFile is the storage plugin's file, or "" when it has none.
func storageFile(plugins *pluginhost.Set) string {
	if plugins == nil || plugins.Storage == nil {
		return ""
	}
	f, ok := plugins.Storage.Plugin.(interface{ Path() string })
	if !ok {
		return ""
	}
	return f.Path()
}

// besideStorage is the path of a state file next to the storage file, or ""
// when the storage plugin has no file.
func besideStorage(plugins *pluginhost.Set, name string) string {
	db := storageFile(plugins)
	if db == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(db), name)
}

// writeFirstRunPassword writes the generated password with mode 0600.
func writeFirstRunPassword(path, user, pw string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// A file left by an earlier run keeps its old mode on open.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := fmt.Fprintf(f, "user: %s\npassword: %s\n", user, pw); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// removeFirstRunPassword deletes the file once its password no longer
// signs in, so a dead password does not sit on the volume.
func removeFirstRunPassword(path string, log *slog.Logger) {
	err := os.Remove(path)
	switch {
	case err == nil:
		log.Info("auth: removed the first-run password file; its password no longer signs in", "path", path)
	case !errors.Is(err, os.ErrNotExist):
		log.Warn("auth: remove first-run password file", "path", path, "err", err)
	}
}

// checkAuth refuses a config whose auth cannot work (#32): auth together
// with the basic-auth account, a storage plugin that keeps no users, or a
// bootstrap password that is too short.
func checkAuth(cfg *config.Config, plugins *pluginhost.Set, httpUser string, getenv func(string) string) error {
	if !cfg.AuthEnabled() {
		return nil
	}
	if httpUser != "" {
		return fmt.Errorf("auth replaces %s and %s; unset them (the first admin comes from %s and %s)", HTTPUserEnv, HTTPPassEnv, AdminUserEnv, AdminPassEnv)
	}
	if plugins.Storage == nil {
		return errors.New("auth requires a storage plugin")
	}
	if _, ok := plugins.Storage.Plugin.(plugin.UserStore); !ok {
		return fmt.Errorf("auth: storage %s does not keep users and tokens", plugins.Storage.Type)
	}
	if _, ok := plugins.Storage.Plugin.(plugin.AuditStore); !ok {
		return fmt.Errorf("auth: storage %s does not keep the audit log", plugins.Storage.Type)
	}
	if pw := getenv(AdminPassEnv); pw != "" {
		if err := auth.CheckPassword(pw); err != nil {
			return fmt.Errorf("%s: %v", AdminPassEnv, err)
		}
	}
	if u := getenv(AdminUserEnv); u != "" && !auth.ValidUserName(u) {
		return fmt.Errorf("%s %q is not a valid user name", AdminUserEnv, u)
	}
	return nil
}

// warnAuthOff logs once at start when auth.enabled: false leaves the HTTP
// server open, the opt-out from the secure default (#328). The UI shows a
// banner too.
func warnAuthOff(cfg *config.Config, httpUser string, log *slog.Logger) {
	if cfg.AuthOptedOut() && cfg.HTTPListen() != "" && httpUser == "" {
		log.Warn("auth.enabled is false: anyone who can reach " + cfg.HTTPListen() + " can read the dashboard and API without signing in; remove it (or set true) to require sign-in")
	}
}

// newAuditor writes the audit log to the storage plugin, when it keeps
// one, and to the notifiers. It runs with or without auth.
func newAuditor(plugins *pluginhost.Set, out emitter, log *slog.Logger) *auth.Auditor {
	var store plugin.AuditStore
	if plugins != nil && plugins.Storage != nil {
		store, _ = plugins.Storage.Plugin.(plugin.AuditStore)
	}
	var emit func(plugin.Event)
	if out != nil {
		emit = out.Emit
	}
	return auth.NewAuditor(store, emit, log)
}

// newAuthService is nil when auth is off. checkAuth has run.
func newAuthService(cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger) (*auth.Service, error) {
	if !cfg.AuthEnabled() {
		return nil, nil
	}
	users, _ := plugins.Storage.Plugin.(plugin.UserStore)
	o := auth.Options{Users: users, SessionTTL: cfg.Auth.SessionTTL, TokenTTL: cfg.Auth.TokenTTL, Logger: log}
	if path := besideStorage(plugins, firstRunPasswordFile); path != "" {
		o.OnGeneratedGone = func(user string) {
			log.Info("auth: generated password replaced or its user deleted", "user", user)
			removeFirstRunPassword(path, log)
		}
	}
	if plugins.SSO != nil {
		o.SSO = plugins.SSO.Plugin
	}
	return auth.New(o)
}

// bootstrapAdmin creates the first admin once the store is open. The
// password is PACKETEER_ADMIN_PASSWORD. With none set and no user yet (and
// no single sign-on), it generates one, logs it once, writes it to a 0600
// file next to the storage file, and limits the account to a password
// change (#328). An existing user of that name is left alone. A password
// file left by an earlier run is removed once no user still has to change
// a generated password (the user was deleted, or the store was replaced).
func bootstrapAdmin(ctx context.Context, svc *auth.Service, audit *auth.Auditor, plugins *pluginhost.Set, getenv func(string) string, log *slog.Logger) {
	if svc == nil {
		return
	}
	name, pw := getenv(AdminUserEnv), getenv(AdminPassEnv)
	if name == "" {
		name = "admin"
	}
	generated := false
	if pw == "" {
		has, err := svc.HasUsers(ctx)
		switch {
		case err != nil:
			log.Error("auth: is on but the user list cannot be read; no admin was created", "err", err)
		case has:
		case svc.SSOEnabled():
			log.Info("auth: no users yet; single sign-on creates them at sign-in, or set " + AdminPassEnv + " for a local admin")
		default:
			pw, generated = auth.GeneratePassword(), true
		}
	}
	if !generated {
		if path := besideStorage(plugins, firstRunPasswordFile); path != "" {
			switch pending, err := svc.ChangePending(ctx); {
			case err != nil:
				log.Warn("auth: cannot read the users; first-run password file not checked", "err", err)
			case !pending:
				removeFirstRunPassword(path, log)
			}
		}
	}
	if pw == "" {
		return
	}
	created, err := svc.Bootstrap(ctx, name, pw, generated)
	switch {
	case err != nil:
		log.Error("auth: bootstrap admin", "user", name, "err", err)
	case created && generated:
		path := besideStorage(plugins, firstRunPasswordFile)
		if path != "" {
			if err := writeFirstRunPassword(path, name, pw); err != nil {
				log.Warn("auth: cannot write the first-run password file", "path", path, "err", err)
				path = ""
			}
		}
		log.Warn("auth: first run: generated admin password; sign in with it, then choose a new one",
			"user", name, "password", pw, "file", path)
		audit.Record(ctx, plugin.AuditRecord{Actor: "system", Method: auth.MethodSystem, Action: "auth.bootstrap", Target: name,
			Detail: "admin created with a generated password; change required"})
	case created:
		log.Info("auth: created admin from the environment", "user", name)
		audit.Record(ctx, plugin.AuditRecord{Actor: "system", Method: auth.MethodSystem, Action: "auth.bootstrap", Target: name,
			Detail: "admin created from " + AdminPassEnv})
	case generated:
		log.Info("auth: admin already exists; no password generated", "user", name)
	default:
		log.Info("auth: admin already exists; " + AdminPassEnv + " is ignored")
	}
}

// auditReload records one online apply. how is "SIGHUP" or "PUT /api/config".
// applied are the keys now running. A refusal or a fatal error is a failed
// record; a fatal one means the process is stopping and routes are withdrawn.
func auditReload(ctx context.Context, audit *auth.Auditor, path, how string, applied []string, refused, fatal error) {
	if how == "" {
		how = "SIGHUP"
	}
	detail := how
	if len(applied) > 0 {
		detail = how + " applied " + strings.Join(applied, ",")
	}
	rec := plugin.AuditRecord{Actor: "system", Method: auth.MethodSystem, Action: "config.reload", Target: path, Detail: detail}
	switch {
	case fatal != nil:
		rec.Result = auth.ResultFailed
		rec.Detail = how + ": " + fatal.Error()
		if len(applied) > 0 {
			rec.Detail += "; applied " + strings.Join(applied, ",")
		}
	case refused != nil:
		rec.Result, rec.Detail = auth.ResultFailed, how+" refused: "+refused.Error()
	}
	audit.Record(ctx, rec)
}
