package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

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
	if plugins.SSO != nil {
		o.SSO = plugins.SSO.Plugin
	}
	return auth.New(o)
}

// bootstrapAdmin creates the first admin from the environment once the
// store is open. An existing user of that name is left alone.
func bootstrapAdmin(ctx context.Context, svc *auth.Service, audit *auth.Auditor, getenv func(string) string, log *slog.Logger) {
	if svc == nil {
		return
	}
	name, pw := getenv(AdminUserEnv), getenv(AdminPassEnv)
	if name == "" {
		name = "admin"
	}
	if pw != "" {
		created, err := svc.Bootstrap(ctx, name, pw)
		switch {
		case err != nil:
			log.Error("auth: bootstrap admin", "user", name, "err", err)
		case created:
			log.Info("auth: created admin from the environment", "user", name)
			audit.Record(ctx, plugin.AuditRecord{Actor: "system", Method: auth.MethodSystem, Action: "auth.bootstrap", Target: name,
				Detail: "admin created from " + AdminPassEnv})
		default:
			log.Info("auth: admin already exists; " + AdminPassEnv + " is ignored")
		}
	}
	if has, err := svc.HasUsers(ctx); err == nil && !has && !svc.SSOEnabled() {
		log.Warn("auth is on but there are no users: nobody can use the API; set " + AdminPassEnv)
	}
}

// auditReload records a SIGHUP config reload.
func auditReload(ctx context.Context, audit *auth.Auditor, path string, refused, fatal error) {
	rec := plugin.AuditRecord{Actor: "system", Method: auth.MethodSystem, Action: "config.reload", Target: path, Detail: "SIGHUP"}
	switch {
	case fatal != nil:
		rec.Result, rec.Detail = auth.ResultFailed, "SIGHUP: "+fatal.Error()
	case refused != nil:
		rec.Result, rec.Detail = auth.ResultFailed, "SIGHUP refused: "+refused.Error()
	}
	audit.Record(ctx, rec)
}
