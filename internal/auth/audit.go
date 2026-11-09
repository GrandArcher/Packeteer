package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Audit results.
const (
	ResultOK     = "ok"
	ResultDenied = "denied"
	ResultFailed = "failed"
)

// ErrNoAuditStore is returned by Query when no storage plugin keeps the
// audit log.
var ErrNoAuditStore = errors.New("the audit log needs a storage plugin that keeps it (storage: sqlite)")

// Auditor writes the audit log (#32): every change on the ops API, every
// denied change, every sign-in and sign-out, and config reloads. Each
// record goes to the log, to the storage plugin when it keeps the audit
// log, and to the notifiers as an audit.recorded event. A store or
// notifier failure is logged and never blocks the change itself.
type Auditor struct {
	store plugin.AuditStore
	emit  func(plugin.Event)
	log   *slog.Logger
	now   func() time.Time
}

// NewAuditor returns an auditor. store and emit may be nil.
func NewAuditor(store plugin.AuditStore, emit func(plugin.Event), log *slog.Logger) *Auditor {
	if log == nil {
		log = slog.Default()
	}
	return &Auditor{store: store, emit: emit, log: log, now: time.Now}
}

// Stored reports whether records are kept for Query.
func (a *Auditor) Stored() bool { return a != nil && a.store != nil }

// Record stamps r with an ID and time and writes it everywhere. It is
// safe on a nil Auditor.
func (a *Auditor) Record(ctx context.Context, r plugin.AuditRecord) plugin.AuditRecord {
	if a == nil {
		return r
	}
	r.ID = randomHex(8)
	r.Time = a.now().UTC()
	if r.Result == "" {
		r.Result = ResultOK
	}
	a.log.Info("audit", "actor", r.Actor, "role", string(r.Role), "method", r.Method, "remote", r.Remote,
		"action", r.Action, "target", r.Target, "result", r.Result, "status", r.Status, "detail", r.Detail)
	if a.store != nil {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if err := a.store.AppendAudit(wctx, r); err != nil {
			a.log.Error("audit store write failed", "id", r.ID, "err", err)
		}
		cancel()
	}
	if a.emit != nil {
		a.emit(plugin.NewEvent(plugin.EventAudit, r.Time, auditMessage(r), auditFields(r)))
	}
	return r
}

// Query reads stored records, newest first.
func (a *Auditor) Query(ctx context.Context, q plugin.AuditQuery) ([]plugin.AuditRecord, error) {
	if !a.Stored() {
		return nil, ErrNoAuditStore
	}
	return a.store.Audit(ctx, q)
}

func auditMessage(r plugin.AuditRecord) string {
	var b strings.Builder
	b.WriteString(r.Actor)
	if r.Role != "" {
		b.WriteString(" (" + string(r.Role) + ")")
	}
	b.WriteString(" " + r.Action)
	if r.Target != "" {
		b.WriteString(" " + r.Target)
	}
	b.WriteString(": " + r.Result)
	return b.String()
}

func auditFields(r plugin.AuditRecord) map[string]string {
	f := map[string]string{"id": r.ID, "actor": r.Actor, "method": r.Method, "action": r.Action, "result": r.Result}
	add := func(k, v string) {
		if v != "" {
			f[k] = v
		}
	}
	add("role", string(r.Role))
	add("remote", r.Remote)
	add("target", r.Target)
	add("detail", r.Detail)
	if r.Status != 0 {
		f["status"] = strconv.Itoa(r.Status)
	}
	return f
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(b)
}
