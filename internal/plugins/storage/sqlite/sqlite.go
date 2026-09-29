// Package sqlite is the default storage plugin: an embedded SQLite file
// (pure Go, no cgo) that keeps report history on a mounted volume.
//
// It stores daily probe rollups, one row per improvement, one row per
// threat mitigation rule, and per-prefix facts (origin ASN, country,
// volume). Raw probe results are not stored.
// Rows older than retention are deleted on start and once a day. The plugin
// records history only; it never announces routes or changes decisions.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "sqlite"

// Defaults and bounds.
const (
	DefaultPath      = "/var/lib/packeteer/packeteer.db"
	DefaultRetention = 400 * 24 * time.Hour
	MinRetention     = 24 * time.Hour
	MaxRetention     = 10 * 365 * 24 * time.Hour
	pruneEvery       = 24 * time.Hour
)

// Config is the plugin config block.
type Config struct {
	// Path is the database file. It must be absolute. Mount a volume on
	// its directory so history survives a container restart.
	Path string `yaml:"path"`
	// Retention deletes rows older than this (default 400 days).
	Retention time.Duration `yaml:"retention"`
}

// Store is the SQLite storage plugin.
type Store struct {
	path      string
	retention time.Duration
	env       plugin.Env
	now       func() time.Time

	mu     sync.Mutex
	db     *sql.DB
	cancel context.CancelFunc
	done   chan struct{}
}

func init() {
	plugin.Storages.Register(TypeName, func(c plugin.Config, e plugin.Env) (plugin.Storage, error) {
		return New(c, e)
	})
}

// New validates the config. It does not open the file.
func New(c plugin.Config, env plugin.Env) (*Store, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Path == "" {
		cfg.Path = DefaultPath
	}
	if !filepath.IsAbs(cfg.Path) {
		return nil, fmt.Errorf("path %q must be absolute", cfg.Path)
	}
	if cfg.Retention == 0 {
		cfg.Retention = DefaultRetention
	}
	if cfg.Retention < MinRetention || cfg.Retention > MaxRetention {
		return nil, fmt.Errorf("retention %s must be between %s and %s", cfg.Retention, MinRetention, MaxRetention)
	}
	return &Store{path: filepath.Clean(cfg.Path), retention: cfg.Retention, env: env, now: time.Now}, nil
}

// Path is the database file.
func (s *Store) Path() string { return s.path }

const schema = `
CREATE TABLE IF NOT EXISTS probe_daily (
	day INTEGER NOT NULL,
	prefix TEXT NOT NULL,
	provider TEXT NOT NULL,
	probes INTEGER NOT NULL,
	failed INTEGER NOT NULL,
	measured INTEGER NOT NULL,
	loss_sum REAL NOT NULL,
	rtt_sum_ms REAL NOT NULL,
	jitter_sum_ms REAL NOT NULL,
	PRIMARY KEY (day, prefix, provider)
);
CREATE TABLE IF NOT EXISTS improvements (
	id TEXT PRIMARY KEY,
	prefix TEXT NOT NULL,
	provider TEXT NOT NULL,
	native TEXT NOT NULL,
	cause TEXT NOT NULL,
	reason TEXT NOT NULL,
	mode TEXT NOT NULL,
	start_ms INTEGER NOT NULL,
	end_ms INTEGER NOT NULL,
	end_reason TEXT NOT NULL,
	has_before INTEGER NOT NULL,
	before_loss REAL NOT NULL,
	before_rtt_ms REAL NOT NULL,
	has_after INTEGER NOT NULL,
	after_loss REAL NOT NULL,
	after_rtt_ms REAL NOT NULL,
	cost_delta REAL NOT NULL,
	est_savings REAL NOT NULL,
	volume_mbps REAL NOT NULL,
	origin_asn INTEGER NOT NULL,
	country TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS improvements_start ON improvements (start_ms);
CREATE INDEX IF NOT EXISTS improvements_end ON improvements (end_ms);
CREATE TABLE IF NOT EXISTS mitigations (
	id TEXT PRIMARY KEY,
	prefix TEXT NOT NULL,
	action TEXT NOT NULL,
	target TEXT NOT NULL,
	match TEXT NOT NULL,
	countries TEXT NOT NULL,
	rate_mbps REAL NOT NULL,
	routes INTEGER NOT NULL,
	reason TEXT NOT NULL,
	mode TEXT NOT NULL,
	created_ms INTEGER NOT NULL,
	expires_ms INTEGER NOT NULL,
	announced_ms INTEGER NOT NULL,
	end_ms INTEGER NOT NULL,
	end_reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS mitigations_created ON mitigations (created_ms);
CREATE INDEX IF NOT EXISTS mitigations_end ON mitigations (end_ms);
CREATE TABLE IF NOT EXISTS prefixes (
	prefix TEXT PRIMARY KEY,
	origin_asn INTEGER NOT NULL,
	country TEXT NOT NULL,
	volume_mbps REAL NOT NULL,
	updated_ms INTEGER NOT NULL
);
`

// Start opens (or creates) the database and starts the daily prune.
func (s *Store) Start(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("storage dir: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+s.path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return fmt.Errorf("open %s: %w", s.path, err)
	}
	s.mu.Lock()
	s.db = db
	s.mu.Unlock()
	if err := s.prune(ctx); err != nil && s.env.Logger != nil {
		s.env.Logger.Warn("storage prune", "err", err)
	}
	loopCtx, cancel := context.WithCancel(context.Background())
	s.cancel, s.done = cancel, make(chan struct{})
	go s.pruneLoop(loopCtx)
	return nil
}

func (s *Store) pruneLoop(ctx context.Context) {
	defer close(s.done)
	t := time.NewTicker(pruneEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.prune(ctx); err != nil && s.env.Logger != nil {
				s.env.Logger.Warn("storage prune", "err", err)
			}
		}
	}
}

// Stop closes the database.
func (s *Store) Stop(context.Context) error {
	if s.cancel != nil {
		s.cancel()
		<-s.done
		s.cancel = nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *Store) handle() (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, errors.New("storage is not started")
	}
	return s.db, nil
}

// prune deletes rows older than retention. Open improvements are kept.
func (s *Store) prune(ctx context.Context) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	cutoff := s.now().Add(-s.retention)
	if _, err := db.ExecContext(ctx, `DELETE FROM probe_daily WHERE day < ?`, cutoff.Unix()); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM improvements WHERE end_ms != 0 AND end_ms < ?`, cutoff.UnixMilli()); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM mitigations WHERE end_ms != 0 AND end_ms < ?`, cutoff.UnixMilli()); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `DELETE FROM prefixes WHERE updated_ms < ?`, cutoff.UnixMilli())
	return err
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Write stores one batch in a transaction.
func (s *Store) Write(ctx context.Context, b plugin.HistoryBatch) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, k := range b.Buckets {
		if !k.Prefix.IsValid() || k.Provider == "" {
			continue
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO probe_daily (day, prefix, provider, probes, failed, measured, loss_sum, rtt_sum_ms, jitter_sum_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (day, prefix, provider) DO UPDATE SET
	probes = probes + excluded.probes,
	failed = failed + excluded.failed,
	measured = measured + excluded.measured,
	loss_sum = loss_sum + excluded.loss_sum,
	rtt_sum_ms = rtt_sum_ms + excluded.rtt_sum_ms,
	jitter_sum_ms = jitter_sum_ms + excluded.jitter_sum_ms`,
			k.Day.UTC().Unix(), k.Prefix.String(), k.Provider, k.Probes, k.Failed, k.Measured, k.LossSum, k.RTTSumMs, k.JitterSum)
		if err != nil {
			return err
		}
	}
	for _, r := range b.Improvements {
		if r.ID == "" || !r.Prefix.IsValid() {
			continue
		}
		_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO improvements (id, prefix, provider, native, cause, reason, mode, start_ms, end_ms, end_reason,
	has_before, before_loss, before_rtt_ms, has_after, after_loss, after_rtt_ms, cost_delta, est_savings, volume_mbps, origin_asn, country)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.ID, r.Prefix.String(), r.Provider, r.Native, r.Cause, r.Reason, r.Mode, ms(r.Start), ms(r.End), r.EndReason,
			b2i(r.HasBefore), r.BeforeLoss, r.BeforeRTT, b2i(r.HasAfter), r.AfterLoss, r.AfterRTT,
			r.CostDelta, r.EstSavings, r.VolumeMbps, int64(r.OriginASN), r.Country)
		if err != nil {
			return err
		}
	}
	for _, m := range b.Mitigations {
		if m.ID == "" || !m.Prefix.IsValid() {
			continue
		}
		_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO mitigations (id, prefix, action, target, match, countries, rate_mbps, routes, reason, mode,
	created_ms, expires_ms, announced_ms, end_ms, end_reason)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			m.ID, m.Prefix.String(), m.Action, m.Target, m.Match, m.Countries, m.RateMbps, m.Routes, m.Reason, m.Mode,
			ms(m.Created), ms(m.Expires), ms(m.Announced), ms(m.End), m.EndReason)
		if err != nil {
			return err
		}
	}
	for _, p := range b.Prefixes {
		if !p.Prefix.IsValid() {
			continue
		}
		_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO prefixes (prefix, origin_asn, country, volume_mbps, updated_ms) VALUES (?, ?, ?, ?, ?)`,
			p.Prefix.String(), int64(p.OriginASN), p.Country, p.VolumeMbps, ms(p.Updated))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Read returns the rows selected by q.
func (s *Store) Read(ctx context.Context, q plugin.HistoryQuery) (plugin.History, error) {
	var out plugin.History
	db, err := s.handle()
	if err != nil {
		return out, err
	}
	var imps *sql.Rows
	if q.OpenOnly {
		imps, err = db.QueryContext(ctx, `SELECT id, prefix, provider, native, cause, reason, mode, start_ms, end_ms, end_reason,
	has_before, before_loss, before_rtt_ms, has_after, after_loss, after_rtt_ms, cost_delta, est_savings, volume_mbps, origin_asn, country
FROM improvements WHERE end_ms = 0 ORDER BY start_ms, id`)
	} else {
		imps, err = db.QueryContext(ctx, `SELECT id, prefix, provider, native, cause, reason, mode, start_ms, end_ms, end_reason,
	has_before, before_loss, before_rtt_ms, has_after, after_loss, after_rtt_ms, cost_delta, est_savings, volume_mbps, origin_asn, country
FROM improvements WHERE start_ms < ? AND (end_ms = 0 OR end_ms >= ?) ORDER BY start_ms, id`, q.To.UnixMilli(), q.From.UnixMilli())
	}
	if err != nil {
		return out, err
	}
	for imps.Next() {
		var r plugin.ImprovementRecord
		var prefix string
		var start, end, asn int64
		var hb, ha int
		if err := imps.Scan(&r.ID, &prefix, &r.Provider, &r.Native, &r.Cause, &r.Reason, &r.Mode, &start, &end, &r.EndReason,
			&hb, &r.BeforeLoss, &r.BeforeRTT, &ha, &r.AfterLoss, &r.AfterRTT, &r.CostDelta, &r.EstSavings, &r.VolumeMbps, &asn, &r.Country); err != nil {
			imps.Close()
			return out, err
		}
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			continue
		}
		r.Prefix, r.Start, r.End = p, fromMS(start), fromMS(end)
		r.HasBefore, r.HasAfter, r.OriginASN = hb != 0, ha != 0, uint32(asn)
		out.Improvements = append(out.Improvements, r)
	}
	if err := imps.Err(); err != nil {
		imps.Close()
		return out, err
	}
	imps.Close()
	if out.Mitigations, err = readMitigations(ctx, db, q); err != nil {
		return out, err
	}
	if q.OpenOnly {
		return out, nil
	}

	rows, err := db.QueryContext(ctx, `SELECT day, prefix, provider, probes, failed, measured, loss_sum, rtt_sum_ms, jitter_sum_ms
FROM probe_daily WHERE day >= ? AND day < ? ORDER BY day, prefix, provider`, q.From.UTC().Truncate(24*time.Hour).Unix(), q.To.Unix())
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var k plugin.ProbeBucket
		var day int64
		var prefix string
		if err := rows.Scan(&day, &prefix, &k.Provider, &k.Probes, &k.Failed, &k.Measured, &k.LossSum, &k.RTTSumMs, &k.JitterSum); err != nil {
			rows.Close()
			return out, err
		}
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			continue
		}
		k.Day, k.Prefix = time.Unix(day, 0).UTC(), p
		out.Buckets = append(out.Buckets, k)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	rows.Close()

	pr, err := db.QueryContext(ctx, `SELECT prefix, origin_asn, country, volume_mbps, updated_ms FROM prefixes ORDER BY prefix`)
	if err != nil {
		return out, err
	}
	defer pr.Close()
	for pr.Next() {
		var info plugin.PrefixInfo
		var prefix string
		var asn, updated int64
		if err := pr.Scan(&prefix, &asn, &info.Country, &info.VolumeMbps, &updated); err != nil {
			return out, err
		}
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			continue
		}
		info.Prefix, info.OriginASN, info.Updated = p, uint32(asn), fromMS(updated)
		out.Prefixes = append(out.Prefixes, info)
	}
	return out, pr.Err()
}

func readMitigations(ctx context.Context, db *sql.DB, q plugin.HistoryQuery) ([]plugin.MitigationRecord, error) {
	const cols = `SELECT id, prefix, action, target, match, countries, rate_mbps, routes, reason, mode,
	created_ms, expires_ms, announced_ms, end_ms, end_reason FROM mitigations`
	var rows *sql.Rows
	var err error
	if q.OpenOnly {
		rows, err = db.QueryContext(ctx, cols+` WHERE end_ms = 0 ORDER BY created_ms, id`)
	} else {
		rows, err = db.QueryContext(ctx, cols+` WHERE created_ms < ? AND (end_ms = 0 OR end_ms >= ?) ORDER BY created_ms, id`,
			q.To.UnixMilli(), q.From.UnixMilli())
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []plugin.MitigationRecord
	for rows.Next() {
		var m plugin.MitigationRecord
		var prefix string
		var created, expires, announced, end int64
		if err := rows.Scan(&m.ID, &prefix, &m.Action, &m.Target, &m.Match, &m.Countries, &m.RateMbps, &m.Routes, &m.Reason, &m.Mode,
			&created, &expires, &announced, &end, &m.EndReason); err != nil {
			return nil, err
		}
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			continue
		}
		m.Prefix, m.Created, m.Expires, m.Announced, m.End = p, fromMS(created), fromMS(expires), fromMS(announced), fromMS(end)
		out = append(out, m)
	}
	return out, rows.Err()
}
