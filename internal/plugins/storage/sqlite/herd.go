package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Herd records (#260). Own rows have member ''; pulled rows carry the
// signing member's key id. The global retention prune does not touch these
// tables: herd sets its own retention and budgets and calls DeleteHerdBefore
// and TrimHerd. lo and hi are the first and last address of the route as 16
// bytes (IPv4 mapped), empty at origin-ASN level, so covering and covered
// matches are byte comparisons.

var _ plugin.HerdStore = (*Store)(nil)

const herdSchema = `
CREATE TABLE IF NOT EXISTS herd_records (
	member TEXT NOT NULL,
	id TEXT NOT NULL,
	granularity TEXT NOT NULL,
	v6 INTEGER NOT NULL,
	lo BLOB NOT NULL,
	hi BLOB NOT NULL,
	origin_asn INTEGER NOT NULL,
	provider_asn INTEGER NOT NULL,
	time_ms INTEGER NOT NULL,
	body BLOB NOT NULL,
	meta BLOB NOT NULL,
	PRIMARY KEY (member, id)
);
CREATE INDEX IF NOT EXISTS herd_records_order ON herd_records (lo, hi, provider_asn, time_ms);
CREATE INDEX IF NOT EXISTS herd_records_origin ON herd_records (origin_asn, time_ms);
CREATE INDEX IF NOT EXISTS herd_records_time ON herd_records (time_ms);
`

// herd_stats holds the row count and body bytes per member, kept by
// triggers in the same transaction as every insert and delete. Stats and
// trimming read it instead of scanning herd_records: the store has one
// connection that report history shares, and a scan of up to 1 GiB of rows
// would stall history writes.
const herdStatsSchema = `
CREATE TABLE herd_stats (
	member TEXT PRIMARY KEY,
	records INTEGER NOT NULL,
	bytes INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS herd_stats_insert AFTER INSERT ON herd_records BEGIN
	INSERT INTO herd_stats (member, records, bytes) VALUES (NEW.member, 1, length(NEW.body))
	ON CONFLICT (member) DO UPDATE SET records = records + 1, bytes = bytes + length(NEW.body);
END;
CREATE TRIGGER IF NOT EXISTS herd_stats_delete AFTER DELETE ON herd_records BEGIN
	UPDATE herd_stats SET records = records - 1, bytes = bytes - length(OLD.body) WHERE member = OLD.member;
	DELETE FROM herd_stats WHERE member = OLD.member AND records <= 0;
END;
`

// ensureHerdStats creates herd_stats and its triggers. A database from
// before the table existed gets one scan of herd_records, once, in the
// same transaction.
func ensureHerdStats(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'herd_stats'`).Scan(&n); err != nil || n > 0 {
		return err
	}
	if _, err := tx.ExecContext(ctx, herdStatsSchema); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO herd_stats (member, records, bytes)
SELECT member, COUNT(*), SUM(length(body)) FROM herd_records GROUP BY member`); err != nil {
		return err
	}
	return tx.Commit()
}

// herdBounds is the first and last address of p. An invalid prefix has
// none.
func herdBounds(p netip.Prefix) (lo, hi []byte, v6 bool) {
	if !p.IsValid() {
		return []byte{}, []byte{}, false
	}
	p = p.Masked()
	a := p.Addr().As16()
	b := a
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	for i := bits; i < 128; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	return a[:], b[:], p.Addr().Is6() && !p.Addr().Is4In6()
}

// PutHerdRecords inserts rows, keeping any row that is already stored.
func (s *Store) PutHerdRecords(ctx context.Context, recs []plugin.HerdRecord) (int, error) {
	if len(recs) == 0 {
		return 0, nil
	}
	db, err := s.handle()
	if err != nil {
		return 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	added := 0
	for i, r := range recs {
		if r.ID == "" || r.Time.IsZero() || len(r.Body) == 0 {
			return 0, fmt.Errorf("herd record %d has no id, time, or body", i)
		}
		lo, hi, v6 := herdBounds(r.Prefix)
		meta := r.Meta
		if meta == nil {
			meta = []byte{}
		}
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO herd_records
(member, id, granularity, v6, lo, hi, origin_asn, provider_asn, time_ms, body, meta)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.Member, r.ID, r.Granularity, v6, lo, hi, r.OriginASN, r.ProviderASN, ms(r.Time), r.Body, meta)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	return added, tx.Commit()
}

// HerdRecords returns the rows q selects.
func (s *Store) HerdRecords(ctx context.Context, q plugin.HerdQuery) ([]plugin.HerdRecord, error) {
	if q.Limit <= 0 {
		return nil, fmt.Errorf("herd query needs a positive limit")
	}
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	var where []string
	var args []any
	add := func(cond string, a ...any) {
		where = append(where, cond)
		args = append(args, a...)
	}
	if !q.AnyMember {
		add("member = ?", q.Member)
	}
	if q.OriginASN != 0 {
		add("origin_asn = ?", q.OriginASN)
	}
	if q.ProviderASN != 0 {
		add("provider_asn = ?", q.ProviderASN)
	}
	if q.Prefix.IsValid() {
		lo, hi, v6 := herdBounds(q.Prefix)
		add("length(lo) = 16 AND v6 = ?", v6)
		switch q.Match {
		case "exact":
			add("lo = ? AND hi = ?", lo, hi)
		case "covering":
			add("lo <= ? AND hi >= ?", lo, hi)
		case "covered":
			add("lo >= ? AND hi <= ?", lo, hi)
		default:
			return nil, fmt.Errorf("herd match %q is not exact, covering, or covered", q.Match)
		}
	}
	if !q.From.IsZero() {
		add("time_ms >= ?", ms(q.From))
	}
	if !q.To.IsZero() {
		add("time_ms < ?", ms(q.To))
	}
	if a := q.After; a != nil {
		lo, hi, _ := herdBounds(a.Prefix)
		add("(lo, hi, provider_asn, time_ms, member, id) > (?, ?, ?, ?, ?, ?)",
			lo, hi, a.ProviderASN, ms(a.Time), a.Member, a.ID)
	}
	qs := `SELECT member, id, granularity, lo, origin_asn, provider_asn, time_ms, body, meta, v6, hi FROM herd_records`
	if len(where) > 0 {
		qs += " WHERE " + strings.Join(where, " AND ")
	}
	order := "lo, hi, provider_asn, time_ms, member, id"
	if q.Newest {
		order = "time_ms DESC, lo, hi, provider_asn, member, id"
	}
	qs += " ORDER BY " + order + " LIMIT ?"
	args = append(args, q.Limit)
	rows, err := db.QueryContext(ctx, qs, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []plugin.HerdRecord
	for rows.Next() {
		var r plugin.HerdRecord
		var lo, hi []byte
		var t int64
		var v6 bool
		if err := rows.Scan(&r.Member, &r.ID, &r.Granularity, &lo, &r.OriginASN, &r.ProviderASN, &t, &r.Body, &r.Meta, &v6, &hi); err != nil {
			return nil, err
		}
		r.Time = fromMS(t)
		r.Prefix = herdPrefix(lo, hi, v6)
		out = append(out, r)
	}
	return out, rows.Err()
}

// herdPrefix rebuilds the route from its bounds. The length is the number
// of leading bits lo and hi share.
func herdPrefix(lo, hi []byte, v6 bool) netip.Prefix {
	if len(lo) != 16 || len(hi) != 16 {
		return netip.Prefix{}
	}
	bits := 0
	for i := 0; i < 16; i++ {
		if lo[i] == hi[i] {
			bits += 8
			continue
		}
		for m := byte(0x80); m != 0 && lo[i]&m == hi[i]&m; m >>= 1 {
			bits++
		}
		break
	}
	var a [16]byte
	copy(a[:], lo)
	addr := netip.AddrFrom16(a)
	if !v6 {
		addr = addr.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(addr, bits)
}

// DeleteHerdBefore deletes rows older than t.
func (s *Store) DeleteHerdBefore(ctx context.Context, t time.Time) (int, error) {
	db, err := s.handle()
	if err != nil {
		return 0, err
	}
	res, err := db.ExecContext(ctx, `DELETE FROM herd_records WHERE time_ms < ?`, ms(t))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// TrimHerd deletes the oldest rows of one class until it fits maxBytes. It
// reads the class size from herd_stats and scans rows only when over.
func (s *Store) TrimHerd(ctx context.Context, pulled bool, maxBytes int64) (int, error) {
	db, err := s.handle()
	if err != nil {
		return 0, err
	}
	cond := "member = ''"
	if pulled {
		cond = "member <> ''"
	}
	var total int64
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes), 0) FROM herd_stats WHERE `+cond).Scan(&total); err != nil {
		return 0, err
	}
	dropped := 0
	for total > maxBytes {
		rows, err := db.QueryContext(ctx, `SELECT rowid, length(body) FROM herd_records WHERE `+cond+` ORDER BY time_ms LIMIT 256`)
		if err != nil {
			return dropped, err
		}
		var ids []any
		for rows.Next() && total > maxBytes {
			var id, n int64
			if err := rows.Scan(&id, &n); err != nil {
				_ = rows.Close()
				return dropped, err
			}
			ids = append(ids, id)
			total -= n
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return dropped, err
		}
		_ = rows.Close()
		if len(ids) == 0 {
			break
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM herd_records WHERE rowid IN (?`+strings.Repeat(",?", len(ids)-1)+`)`, ids...); err != nil {
			return dropped, err
		}
		dropped += len(ids)
	}
	return dropped, nil
}

// HerdStats counts the stored rows from herd_stats, without scanning
// herd_records.
func (s *Store) HerdStats(ctx context.Context) (plugin.HerdStats, error) {
	out := plugin.HerdStats{PerMember: map[string]int{}}
	db, err := s.handle()
	if err != nil {
		return out, err
	}
	rows, err := db.QueryContext(ctx, `SELECT member, records, bytes FROM herd_stats`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var member string
		var n int
		var b int64
		if err := rows.Scan(&member, &n, &b); err != nil {
			return out, err
		}
		if member == "" {
			out.LocalRecords, out.LocalBytes = n, b
			continue
		}
		out.PulledRecords += n
		out.PulledBytes += b
		out.PerMember[member] = n
	}
	return out, rows.Err()
}
