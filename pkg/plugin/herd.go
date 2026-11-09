package plugin

import (
	"context"
	"net/netip"
	"time"
)

// ---- Herd store (#260) ----

// HerdRecord is one stored herd measurement record (docs/design/herd.md).
// The core owns the record format; the store keeps Body as is and indexes
// the other fields for queries. A store must not interpret Body.
type HerdRecord struct {
	// Member is the key id of the node that signed the record. Empty for
	// this node's own records.
	Member      string
	ID          string
	Granularity string
	// Prefix is the exact learned route (route level). Invalid at origin-ASN
	// level.
	Prefix      netip.Prefix
	OriginASN   uint32
	ProviderASN uint32
	// Time is the start of the round. For a pulled record it is already
	// converted to the local clock.
	Time time.Time
	// Body is the record as served. Meta is kept on this node only and is
	// never served: for an own record, the prefixes and AS paths that went
	// into it, so the exclude list can be applied to data stored earlier.
	Body []byte
	Meta []byte
}

// HerdQuery selects stored herd records, ordered by prefix, provider ASN,
// time, member, then id, so pages are stable.
type HerdQuery struct {
	// Member selects one member's rows. Empty selects this node's own
	// rows. AnyMember selects every row.
	Member      string
	AnyMember   bool
	OriginASN   uint32 // 0: any
	ProviderASN uint32 // 0: any
	// Prefix, when valid, selects route-level rows by Match: "exact",
	// "covering" (rows that cover Prefix), or "covered" (rows inside it).
	Prefix netip.Prefix
	Match  string
	// From and To bound Time to [From, To). A zero bound is open.
	From, To time.Time
	// After resumes after this row (the last row of the previous page).
	After *HerdRecord
	// Newest orders by time, newest first, instead of by prefix. After is
	// not used with it.
	Newest bool
	Limit  int
}

// HerdStats is what the herd tables hold, for budgets and the status API.
type HerdStats struct {
	LocalRecords  int
	LocalBytes    int64
	PulledRecords int
	PulledBytes   int64
	// PerMember counts pulled rows by member.
	PerMember map[string]int
}

// HerdStore is optional on a storage plugin: herd records live in tables
// of their own, apart from report history. It does not announce and does
// not change a decision.
type HerdStore interface {
	// PutHerdRecords inserts rows. A row with the same Member and ID is
	// kept as it was. It returns how many rows were new.
	PutHerdRecords(ctx context.Context, recs []HerdRecord) (int, error)
	HerdRecords(ctx context.Context, q HerdQuery) ([]HerdRecord, error)
	// DeleteHerdBefore deletes every row whose Time is before t, own and
	// pulled, and returns how many.
	DeleteHerdBefore(ctx context.Context, t time.Time) (int, error)
	// TrimHerd deletes the oldest own or pulled rows until that class
	// holds at most maxBytes of Body, and returns how many it deleted.
	TrimHerd(ctx context.Context, pulled bool, maxBytes int64) (int, error)
	HerdStats(ctx context.Context) (HerdStats, error)
}
