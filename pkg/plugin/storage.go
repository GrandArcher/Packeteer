package plugin

import (
	"context"
	"io"
	"net/netip"
	"time"
)

// ---- Storage ----

// ProbeBucket is the daily rollup of one provider's measurements toward one
// prefix. Day is midnight UTC. Sums are over the Measured probes (the ones
// that returned statistics); Failed counts probes with no measurement. A
// store merges buckets that share Day, Prefix, and Provider by adding them.
type ProbeBucket struct {
	Day       time.Time
	Prefix    netip.Prefix
	Provider  string
	Probes    int
	Failed    int
	Measured  int
	LossSum   float64
	RTTSumMs  float64
	JitterSum float64 // milliseconds
}

// ImprovementRecord is one improvement from start to end. A switch to
// another provider ends one record and starts another. End is zero while
// the improvement is active. Before is the native provider's measurement
// and After the chosen provider's, both at the decision that started it.
type ImprovementRecord struct {
	ID         string
	Prefix     netip.Prefix
	Provider   string
	Native     string
	Cause      string
	Reason     string
	Mode       string
	Start      time.Time
	End        time.Time
	EndReason  string
	HasBefore  bool
	BeforeLoss float64
	BeforeRTT  float64 // milliseconds
	HasAfter   bool
	AfterLoss  float64
	AfterRTT   float64 // milliseconds
	CostDelta  float64
	EstSavings float64
	VolumeMbps float64
	OriginASN  uint32
	Country    string
}

// PrefixInfo is what reports know about a prefix: the origin ASN from the
// learned AS path, an ISO country code when a GeoIP database is configured,
// and the latest observed volume. A store keeps the newest row per prefix.
type PrefixInfo struct {
	Prefix     netip.Prefix
	OriginASN  uint32
	Country    string
	VolumeMbps float64
	Updated    time.Time
}

// MitigationRecord is one threat mitigation rule (#28) from creation to
// its end: expiry, removal, replacement, or the controller stopping. End
// is zero while the rule is held. Announced is when its routes first went
// on the wire (zero if they never did: observe, or never in the RIB).
type MitigationRecord struct {
	ID     string
	Prefix netip.Prefix
	Action string
	Target string
	// Match is the FlowSpec match in text form, Countries the source
	// countries, RateMbps the rate limit. Empty for RTBH and redirect.
	Match     string
	Countries string
	RateMbps  float64
	// Routes is how many routes the rule stands for (one, or one per
	// source network of a country rule).
	Routes    int
	Reason    string
	Mode      string
	Created   time.Time
	Expires   time.Time
	Announced time.Time
	End       time.Time
	EndReason string
}

// AnomalyRecord is one traffic anomaly (#33) from detection to clearing.
// End is zero while it is open. Rule is the anomaly rule that matched ("" when
// none did: alert only); Mitigation and Action the mitigation rule the
// detector added for it, if any.
type AnomalyRecord struct {
	ID           string
	Prefix       netip.Prefix
	Protocol     string
	PeakMbps     float64
	BaselineMbps float64
	Reason       string
	Rule         string
	Mitigation   string
	Action       string
	Start        time.Time
	End          time.Time
	EndReason    string
}

// HistoryBatch is one write. Improvements and mitigations replace earlier
// rows with the same ID; buckets are added; prefixes replace.
type HistoryBatch struct {
	Buckets      []ProbeBucket
	Improvements []ImprovementRecord
	Prefixes     []PrefixInfo
	Mitigations  []MitigationRecord
	Anomalies    []AnomalyRecord
}

// HistoryQuery selects rows. Buckets are those whose Day is in [From, To)
// after From is truncated to its UTC day, so a range that starts mid-day
// includes that whole day (rollups are daily).
// Improvements, mitigations, and anomalies are those that overlap
// [From, To): started (created) before To and still open or ended at or
// after From. OpenOnly returns only those with no End, and no buckets.
// Prefixes are always all rows.
type HistoryQuery struct {
	From     time.Time
	To       time.Time
	OpenOnly bool
}

// History is a query result.
type History struct {
	Buckets      []ProbeBucket
	Improvements []ImprovementRecord
	Prefixes     []PrefixInfo
	Mitigations  []MitigationRecord
	Anomalies    []AnomalyRecord
}

// Storage persists history for reports. It records what the controller
// measured and decided; it must not announce routes or change decisions.
// A write error is logged by the core and never withdraws or blocks an
// improvement.
type Storage interface {
	Lifecycle
	Write(ctx context.Context, b HistoryBatch) error
	Read(ctx context.Context, q HistoryQuery) (History, error)
}

// StorageBackup is optional on a storage plugin: `packeteer -backup` and
// `-restore` (#31) use it to copy report history in and out. Both run in
// a separate process, on a plugin that was built but not started.
type StorageBackup interface {
	// Backup writes a consistent copy of the stored history to w. It may
	// run while a controller writes to the same store.
	Backup(ctx context.Context, w io.Writer) error
	// Restore replaces the stored history with a copy Backup wrote, after
	// checking it. It refuses to replace existing history unless
	// overwrite is set. The controller using the store must be stopped.
	Restore(ctx context.Context, r io.Reader, overwrite bool) error
}

// UsageSample is one interface rate sample for a provider binding in a
// billing period (#127). At is when the sample was taken. InBps and
// OutBps are bits per second. PeriodStart and PeriodEnd are the UTC
// bounds of the period the sample belongs to, [start, end).
type UsageSample struct {
	Provider    string
	Host        string
	Interface   string
	PeriodStart time.Time
	PeriodEnd   time.Time
	At          time.Time
	InBps       float64
	OutBps      float64
}

// UsageSampleQuery selects samples for one binding whose At is in
// [From, To). Limit above 0 returns only the newest Limit rows, still
// oldest first. Zero returns every row in the range.
type UsageSampleQuery struct {
	Provider  string
	Host      string
	Interface string
	From      time.Time
	To        time.Time
	Limit     int
}

// SampleStore is optional on a storage plugin (#127). A telemetry plugin
// that keeps a 95th-percentile window writes samples here so a restart
// reloads the open billing period. Closed periods stay until the store's
// retention prune. It does not announce and does not change a decision.
// Backup copies the whole database, so the samples ride along.
type SampleStore interface {
	// PutUsageSamples inserts samples. A row with the same binding and
	// At replaces the earlier one.
	PutUsageSamples(ctx context.Context, samples []UsageSample) error
	// UsageSamples returns the rows selected by q, oldest first.
	UsageSamples(ctx context.Context, q UsageSampleQuery) ([]UsageSample, error)
	// TrimUsageSamples deletes samples for the binding inside
	// [periodStart, periodEnd) that were taken before oldestKept. The
	// open period on disk stays within the collector's memory cap.
	// Samples outside that period are left for retention.
	TrimUsageSamples(ctx context.Context, provider, host, iface string, periodStart, periodEnd, oldestKept time.Time) error
}

// CountryLookup is optional on a policy plugin that has a GeoIP database.
// Reports use it for country statistics. It returns "" when unknown.
type CountryLookup interface {
	Country(addr netip.Addr) string
}
