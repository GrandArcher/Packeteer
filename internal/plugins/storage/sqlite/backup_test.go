package sqlite

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestBackupRestore copies history out of a store that is running and
// into a new path, refuses to overwrite without the flag, and refuses a
// file that is not a history database (#31).
func TestBackupRestore(t *testing.T) {
	ctx := context.Background()
	var _ plugin.StorageBackup = (*Store)(nil)
	src := newStore(t, "path: "+filepath.Join(t.TempDir(), "packeteer.db"))
	src.now = func() time.Time { return day.Add(48 * time.Hour) }
	if err := src.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer src.Stop(ctx)
	rec := plugin.ImprovementRecord{ID: "a", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Start: day.Add(time.Hour)}
	if err := src.Write(ctx, plugin.HistoryBatch{
		Buckets:      []plugin.ProbeBucket{{Day: day, Prefix: pfxA, Provider: "transit-a", Probes: 2, Measured: 2, LossSum: 20}},
		Improvements: []plugin.ImprovementRecord{rec},
	}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := src.Backup(ctx, &buf); err != nil {
		t.Fatal(err)
	}

	dstPath := filepath.Join(t.TempDir(), "restored", "packeteer.db")
	dst := newStore(t, "path: "+dstPath)
	if err := dst.Restore(ctx, bytes.NewReader(buf.Bytes()), false); err != nil {
		t.Fatal(err)
	}
	if err := dst.Restore(ctx, bytes.NewReader(buf.Bytes()), false); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("second restore without overwrite: %v", err)
	}
	if err := dst.Restore(ctx, bytes.NewReader(buf.Bytes()), true); err != nil {
		t.Fatal(err)
	}
	dst.now = src.now
	if err := dst.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer dst.Stop(ctx)
	h, err := dst.Read(ctx, plugin.HistoryQuery{From: day.Add(-time.Hour), To: day.Add(72 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Buckets) != 1 || h.Buckets[0].LossSum != 20 || len(h.Improvements) != 1 || h.Improvements[0].ID != "a" {
		t.Fatalf("restored history = %+v", h)
	}

	bad := newStore(t, "path: "+filepath.Join(t.TempDir(), "bad.db"))
	if err := bad.Restore(ctx, strings.NewReader("not a database"), false); err == nil {
		t.Fatal("restored garbage")
	}
	missing := newStore(t, "path: "+filepath.Join(t.TempDir(), "none.db"))
	if err := missing.Backup(ctx, &buf); err == nil {
		t.Fatal("backup of a missing database")
	}
}
