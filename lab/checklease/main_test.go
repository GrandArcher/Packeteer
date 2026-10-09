package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func held(id string, seq int) []byte {
	return []byte(fmt.Sprintf(`{"holder":"%s#abc","id":"%s","seq":%d,"route_hold_ms":9000,"ttl_ms":4000,"time":"2026-10-08T14:17:21Z"}`, id, id, seq))
}

func released(id string, seq int) []byte {
	return []byte(fmt.Sprintf(`{"holder":"%s#abc","id":"%s","seq":%d,"released":true,"route_hold_ms":9000,"ttl_ms":4000,"time":"2026-10-08T14:17:21Z"}`, id, id, seq))
}

func TestReleasedBy(t *testing.T) {
	if !ReleasedBy(released("pk-a", 3), "pk-a") {
		t.Fatal("released record was not a release by pk-a")
	}
	for _, raw := range [][]byte{
		held("pk-a", 1),
		released("pk-b", 4),
		[]byte(`{"id":"pk-a","released":false}`),
		[]byte(`not json`),
		[]byte(`{"released":true}`),
		nil,
	} {
		if ReleasedBy(raw, "pk-a") {
			t.Fatalf("accepted %s", raw)
		}
	}
	if ReleasedBy(released("pk-a", 1), "") {
		t.Fatal("empty id accepted")
	}
}

func TestReleaseWatchBaselineDoesNotCount(t *testing.T) {
	var w releaseWatch
	w.id = "pk-a"
	if w.observe(released("pk-a", 1), nil) {
		t.Fatal("a record that is already released at the baseline counted")
	}
	if w.observe(released("pk-a", 1), nil) {
		t.Fatal("staying released after the baseline counted")
	}
	if w.observe(held("pk-a", 2), nil) {
		t.Fatal("a renewal counted")
	}
	if !w.observe(released("pk-a", 3), nil) {
		t.Fatal("a release during the watch was missed")
	}
	if !w.observe(held("pk-b", 4), nil) {
		t.Fatal("the standby's overwrite cleared a release already seen")
	}

	var other releaseWatch
	other.id = "pk-a"
	if other.observe(held("pk-a", 1), nil) || other.observe(released("pk-b", 2), nil) {
		t.Fatal("another instance's release counted")
	}
}

func TestMissingReleaseFails(t *testing.T) {
	for i := 0; i < 20; i++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "lease.json")
		if err := os.WriteFile(path, held("pk-a", 1), 0o644); err != nil {
			t.Fatal(err)
		}
		ready := filepath.Join(dir, "ready")
		var stdout, stderr bytes.Buffer
		start := time.Now()
		code := run([]string{
			"-file", path, "-id", "pk-a", "-timeout", "40ms", "-every", "2ms", "-ready", ready,
		}, &stdout, &stderr)
		elapsed := time.Since(start)
		if code != 1 {
			t.Fatalf("iter %d: exit %d, want 1 (stderr %s)", i, code, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("iter %d: stdout %q", i, stdout.String())
		}
		if _, err := os.Stat(ready); err != nil {
			t.Fatalf("iter %d: ready file: %v", i, err)
		}
		// A missing release has to consume the bound. Returning at once
		// would hide a watch that never looked.
		if elapsed < 30*time.Millisecond {
			t.Fatalf("iter %d: missing release returned in %s", i, elapsed)
		}
	}
}

func writeRecord(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func TestReleaseDuringWatchSucceeds(t *testing.T) {
	for i := 0; i < 20; i++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "lease.json")
		if err := os.WriteFile(path, held("pk-a", 1), 0o644); err != nil {
			t.Fatal(err)
		}
		ready := filepath.Join(dir, "ready")
		// The standby overwrites a release on its next renewal. The watch
		// has to observe that record; the file at the end does not show it.
		done := make(chan error, 1)
		go func() {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if _, err := os.Stat(ready); err != nil {
				done <- err
				return
			}
			if err := writeRecord(path, released("pk-a", 2)); err != nil {
				done <- err
				return
			}
			time.Sleep(50 * time.Millisecond)
			done <- writeRecord(path, held("pk-b", 3))
		}()
		var stdout, stderr bytes.Buffer
		code := run([]string{
			"-file", path, "-id", "pk-a", "-timeout", "2s", "-every", "2ms", "-ready", ready,
		}, &stdout, &stderr)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		final, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if ReleasedBy(final, "pk-a") {
			t.Fatalf("iter %d: release was still the final record", i)
		}
		if code != 0 {
			t.Fatalf("iter %d: exit %d, stderr %s, final %s", i, code, stderr.String(), final)
		}
		if stdout.String() != "released by pk-a\n" {
			t.Fatalf("iter %d: stdout %q", i, stdout.String())
		}
	}
}

func TestOtherIDAndAlreadyReleasedFail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lease.json")
	if err := os.WriteFile(path, released("pk-b", 1), 0o644); err != nil {
		t.Fatal(err)
	}
	code := run([]string{"-file", path, "-id", "pk-a", "-timeout", "40ms", "-every", "2ms"}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != 1 {
		t.Fatalf("other id: exit %d", code)
	}

	// Already released at the baseline, and it stays that way: SIGTERM
	// has not produced a new release.
	if err := os.WriteFile(path, released("pk-a", 2), 0o644); err != nil {
		t.Fatal(err)
	}
	code = run([]string{"-file", path, "-id", "pk-a", "-timeout", "40ms", "-every", "2ms"}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != 1 {
		t.Fatalf("already released: exit %d", code)
	}
}

func TestWatchDoesNotArm(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-dir", "lease.json")
	code := run([]string{"-file", missing, "-id", "pk-a", "-timeout", "1s", "-every", "2ms"}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != 2 {
		t.Fatalf("exit %d, want 2 (arming failure, not a missing release)", code)
	}
}

func TestBadInvocation(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-file", "x"},
		{"-id", "pk-a"},
		{"-file", "x", "-id", "pk-a", "-timeout", "0"},
		{"-file", "x", "-id", "pk-a", "-every", "0"},
	} {
		if code := run(args, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
			t.Fatalf("%q: exit %d", args, code)
		}
	}
}

func TestWaitReleasedContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lease.json")
	if err := os.WriteFile(path, held("pk-a", 1), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	err := waitReleased(ctx, path, "pk-a", 2*time.Millisecond, nil)
	if !errors.Is(err, errNotReleased) {
		t.Fatalf("err %v", err)
	}
}
