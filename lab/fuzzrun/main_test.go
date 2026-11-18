package main

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

const deadlineOut = "--- FAIL: FuzzParse (10.11s)\n    context deadline exceeded\nFAIL\n"

// script returns a runner that plays one output per call and records args.
func script(calls *[][]string, outs ...string) func([]string, io.Writer) error {
	return func(args []string, w io.Writer) error {
		i := len(*calls)
		*calls = append(*calls, args)
		_, _ = io.WriteString(w, outs[i])
		if strings.HasPrefix(outs[i], "ok") {
			return nil
		}
		return errors.New("exit status 1")
	}
}

func TestRunRetriesOnlyTheEngineDeadline(t *testing.T) {
	var calls [][]string
	var stdout, stderr bytes.Buffer
	code := run([]string{"FuzzParse", "10s", "./internal/twamp/"}, &stdout, &stderr, script(&calls, deadlineOut, "ok  \tpkg\t10.1s\n"))
	if code != 0 || len(calls) != 2 {
		t.Fatalf("code %d after %d runs; stderr %q", code, len(calls), stderr.String())
	}
	want := []string{"test", "-run", "^$", "-fuzz", "^FuzzParse$", "-fuzztime", "10s", "./internal/twamp/"}
	if !reflect.DeepEqual(calls[0], want) {
		t.Fatalf("go args %v, want %v", calls[0], want)
	}
	if !strings.Contains(stderr.String(), "FuzzParse attempt 1 of 3 failed: the fuzzing engine hit its own deadline") {
		t.Fatalf("retry log %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "context deadline exceeded") {
		t.Fatalf("go output not passed through: %q", stdout.String())
	}
}

func TestRunNeverRetriesAFinding(t *testing.T) {
	for name, out := range map[string]string{
		"input written": "--- FAIL: FuzzParse\n    context deadline exceeded\nFailing input written to testdata/fuzz/FuzzParse/ab12\n",
		"panic":         "panic: index out of range\ncontext deadline exceeded\n",
		"other failure": "--- FAIL: FuzzParse\n    parse: 3 observations from 2 bytes\n",
	} {
		var calls [][]string
		var stderr bytes.Buffer
		code := run([]string{"FuzzParse", "10s", "./internal/twamp/"}, io.Discard, &stderr, script(&calls, out))
		if code != 1 || len(calls) != 1 {
			t.Errorf("%s: code %d after %d runs", name, code, len(calls))
		}
		if strings.Contains(stderr.String(), "running it again") {
			t.Errorf("%s: retried: %q", name, stderr.String())
		}
	}
}

func TestRunStopsAfterMaxAttempts(t *testing.T) {
	var calls [][]string
	var stderr bytes.Buffer
	code := run([]string{"FuzzParse", "10s", "./internal/twamp/"}, io.Discard, &stderr, script(&calls, deadlineOut, deadlineOut, deadlineOut, deadlineOut))
	if code != 1 || len(calls) != maxAttempts {
		t.Fatalf("code %d after %d runs, want 1 after %d", code, len(calls), maxAttempts)
	}
	if n := strings.Count(stderr.String(), "running it again"); n != maxAttempts-1 {
		t.Fatalf("%d retry lines in %q", n, stderr.String())
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"FuzzParse", "10s"}, {"TestParse", "10s", "./x"}, {"Fuzz Parse", "10s", "./x"}} {
		var calls [][]string
		if code := run(args, io.Discard, io.Discard, script(&calls)); code != 2 || len(calls) != 0 {
			t.Errorf("%v: code %d, %d runs", args, code, len(calls))
		}
	}
}
