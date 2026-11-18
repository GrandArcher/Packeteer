// Command fuzzrun runs one Go fuzz target for a fixed time and retries it
// when the run fails only on the fuzzing engine's own deadline (#660).
//
// At the end of -fuzztime the engine can fail a run with "context
// deadline exceeded" when a worker is slow to answer on a loaded runner
// (CI runs of FuzzDecodeV5, FuzzSFlow, FuzzBMPStream, and FuzzParse). That
// failure writes no input to testdata/fuzz. Any other failure, a crash or
// a panic or an input written for the target, is a finding and is never
// retried. Every retry logs why.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// maxAttempts bounds the retries: one run and two more.
const maxAttempts = 3

var targetName = regexp.MustCompile(`^Fuzz[A-Za-z0-9_]+$`)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, goTest))
}

// goTest runs go with args and writes its combined output to out.
func goTest(args []string, out io.Writer) error {
	cmd := exec.Command("go", args...)
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
}

func run(args []string, stdout, stderr io.Writer, runGo func([]string, io.Writer) error) int {
	if len(args) != 3 || !targetName.MatchString(args[0]) {
		fmt.Fprintln(stderr, "usage: fuzzrun FuzzTarget FUZZTIME PACKAGE")
		return 2
	}
	target, fuzztime, pkg := args[0], args[1], args[2]
	goArgs := []string{"test", "-run", "^$", "-fuzz", "^" + target + "$", "-fuzztime", fuzztime, pkg}
	for attempt := 1; ; attempt++ {
		var out bytes.Buffer
		err := runGo(goArgs, io.MultiWriter(stdout, &out))
		if err == nil {
			return 0
		}
		reason, retry := classify(out.String())
		if !retry || attempt == maxAttempts {
			fmt.Fprintf(stderr, "fuzzrun: %s failed on attempt %d of %d: %v (%s)\n", target, attempt, maxAttempts, err, reason)
			return 1
		}
		fmt.Fprintf(stderr, "fuzzrun: %s attempt %d of %d failed: %s; running it again\n", target, attempt, maxAttempts, reason)
	}
}

// classify reports whether a failed run is only the engine's deadline.
func classify(out string) (reason string, retry bool) {
	switch {
	case strings.Contains(out, "Failing input written to"):
		return "the fuzzer wrote a failing input", false
	case strings.Contains(out, "panic:") || strings.Contains(out, "fatal error:"):
		return "the target crashed", false
	case strings.Contains(out, "context deadline exceeded"):
		return "the fuzzing engine hit its own deadline (context deadline exceeded) and wrote no failing input", true
	}
	return "not the fuzzing engine's deadline", false
}
