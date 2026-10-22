package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func mutexWait(t *testing.T, text string) float64 {
	t.Helper()
	for line := range strings.Lines(text) {
		if v, ok := strings.CutPrefix(line, "packeteer_go_mutex_wait_seconds_total "); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				t.Fatal(err)
			}
			return f
		}
	}
	t.Fatalf("no packeteer_go_mutex_wait_seconds_total in\n%s", text)
	return 0
}

// The lock-wait counter (#383) is served on /metrics and follows real
// contention: eight goroutines taking one mutex for 1ms each, 20 times,
// block for about a second between them.
func TestMetricsMutexWaitFollowsContention(t *testing.T) {
	ts := newTestServer(t, sampleSnap(), "", "")
	code, _, body := do(t, http.MethodGet, ts.URL+"/metrics", "", "")
	if code != http.StatusOK || !strings.Contains(string(body), "# TYPE packeteer_go_mutex_wait_seconds_total counter\n") {
		t.Fatalf("metrics %d\n%s", code, body)
	}
	before := mutexWait(t, string(body))

	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				mu.Lock()
				time.Sleep(time.Millisecond)
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	_, _, body = do(t, http.MethodGet, ts.URL+"/metrics", "", "")
	// The runtime samples the wait, so ask for a fraction of it.
	if got := mutexWait(t, string(body)) - before; got < 0.2 {
		t.Fatalf("mutex wait grew %.3fs under about 1s of contention", got)
	}
}
