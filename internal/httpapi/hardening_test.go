package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
)

// The single basic-auth account is throttled per client network: ten bad
// attempts refuse even the right password from that /64, while another
// network still signs in (#493).
func TestLegacyBasicAuthThrottled(t *testing.T) {
	s, err := New(Options{User: "ops", Password: "secret", Snapshot: func() Snapshot { return Snapshot{} }})
	if err != nil {
		t.Fatal(err)
	}
	get := func(remote, pass string) int {
		r := httptest.NewRequest(http.MethodGet, "/api/providers", nil)
		r.RemoteAddr = remote
		r.SetBasicAuth("ops", pass)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, r)
		return rec.Code
	}
	for i := range 10 {
		if code := get(fmt.Sprintf("[2001:db8:0:7::%x]:40000", i+1), "guess"); code != http.StatusUnauthorized {
			t.Fatalf("bad attempt %d: %d", i, code)
		}
	}
	if code := get("[2001:db8:0:7::99]:40000", "secret"); code != http.StatusTooManyRequests {
		t.Fatalf("right password from the throttled /64: %d", code)
	}
	if code := get("[2001:db8:0:8::1]:40000", "secret"); code != http.StatusOK {
		t.Fatalf("right password from another /64: %d", code)
	}
}

// The basic-auth account is counted per network, whatever user name is
// sent: failures under other names lock it out, and 10,001 more attempts
// under new names (more than the 10,000-entry throttle table) are refused
// without adding entries, so the lockout holds (#527).
func TestLegacyBasicAuthThrottleIgnoresUserName(t *testing.T) {
	s, err := New(Options{User: "ops", Password: "secret", Snapshot: func() Snapshot { return Snapshot{} }})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	get := func(remote, user, pass string) int {
		r := httptest.NewRequest(http.MethodGet, "/api/providers", nil)
		r.RemoteAddr = remote
		r.SetBasicAuth(user, pass)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	const remote = "192.0.2.10:40000"
	for i := range 10 {
		if code := get(remote, fmt.Sprintf("user%d", i), "guess"); code != http.StatusUnauthorized {
			t.Fatalf("bad attempt %d: %d", i, code)
		}
	}
	if code := get(remote, "ops", "secret"); code != http.StatusTooManyRequests {
		t.Fatalf("right password after failures under other names: %d", code)
	}
	for i := range 10_001 {
		if code := get(remote, fmt.Sprintf("flood%d", i), "guess"); code != http.StatusTooManyRequests {
			t.Fatalf("flood attempt %d: %d", i, code)
		}
	}
	if code := get(remote, "ops", "secret"); code != http.StatusTooManyRequests {
		t.Fatalf("right password after the flood: %d", code)
	}
	if code := get("198.51.100.10:40000", "ops", "secret"); code != http.StatusOK {
		t.Fatalf("right password from another network: %d", code)
	}
}

// A client that sends its headers and then trickles the body loses the
// connection at ReadTimeout instead of holding a handler.
func TestReadTimeoutClosesSlowBody(t *testing.T) {
	s, err := New(Options{Addr: "127.0.0.1:0", Snapshot: func() Snapshot { return Snapshot{} }})
	if err != nil {
		t.Fatal(err)
	}
	s.readTimeout = 200 * time.Millisecond
	got := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /slow", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		got <- err
	})
	s.handler = mux
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	c, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "POST /slow HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nab"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("the handler read a body that never arrived")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("slow body still held the handler after ReadTimeout")
	}
	if s.http.ReadTimeout != 200*time.Millisecond {
		t.Fatalf("ReadTimeout %v", s.http.ReadTimeout)
	}
}

// The SSO callback does not echo the token exchange error to the
// unauthenticated client; the log keeps it (#493).
func TestSSOCallbackErrorIsGeneric(t *testing.T) {
	const detail = "token endpoint: invalid_client for client-id pk-lab"
	e := newRBAC(t, &testSSO{err: errors.New(detail)})
	rec := e.do("GET", "/auth/login", "", "")
	var state *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.StateCookie {
			state = c
		}
	}
	if state == nil {
		t.Fatalf("no state cookie: %d", rec.Code)
	}
	rec = e.do("GET", "/auth/callback?code=c&state="+url.QueryEscape(state.Value), "", "", func(r *http.Request) { r.AddCookie(state) })
	if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"error":"sign-in refused"}` {
		t.Fatalf("callback: %d %s", rec.Code, rec.Body)
	}
}

// A store or internal error is answered generically and logged in full.
func TestAuthErrorHidesDetail(t *testing.T) {
	var logs bytes.Buffer
	s, err := New(Options{Logger: slog.New(slog.NewTextHandler(&logs, nil)), Snapshot: func() Snapshot { return Snapshot{} }})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		err  error
		code int
		body string
	}{
		{fmt.Errorf("%w: %v", auth.ErrUnavailable, errors.New("open /data/packeteer.db: disk I/O error")), http.StatusServiceUnavailable, "user store unavailable"},
		{errors.New("crypto/rand: read /dev/urandom: bad file"), http.StatusInternalServerError, "internal error"},
		{auth.ErrBusy, http.StatusTooManyRequests, auth.ErrBusy.Error()},
		{auth.ErrLastAdmin, http.StatusConflict, auth.ErrLastAdmin.Error()},
	} {
		rec := httptest.NewRecorder()
		s.writeAuthError(rec, tc.err)
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), `"error":"`+tc.body+`"`) {
			t.Errorf("%v: %d %s", tc.err, rec.Code, rec.Body)
		}
	}
	for _, d := range []string{"disk I/O error", "/dev/urandom"} {
		if !strings.Contains(logs.String(), d) {
			t.Errorf("log lacks %q:\n%s", d, logs.String())
		}
	}
}
