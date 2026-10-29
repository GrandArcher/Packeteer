package grpcplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/GrandArcher/Packeteer/internal/plugins/oop"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"github.com/GrandArcher/Packeteer/pkg/plugin/rpc"
)

// supervisor owns the plugin process of one instance: it starts it,
// replaces it when it dies or fails a health check, and stops it.
type supervisor struct {
	kind      plugin.Kind
	name      string
	spec      oop.Spec
	health    time.Duration
	backoff0  time.Duration
	log       *slog.Logger
	checkOnly bool

	mu      sync.Mutex
	cur     *launched // nil while the plugin is down
	upSince time.Time
	backoff time.Duration
	nextTry time.Time
	lastErr error
	// dead holds processes whose client the loop has not stopped yet.
	dead    []*launched
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
	wake    chan struct{}
}

func newSupervisorFrom(kind plugin.Kind, name string, spec oop.Spec, health, backoff time.Duration, log *slog.Logger) *supervisor {
	return &supervisor{kind: kind, name: name, spec: spec, health: health, backoff0: backoff, backoff: backoff,
		log: log, wake: make(chan struct{}, 1)}
}

// launched is one running plugin process with its connected client.
type launched struct {
	proc   *goplugin.Client
	client *rpc.Client
}

// stop asks the process to exit and kills it if it does not (go-plugin
// waits up to two seconds).
func (l *launched) stop() { l.proc.Kill() }

// launch starts the program, completes the go-plugin handshake (which
// fails on a protocol version mismatch), and sends Init.
func (s *supervisor) launch(ctx context.Context) (*launched, error) {
	cmd := exec.Command(s.spec.Path, s.spec.Args...)
	// The program gets exactly spec.Env: SkipHostEnv below keeps the rest
	// of Packeteer's environment, secrets included, out of it.
	cmd.Env = s.spec.Env
	proc := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  rpc.Handshake,
		Plugins:          rpc.PluginSet(nil),
		Cmd:              cmd,
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		SkipHostEnv:      true,
		StartTimeout:     s.spec.Timeout,
		Logger:           hclog.New(&hclog.LoggerOptions{Name: "plugin", Level: hclog.Debug, Output: slogWriter{s.log}}),
	})
	fail := func(err error) (*launched, error) {
		proc.Kill()
		return nil, err
	}
	protocol, err := proc.Client()
	if err != nil {
		return fail(fmt.Errorf("start: %w", err))
	}
	raw, err := protocol.Dispense(rpc.PluginName)
	if err != nil {
		return fail(fmt.Errorf("start: %w", err))
	}
	client := raw.(*rpc.Client)
	cfg, err := json.Marshal(s.spec.Config)
	if err != nil {
		return fail(fmt.Errorf("config: %w", err))
	}
	if err := client.Init(ctx, rpc.InitRequest{Kind: s.kind, Name: s.name, Config: cfg}); err != nil {
		return fail(describe(ctx, "init", err))
	}
	return &launched{proc: proc, client: client}, nil
}

// slogWriter sends go-plugin's log lines (its own and the plugin's
// stderr) to the plugin's logger at debug level.
type slogWriter struct{ log *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	if line := strings.TrimSpace(string(p)); line != "" {
		w.log.Debug("grpc plugin", "log", line)
	}
	return len(p), nil
}

// describe turns a call error into one that names the cause.
func describe(ctx context.Context, method string, err error) error {
	switch status.Code(err) {
	case codes.DeadlineExceeded:
		return fmt.Errorf("%s: timed out", method)
	case codes.Canceled:
		if ctx.Err() != nil {
			return fmt.Errorf("%s: %w", method, ctx.Err())
		}
	}
	if st, ok := status.FromError(err); ok {
		return fmt.Errorf("%s: plugin error: %s", method, st.Message())
	}
	return fmt.Errorf("%s: %w", method, err)
}

// Start launches the plugin and begins supervising it. A plugin that
// cannot start now refuses the start of the controller, as an exec plugin
// that fails its init does.
func (s *supervisor) Start(ctx context.Context) error {
	if s.checkOnly {
		return errors.New("plugin was built for a config check and does not run")
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("already started")
	}
	s.mu.Unlock()
	lctx, cancel := context.WithTimeout(ctx, s.spec.Timeout)
	defer cancel()
	l, err := s.launch(lctx)
	if err != nil {
		return err
	}
	loopCtx, stop := context.WithCancel(context.Background())
	s.mu.Lock()
	s.started = true
	s.cur, s.upSince, s.cancel, s.done = l, time.Now(), stop, make(chan struct{})
	s.mu.Unlock()
	go s.loop(loopCtx)
	return nil
}

// Stop ends the supervision and the process. It returns when the process is
// gone or ctx expires; the process is then killed in the background.
func (s *supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel = nil
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("stopping the plugin process: %w", ctx.Err())
	}
}

// loop checks a running plugin and restarts a down one, until ctx ends. It
// stops every process it still owns on exit.
func (s *supervisor) loop(ctx context.Context) {
	defer close(s.done)
	defer s.reapAll()
	for {
		s.reap()
		wait := s.health
		s.mu.Lock()
		down := s.cur == nil
		if down {
			wait = max(time.Until(s.nextTry), 0)
		}
		s.mu.Unlock()
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.wake:
			t.Stop()
		case <-t.C:
		}
		if ctx.Err() != nil {
			return
		}
		if down {
			s.restart(ctx)
		} else {
			s.check(ctx)
		}
	}
}

func (s *supervisor) check(ctx context.Context) {
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if cur == nil {
		return
	}
	var err error
	if cur.proc.Exited() {
		err = errors.New("process exited")
	} else {
		hctx, cancel := context.WithTimeout(ctx, s.spec.Timeout)
		defer cancel()
		if herr := cur.client.Health(hctx); herr != nil {
			err = describe(hctx, "health check", herr)
		}
	}
	if err != nil && ctx.Err() == nil {
		s.markDown(cur, err)
	}
}

func (s *supervisor) restart(ctx context.Context) {
	s.mu.Lock()
	// A wake-up left over from an earlier failure must not skip the delay.
	if time.Now().Before(s.nextTry) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	lctx, cancel := context.WithTimeout(ctx, s.spec.Timeout)
	defer cancel()
	l, err := s.launch(lctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		if l != nil {
			s.dead = append(s.dead, l)
		}
		return
	}
	if err != nil {
		s.lastErr = err
		s.log.Warn("grpc plugin restart failed", "err", err, "retry_in", s.scheduleRetry())
		return
	}
	s.cur, s.upSince, s.lastErr = l, time.Now(), nil
	s.log.Info("grpc plugin restarted")
}

// scheduleRetry sets the time of the next start attempt and doubles the
// delay for the one after. The caller holds s.mu.
func (s *supervisor) scheduleRetry() time.Duration {
	d := s.backoff
	s.nextTry = time.Now().Add(d)
	s.backoff = min(d*2, s.backoff0*maxBackoffFactor)
	return d
}

// markDown takes l out of service. It does nothing when l is already
// replaced, so a late failure of an old process cannot down the new one.
func (s *supervisor) markDown(l *launched, err error) {
	s.mu.Lock()
	if l == nil || s.cur != l {
		s.mu.Unlock()
		return
	}
	s.cur = nil
	s.dead = append(s.dead, l)
	s.lastErr = err
	// A plugin that ran for a while before dying restarts at the base
	// delay; one that keeps dying right after a start backs off.
	if time.Since(s.upSince) >= s.backoff0*maxBackoffFactor {
		s.backoff = s.backoff0
	}
	retry := s.scheduleRetry()
	s.mu.Unlock()
	s.log.Warn("grpc plugin is down; restarting", "err", err, "retry_in", retry)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// reap stops processes taken out of service.
func (s *supervisor) reap() {
	s.mu.Lock()
	dead := s.dead
	s.dead = nil
	s.mu.Unlock()
	for _, l := range dead {
		l.stop()
	}
}

// reapAll stops everything the supervisor owns.
func (s *supervisor) reapAll() {
	s.mu.Lock()
	if s.cur != nil {
		s.dead = append(s.dead, s.cur)
		s.cur = nil
	}
	s.mu.Unlock()
	s.reap()
}

// call runs fn against the running plugin. A transport failure takes the
// process out of service; the loop starts a new one.
func call[T any](ctx context.Context, s *supervisor, method string, fn func(context.Context, *rpc.Client) (T, error)) (T, error) {
	var zero T
	if s.checkOnly {
		return zero, fmt.Errorf("%s: plugin was built for a config check and does not run", method)
	}
	s.mu.Lock()
	cur, lastErr := s.cur, s.lastErr
	s.mu.Unlock()
	if cur == nil {
		if lastErr != nil {
			return zero, fmt.Errorf("%s: plugin is not running: %v", method, lastErr)
		}
		return zero, fmt.Errorf("%s: plugin is not running", method)
	}
	cctx, cancel := context.WithTimeout(ctx, s.spec.Timeout)
	defer cancel()
	out, err := fn(cctx, cur.client)
	if err == nil {
		return out, nil
	}
	if status.Code(err) == codes.Unavailable {
		s.markDown(cur, err)
	}
	return zero, describe(cctx, method, err)
}
