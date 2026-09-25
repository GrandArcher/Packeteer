// Package webhook implements the "webhook" notifier: each event is POSTed
// as JSON to a configured URL.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "webhook"

// DefaultTimeout bounds one delivery.
const DefaultTimeout = 5 * time.Second

func init() { plugin.Notifiers.Register(TypeName, New) }

// Config is the webhook notifier's config block.
type Config struct {
	URL     string        `yaml:"url"`
	Timeout time.Duration `yaml:"timeout"`
	// Headers are added to each request. Values may reference ${VAR} from
	// the environment so tokens stay out of the config file.
	Headers map[string]string `yaml:"headers"`
	// MinSeverity drops events below this level (info, warning, critical).
	MinSeverity plugin.Severity `yaml:"min_severity"`
}

// Notifier posts events to a URL.
type Notifier struct {
	plugin.Base
	url     string
	headers http.Header
	min     int
	client  *http.Client
}

var severityRank = map[plugin.Severity]int{
	plugin.SeverityInfo: 0, plugin.SeverityWarning: 1, plugin.SeverityCritical: 2,
}

// New is the plugin factory.
func New(c plugin.Config, e plugin.Env) (plugin.Notifier, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	getenv := e.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	raw := os.Expand(cfg.URL, getenv)
	if raw == "" {
		return nil, fmt.Errorf("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("url must be an absolute http(s) URL")
	}
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("timeout %s must not be negative", cfg.Timeout)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = plugin.SeverityInfo
	}
	rank, ok := severityRank[cfg.MinSeverity]
	if !ok {
		return nil, fmt.Errorf("min_severity %q is invalid (want info, warning, critical)", cfg.MinSeverity)
	}
	h := http.Header{}
	for k, v := range cfg.Headers {
		h.Set(k, os.Expand(v, getenv))
	}
	h.Set("Content-Type", "application/json")
	return &Notifier{url: u.String(), headers: h, min: rank, client: &http.Client{Timeout: cfg.Timeout}}, nil
}

// Notify implements plugin.Notifier.
func (n *Notifier) Notify(ctx context.Context, e plugin.Event) error {
	if r, ok := severityRank[e.Severity]; ok && r < n.min {
		return nil
	}
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header = n.headers.Clone()
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook: unexpected status %s", resp.Status)
	}
	return nil
}
