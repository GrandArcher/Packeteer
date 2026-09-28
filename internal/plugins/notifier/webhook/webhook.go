// Package webhook implements the "webhook" notifier: each event is POSTed
// to a configured URL. The body is the event as JSON (preset generic), a
// Slack, Microsoft Teams, or PagerDuty Events v2 message, or a custom
// text/template for SMS and chat gateways.
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
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "webhook"

// DefaultTimeout bounds one delivery.
const DefaultTimeout = 5 * time.Second

// PagerDutyURL is the Events API v2 endpoint used when preset is pagerduty
// and url is not set.
const PagerDutyURL = "https://events.pagerduty.com/v2/enqueue"

// Presets.
const (
	PresetGeneric   = "generic"
	PresetSlack     = "slack"
	PresetTeams     = "teams"
	PresetPagerDuty = "pagerduty"
)

const maxTemplate = 16 << 10

func init() { plugin.Notifiers.Register(TypeName, New) }

// Config is the webhook notifier's config block.
type Config struct {
	URL     string        `yaml:"url"`
	Timeout time.Duration `yaml:"timeout"`
	// Headers are added to each request. Values may reference ${VAR} from
	// the environment so tokens stay out of the config file.
	Headers map[string]string `yaml:"headers"`
	// Preset is generic (default), slack, teams, or pagerduty.
	Preset string `yaml:"preset"`
	// RoutingKeyEnv names the environment variable that holds the
	// PagerDuty integration key. Required for preset pagerduty.
	RoutingKeyEnv string `yaml:"routing_key_env"`
	// Template renders the body with text/template instead of a preset,
	// e.g. for an SMS gateway. ContentType defaults to application/json.
	Template    string `yaml:"template"`
	ContentType string `yaml:"content_type"`

	plugin.EventFilter `yaml:",inline"`
}

// Notifier posts events to a URL.
type Notifier struct {
	plugin.Base
	url        string
	headers    http.Header
	preset     string
	routingKey string
	tmpl       *template.Template
	gate       *plugin.EventGate
	client     *http.Client
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

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
	gate, err := plugin.NewEventGate(cfg.EventFilter)
	if err != nil {
		return nil, err
	}
	n := &Notifier{gate: gate, preset: cfg.Preset}
	if n.preset == "" {
		n.preset = PresetGeneric
	}
	switch n.preset {
	case PresetGeneric, PresetSlack, PresetTeams:
		if cfg.RoutingKeyEnv != "" {
			return nil, fmt.Errorf("routing_key_env is only for preset pagerduty")
		}
	case PresetPagerDuty:
		if cfg.URL == "" {
			cfg.URL = PagerDutyURL
		}
		if !envName.MatchString(cfg.RoutingKeyEnv) {
			return nil, fmt.Errorf("routing_key_env is required for preset pagerduty and must be an environment variable name")
		}
		n.routingKey = getenv(cfg.RoutingKeyEnv)
		if n.routingKey == "" {
			return nil, fmt.Errorf("routing_key_env: %s is not set", cfg.RoutingKeyEnv)
		}
	default:
		return nil, fmt.Errorf("preset %q is invalid (want generic, slack, teams, pagerduty)", cfg.Preset)
	}
	raw := os.Expand(cfg.URL, getenv)
	if raw == "" {
		return nil, fmt.Errorf("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("url must be an absolute http(s) URL")
	}
	n.url = u.String()
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("timeout %s must not be negative", cfg.Timeout)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	ctype := "application/json"
	if cfg.Template != "" {
		if n.preset != PresetGeneric {
			return nil, fmt.Errorf("template cannot be combined with preset %s", n.preset)
		}
		if len(cfg.Template) > maxTemplate {
			return nil, fmt.Errorf("template is longer than %d bytes", maxTemplate)
		}
		t, err := template.New("body").Option("missingkey=zero").Funcs(template.FuncMap{
			"json":  jsonString,
			"upper": strings.ToUpper,
		}).Parse(cfg.Template)
		if err != nil {
			return nil, fmt.Errorf("template: %w", err)
		}
		n.tmpl = t
		if cfg.ContentType != "" {
			ctype = cfg.ContentType
		}
	} else if cfg.ContentType != "" {
		return nil, fmt.Errorf("content_type is only used with template")
	}
	h := http.Header{}
	for k, v := range cfg.Headers {
		h.Set(k, os.Expand(v, getenv))
	}
	h.Set("Content-Type", ctype)
	n.headers = h
	n.client = &http.Client{Timeout: cfg.Timeout}
	return n, nil
}

// EventGate implements plugin.Gated.
func (n *Notifier) EventGate() *plugin.EventGate { return n.gate }

// Notify implements plugin.Notifier.
func (n *Notifier) Notify(ctx context.Context, e plugin.Event) error {
	if !n.gate.Match(e) {
		return nil
	}
	body, err := n.body(e)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header = n.headers.Clone()
	resp, err := n.client.Do(req)
	if err != nil {
		// url.Error includes the URL, which may carry a secret token.
		return fmt.Errorf("webhook: %w", redact(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook: unexpected status %s", resp.Status)
	}
	return nil
}

func redact(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

func (n *Notifier) body(e plugin.Event) ([]byte, error) {
	if n.tmpl != nil {
		var b bytes.Buffer
		if err := n.tmpl.Execute(&b, e); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}
	switch n.preset {
	case PresetSlack:
		return json.Marshal(map[string]string{"text": Text(e)})
	case PresetTeams:
		return json.Marshal(map[string]any{
			"@type":      "MessageCard",
			"@context":   "https://schema.org/extensions",
			"summary":    e.Message,
			"themeColor": color(e.Severity),
			"title":      fmt.Sprintf("[%s] %s", strings.ToUpper(string(e.Severity)), e.Kind),
			"text":       Text(e),
		})
	case PresetPagerDuty:
		return json.Marshal(pagerDuty(n.routingKey, e))
	default:
		return json.Marshal(e)
	}
}

// Text is a one-message plain-text rendering used by chat presets.
func Text(e plugin.Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s: %s", strings.ToUpper(string(e.Severity)), e.Kind, e.Message)
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "\n%s: %s", k, e.Fields[k])
	}
	return b.String()
}

func color(s plugin.Severity) string {
	switch s {
	case plugin.SeverityCritical:
		return "D93F0B"
	case plugin.SeverityWarning:
		return "FBCA04"
	default:
		return "0E8A16"
	}
}

func pagerDuty(key string, e plugin.Event) map[string]any {
	action := "trigger"
	if e.Resolves() {
		action = "resolve"
	}
	sev := string(e.Severity)
	if sev == "" {
		sev = string(plugin.SeverityInfo)
	}
	summary := e.Kind + ": " + e.Message
	if len(summary) > 1024 {
		summary = summary[:1024]
	}
	return map[string]any{
		"routing_key":  key,
		"event_action": action,
		"dedup_key":    e.DedupKey(),
		"payload": map[string]any{
			"summary":        summary,
			"source":         "packeteer",
			"severity":       sev,
			"timestamp":      e.Time.UTC().Format(time.RFC3339),
			"component":      e.Kind,
			"custom_details": e.Fields,
		},
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
