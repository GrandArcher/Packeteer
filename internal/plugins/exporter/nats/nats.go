// Package nats implements the "nats" exporter: events, decisions, and
// optionally tagged flow records are published to core NATS subjects as
// JSON. Credentials come from environment variables, never the config
// file.
package nats

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	natsgo "github.com/nats-io/nats.go"

	"github.com/GrandArcher/Packeteer/internal/export"
	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/sinkcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "nats"

// timeout is the connect timeout; a flush is bounded by the dispatcher.
const timeout = 10 * time.Second

// DefaultSubjectPrefix gives the subjects packeteer.events,
// packeteer.decisions, and packeteer.flows.
const DefaultSubjectPrefix = "packeteer"

func init() { plugin.Exporters.Register(TypeName, New) }

// Config is the nats exporter's config block.
type Config struct {
	// URLs are nats:// or tls:// server URLs.
	URLs          []string `yaml:"urls"`
	SubjectPrefix string   `yaml:"subject_prefix"`
	// Streams defaults to events and decisions. Flows are opt-in.
	Streams     []string `yaml:"streams"`
	TLS         bool     `yaml:"tls"`
	CAFile      string   `yaml:"ca_file"`
	UsernameEnv string   `yaml:"username_env"`
	PasswordEnv string   `yaml:"password_env"`
}

type conn interface {
	Publish(subject string, data []byte) error
	FlushWithContext(ctx context.Context) error
	Close()
}

// Exporter publishes records to NATS.
type Exporter struct {
	streams []string
	prefix  string
	urls    string
	opts    []natsgo.Option

	// dial opens the connection; tests replace it.
	dial func(urls string, opts ...natsgo.Option) (conn, error)
	c    conn
}

// New is the plugin factory. It opens no connection.
func New(c plugin.Config, e plugin.Env) (plugin.Exporter, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if len(cfg.URLs) == 0 {
		return nil, errors.New("urls is required")
	}
	for _, s := range cfg.URLs {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "nats" && u.Scheme != "tls") || u.Host == "" {
			return nil, fmt.Errorf("url %q must be nats://host:port or tls://host:port", s)
		}
		if u.User != nil {
			return nil, fmt.Errorf("url %q must not carry credentials; use username_env and password_env", s)
		}
		if u.Scheme == "tls" && !cfg.TLS {
			return nil, fmt.Errorf("url %q is tls:// but tls is false", s)
		}
	}
	if cfg.SubjectPrefix == "" {
		cfg.SubjectPrefix = DefaultSubjectPrefix
	}
	if !validPrefix(cfg.SubjectPrefix) {
		return nil, fmt.Errorf("subject_prefix %q must be dot-separated tokens of letters, digits, '_' and '-'", cfg.SubjectPrefix)
	}
	streams, err := plugin.ParseStreams(cfg.Streams,
		[]string{plugin.StreamEvents, plugin.StreamDecisions},
		[]string{plugin.StreamEvents, plugin.StreamDecisions, plugin.StreamFlows})
	if err != nil {
		return nil, err
	}
	tlsConf, err := sinkcfg.TLS(cfg.TLS, cfg.CAFile)
	if err != nil {
		return nil, err
	}
	user, pass, err := sinkcfg.Credentials(e.Getenv, cfg.UsernameEnv, cfg.PasswordEnv)
	if err != nil {
		return nil, err
	}
	if user != "" && !cfg.TLS {
		return nil, errors.New("username_env needs tls: true (the password would cross the network in clear)")
	}
	opts := []natsgo.Option{
		natsgo.Name("packeteer"),
		natsgo.Timeout(timeout),
		// A server that is down at startup must not stop Packeteer.
		natsgo.RetryOnFailedConnect(true),
		natsgo.MaxReconnects(-1),
	}
	if tlsConf != nil {
		opts = append(opts, natsgo.Secure(tlsConf))
	}
	if user != "" {
		opts = append(opts, natsgo.UserInfo(user, pass))
	}
	return &Exporter{streams: streams, prefix: cfg.SubjectPrefix, urls: strings.Join(cfg.URLs, ","), opts: opts,
		dial: func(u string, o ...natsgo.Option) (conn, error) { return natsgo.Connect(u, o...) }}, nil
}

func validPrefix(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for _, tok := range strings.Split(s, ".") {
		if tok == "" {
			return false
		}
		for _, r := range tok {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Streams implements plugin.Exporter.
func (x *Exporter) Streams() []string { return x.streams }

// Start connects, retrying in the background when the server is down.
func (x *Exporter) Start(context.Context) error {
	c, err := x.dial(x.urls, x.opts...)
	if err != nil {
		return fmt.Errorf("nats connect: %w", err)
	}
	x.c = c
	return nil
}

// Stop closes the connection.
func (x *Exporter) Stop(context.Context) error {
	if x.c != nil {
		x.c.Close()
		x.c = nil
	}
	return nil
}

// Export publishes the batch and flushes, so a delivered count means the
// server has the messages. Subjects are prefix.stream.
func (x *Exporter) Export(ctx context.Context, batch []plugin.ExportRecord) error {
	if x.c == nil {
		return errors.New("nats exporter is not started")
	}
	for _, r := range batch {
		_, body, err := export.JSON(r)
		if err != nil {
			return err
		}
		if err := x.c.Publish(x.prefix+"."+r.Stream, body); err != nil {
			return err
		}
	}
	return x.c.FlushWithContext(ctx)
}
