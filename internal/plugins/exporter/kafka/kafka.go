// Package kafka implements the "kafka" exporter: events, decisions, and
// optionally tagged flow records are produced to Kafka topics as JSON.
// Credentials come from environment variables, never the config file.
package kafka

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/GrandArcher/Packeteer/internal/export"
	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/sinkcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "kafka"

// timeout bounds one batch; the dispatcher gives the same deadline.
const timeout = 10 * time.Second

// DefaultTopicPrefix gives the topics packeteer.events, packeteer.decisions,
// and packeteer.flows.
const DefaultTopicPrefix = "packeteer"

func init() { plugin.Exporters.Register(TypeName, New) }

// Config is the kafka exporter's config block.
type Config struct {
	// Brokers are seed brokers as host:port.
	Brokers []string `yaml:"brokers"`
	// TopicPrefix is joined with the stream name by a dot.
	TopicPrefix string `yaml:"topic_prefix"`
	// Streams defaults to events and decisions. Flows are opt-in.
	Streams []string `yaml:"streams"`
	TLS     bool     `yaml:"tls"`
	CAFile  string   `yaml:"ca_file"`
	// SASL is plain, scram-sha-256, or scram-sha-512. It always needs TLS.
	SASL        string `yaml:"sasl"`
	UsernameEnv string `yaml:"username_env"`
	PasswordEnv string `yaml:"password_env"`
}

type producer interface {
	ProduceSync(ctx context.Context, rs ...*kgo.Record) kgo.ProduceResults
	Close()
}

// Exporter produces records to Kafka.
type Exporter struct {
	streams []string
	prefix  string
	opts    []kgo.Opt

	// dial builds the client; tests replace it.
	dial func(opts ...kgo.Opt) (producer, error)
	// mu guards p: Start and Stop run on the main goroutine, Export on the
	// export worker, which can run before Start.
	mu sync.Mutex
	p  producer
}

// New is the plugin factory. It opens no connection.
func New(c plugin.Config, e plugin.Env) (plugin.Exporter, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("brokers is required")
	}
	for _, b := range cfg.Brokers {
		if _, _, err := net.SplitHostPort(b); err != nil {
			return nil, fmt.Errorf("broker %q must be host:port", b)
		}
	}
	if cfg.TopicPrefix == "" {
		cfg.TopicPrefix = DefaultTopicPrefix
	}
	if !validTopic(cfg.TopicPrefix) {
		return nil, fmt.Errorf("topic_prefix %q must use letters, digits, '.', '_' and '-' only", cfg.TopicPrefix)
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
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.AllowAutoTopicCreation(),
		kgo.RecordDeliveryTimeout(timeout),
		kgo.ProduceRequestTimeout(timeout),
	}
	if tlsConf != nil {
		opts = append(opts, kgo.DialTLSConfig(tlsConf))
	}
	user, pass, err := sinkcfg.Credentials(e.Getenv, cfg.UsernameEnv, cfg.PasswordEnv)
	if err != nil {
		return nil, err
	}
	if cfg.SASL == "" && user != "" {
		return nil, errors.New("username_env needs sasl")
	}
	if cfg.SASL != "" {
		if user == "" {
			return nil, errors.New("sasl needs username_env and password_env")
		}
		if !cfg.TLS {
			return nil, errors.New("sasl needs tls: true (the password would cross the network in clear)")
		}
		mech, err := mechanism(cfg.SASL, user, pass)
		if err != nil {
			return nil, err
		}
		opts = append(opts, kgo.SASL(mech))
	}
	return &Exporter{streams: streams, prefix: cfg.TopicPrefix, opts: opts,
		dial: func(o ...kgo.Opt) (producer, error) { return kgo.NewClient(o...) }}, nil
}

func mechanism(name, user, pass string) (sasl.Mechanism, error) {
	switch name {
	case "plain":
		return plain.Auth{User: user, Pass: pass}.AsMechanism(), nil
	case "scram-sha-256":
		return scram.Auth{User: user, Pass: pass}.AsSha256Mechanism(), nil
	case "scram-sha-512":
		return scram.Auth{User: user, Pass: pass}.AsSha512Mechanism(), nil
	}
	return nil, fmt.Errorf("sasl %q is invalid (want plain, scram-sha-256, scram-sha-512)", name)
}

func validTopic(s string) bool {
	if len(s) > 100 || s == "." || s == ".." {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-')
	}) < 0
}

// Streams implements plugin.Exporter.
func (x *Exporter) Streams() []string { return x.streams }

// Start builds the client. The first connection is made on first use, so a
// broker that is down at startup does not stop Packeteer.
func (x *Exporter) Start(context.Context) error {
	p, err := x.dial(x.opts...)
	if err != nil {
		return fmt.Errorf("kafka client: %w", err)
	}
	x.mu.Lock()
	x.p = p
	x.mu.Unlock()
	return nil
}

// Stop closes the client.
func (x *Exporter) Stop(context.Context) error {
	x.mu.Lock()
	p := x.p
	x.p = nil
	x.mu.Unlock()
	if p != nil {
		p.Close()
	}
	return nil
}

// Export produces the batch and waits for the broker's acknowledgement.
func (x *Exporter) Export(ctx context.Context, batch []plugin.ExportRecord) error {
	x.mu.Lock()
	p := x.p
	x.mu.Unlock()
	if p == nil {
		return errors.New("kafka exporter is not started")
	}
	recs := make([]*kgo.Record, 0, len(batch))
	for _, r := range batch {
		key, body, err := export.JSON(r)
		if err != nil {
			return err
		}
		recs = append(recs, &kgo.Record{Topic: x.prefix + "." + r.Stream, Key: []byte(key), Value: body, Timestamp: stamp(r)})
	}
	return p.ProduceSync(ctx, recs...).FirstErr()
}

func stamp(r plugin.ExportRecord) time.Time {
	switch {
	case r.Event != nil:
		return r.Event.Time
	case r.Decision != nil:
		return r.Decision.Time
	case r.Flow != nil:
		return r.Flow.Time
	}
	return time.Time{}
}
