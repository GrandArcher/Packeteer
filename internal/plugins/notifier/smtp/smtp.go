// Package smtp implements the "smtp" notifier: each event is sent as a
// plain-text email through a relay. Credentials are read from environment
// variables named in config, never from the config file.
package smtp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "smtp"

// Defaults and bounds.
const (
	DefaultTimeout = 10 * time.Second
	MaxTimeout     = 2 * time.Minute
	MaxRecipients  = 50
	DefaultSubject = "[packeteer]"
)

// TLS modes.
const (
	TLSStartTLS = "starttls"
	TLSImplicit = "tls"
	TLSNone     = "none"
)

func init() { plugin.Notifiers.Register(TypeName, New) }

// Config is the smtp notifier's config block.
type Config struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	// TLS is starttls (default, required; no plaintext fallback), tls
	// (implicit TLS, usually port 465), or none (no credentials allowed).
	TLS string `yaml:"tls"`
	// CAFile is an optional PEM bundle for a private relay CA. The
	// system roots are used when it is empty.
	CAFile string `yaml:"ca_file"`
	// UsernameEnv and PasswordEnv name environment variables. Both or
	// neither. AUTH PLAIN is used only over TLS.
	UsernameEnv   string        `yaml:"username_env"`
	PasswordEnv   string        `yaml:"password_env"`
	From          string        `yaml:"from"`
	To            []string      `yaml:"to"`
	SubjectPrefix *string       `yaml:"subject_prefix"`
	HELO          string        `yaml:"helo"`
	Timeout       time.Duration `yaml:"timeout"`

	plugin.EventFilter `yaml:",inline"`
}

// Notifier sends one email per event.
type Notifier struct {
	plugin.Base
	host    string
	addr    string
	mode    string
	tlsConf *tls.Config
	user    string
	pass    string
	from    string
	to      []string
	subject string
	helo    string
	timeout time.Duration
	gate    *plugin.EventGate
	now     func() time.Time
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// New is the plugin factory. It does no network I/O.
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
	n := &Notifier{gate: gate, now: time.Now}
	host := strings.TrimSpace(cfg.Host)
	if host == "" || strings.ContainsAny(host, " /:") && net.ParseIP(host) == nil {
		return nil, fmt.Errorf("host is required and must be a hostname or IP address")
	}
	n.host = host
	n.mode = cfg.TLS
	if n.mode == "" {
		n.mode = TLSStartTLS
	}
	port := cfg.Port
	switch n.mode {
	case TLSStartTLS:
		if port == 0 {
			port = 587
		}
	case TLSImplicit:
		if port == 0 {
			port = 465
		}
	case TLSNone:
		if port == 0 {
			port = 25
		}
	default:
		return nil, fmt.Errorf("tls %q is invalid (want starttls, tls, none)", cfg.TLS)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %d must be between 1 and 65535", cfg.Port)
	}
	n.addr = net.JoinHostPort(host, strconv.Itoa(port))
	if n.mode != TLSNone {
		n.tlsConf = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			if !filepath.IsAbs(cfg.CAFile) {
				return nil, fmt.Errorf("ca_file must be an absolute path")
			}
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("ca_file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("ca_file: no PEM certificates")
			}
			n.tlsConf.RootCAs = pool
		}
	} else if cfg.CAFile != "" {
		return nil, fmt.Errorf("ca_file needs tls starttls or tls")
	}
	if (cfg.UsernameEnv == "") != (cfg.PasswordEnv == "") {
		return nil, fmt.Errorf("set both username_env and password_env, or neither")
	}
	if cfg.UsernameEnv != "" {
		if n.mode == TLSNone {
			return nil, fmt.Errorf("credentials require tls starttls or tls")
		}
		for _, v := range []string{cfg.UsernameEnv, cfg.PasswordEnv} {
			if !envName.MatchString(v) {
				return nil, fmt.Errorf("%q is not an environment variable name", v)
			}
		}
		n.user, n.pass = getenv(cfg.UsernameEnv), getenv(cfg.PasswordEnv)
		if n.user == "" || n.pass == "" {
			return nil, fmt.Errorf("%s and %s must be set in the environment", cfg.UsernameEnv, cfg.PasswordEnv)
		}
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("from: %w", err)
	}
	n.from = from.Address
	if len(cfg.To) == 0 || len(cfg.To) > MaxRecipients {
		return nil, fmt.Errorf("to needs 1 to %d addresses", MaxRecipients)
	}
	for i, t := range cfg.To {
		a, err := mail.ParseAddress(t)
		if err != nil {
			return nil, fmt.Errorf("to[%d]: %w", i, err)
		}
		n.to = append(n.to, a.Address)
	}
	n.subject = DefaultSubject
	if cfg.SubjectPrefix != nil {
		n.subject = headerSafe(*cfg.SubjectPrefix)
	}
	n.helo = cfg.HELO
	if n.helo == "" {
		n.helo = "localhost"
	}
	if strings.ContainsAny(n.helo, " \r\n") {
		return nil, fmt.Errorf("helo must be a hostname")
	}
	if cfg.Timeout < 0 || cfg.Timeout > MaxTimeout {
		return nil, fmt.Errorf("timeout %s must be between 0 and %s", cfg.Timeout, MaxTimeout)
	}
	n.timeout = cfg.Timeout
	if n.timeout == 0 {
		n.timeout = DefaultTimeout
	}
	return n, nil
}

// EventGate implements plugin.Gated.
func (n *Notifier) EventGate() *plugin.EventGate { return n.gate }

// Notify implements plugin.Notifier.
func (n *Notifier) Notify(ctx context.Context, e plugin.Event) error {
	if !n.gate.Match(e) {
		return nil
	}
	if err := n.send(ctx, n.to, n.message(e)); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return nil
}

func (n *Notifier) send(ctx context.Context, to []string, msg []byte) error {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", n.addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if n.mode == TLSImplicit {
		tc := tls.Client(conn, n.tlsConf)
		if err := tc.HandshakeContext(ctx); err != nil {
			return err
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, n.host)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello(n.helo); err != nil {
		return err
	}
	if n.mode == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS (set tls: none only for a trusted local relay)")
		}
		if err := c.StartTLS(n.tlsConf); err != nil {
			return err
		}
	}
	if n.user != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("server does not offer AUTH")
		}
		if err := c.Auth(smtp.PlainAuth("", n.user, n.pass, n.host)); err != nil {
			return err
		}
	}
	if err := c.Mail(n.from); err != nil {
		return err
	}
	for _, t := range to {
		if err := c.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// message renders RFC 5322 headers and a quoted-printable text body.
func (n *Notifier) message(e plugin.Event) []byte {
	var b bytes.Buffer
	subject := fmt.Sprintf("[%s] %s: %s", strings.ToUpper(string(e.Severity)), e.Kind, e.Message)
	if n.subject != "" {
		subject = n.subject + " " + subject
	}
	now := e.Time
	if now.IsZero() {
		now = n.now()
	}
	hdr := [][2]string{
		{"From", n.from},
		{"To", strings.Join(n.to, ", ")},
		{"Subject", mime.QEncoding.Encode("utf-8", headerSafe(subject))},
		{"Date", now.Format(time.RFC1123Z)},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "quoted-printable"},
		{"X-Packeteer-Event", headerSafe(e.Kind)},
		{"X-Packeteer-Severity", headerSafe(string(e.Severity))},
	}
	for _, h := range hdr {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	b.WriteString("\r\n")
	var body strings.Builder
	fmt.Fprintf(&body, "%s\r\n\r\n", e.Message)
	fmt.Fprintf(&body, "kind: %s\r\nseverity: %s\r\ntime: %s\r\n", e.Kind, e.Severity, now.UTC().Format(time.RFC3339))
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&body, "%s: %s\r\n", k, e.Fields[k])
	}
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(body.String()))
	_ = qp.Close()
	return b.Bytes()
}

var _ plugin.ReportSender = (*Notifier)(nil)

// SendReport implements plugin.ReportSender (report subscriptions, #34):
// one multipart email with a text body and the report attached. m.To,
// from the config file, replaces the notifier's recipients when set.
func (n *Notifier) SendReport(ctx context.Context, m plugin.ReportMail) error {
	to := n.to
	if len(m.To) > 0 {
		if len(m.To) > MaxRecipients {
			return fmt.Errorf("smtp: report to needs at most %d addresses", MaxRecipients)
		}
		to = nil
		for i, t := range m.To {
			a, err := mail.ParseAddress(t)
			if err != nil {
				return fmt.Errorf("smtp: report to[%d]: %w", i, err)
			}
			to = append(to, a.Address)
		}
	}
	if err := n.send(ctx, to, n.reportMessage(m, to)); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return nil
}

// reportMessage renders a multipart/mixed message: a quoted-printable
// text part and one base64 part per attachment.
func (n *Notifier) reportMessage(m plugin.ReportMail, to []string) []byte {
	var b bytes.Buffer
	subject := headerSafe(m.Subject)
	if n.subject != "" {
		subject = n.subject + " " + subject
	}
	boundary := fmt.Sprintf("packeteer-%x", sha256.Sum256([]byte(m.Subscription+"\x00"+m.Subject+"\x00"+m.Text)))[:40]
	hdr := [][2]string{
		{"From", n.from},
		{"To", strings.Join(to, ", ")},
		{"Subject", mime.QEncoding.Encode("utf-8", subject)},
		{"Date", n.now().Format(time.RFC1123Z)},
		{"MIME-Version", "1.0"},
		{"Content-Type", `multipart/mixed; boundary="` + boundary + `"`},
		{"X-Packeteer-Report", headerSafe(m.Report)},
		{"X-Packeteer-Subscription", headerSafe(m.Subscription)},
	}
	for _, h := range hdr {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary)
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(m.Text, "\n", "\r\n")))
	_ = qp.Close()
	b.WriteString("\r\n")
	for _, a := range m.Attachments {
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		name := strings.Map(func(r rune) rune {
			if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
				return '_'
			}
			return r
		}, a.Name)
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"%s\"\r\n\r\n",
			boundary, headerSafe(ct), name)
		enc := base64.StdEncoding.EncodeToString(a.Data)
		for len(enc) > 76 {
			b.WriteString(enc[:76] + "\r\n")
			enc = enc[76:]
		}
		b.WriteString(enc + "\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}

// headerSafe removes CR and LF so a message or field cannot add headers.
func headerSafe(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}
