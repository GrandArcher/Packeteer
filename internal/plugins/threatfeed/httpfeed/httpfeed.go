// Package httpfeed is the built-in "http" threat feed (#134). It GETs a
// list of networks from a URL, as plain CIDR lines or as JSON, and returns
// it to the threat feed controller. It never announces.
package httpfeed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"unicode"

	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/sinkcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "http"

// Formats.
const (
	FormatCIDR = "cidr"
	FormatJSON = "json"
)

// Bounds on one fetch. A larger list fails the fetch rather than being
// cut, so the controller never acts on part of a feed.
const (
	MaxBody    = 16 << 20
	MaxEntries = 100000
	maxComment = 128
)

func init() { plugin.ThreatFeeds.Register(TypeName, New) }

// Config is the http feed's config block.
type Config struct {
	// URL is the list's absolute http(s) URL, without credentials or query.
	URL string `yaml:"url"`
	// Format is cidr (default) or json.
	Format string `yaml:"format"`
	// TokenEnv names the environment variable holding a bearer token. The
	// token is never in the config file.
	TokenEnv string `yaml:"token_env"`
}

type feed struct {
	plugin.Base
	url    string
	format string
	token  string
	client *http.Client
}

// New validates the config and reads the token. It opens no connection.
func New(c plugin.Config, env plugin.Env) (plugin.ThreatFeed, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	u, err := sinkcfg.HTTPURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("url %w", err)
	}
	f := &feed{url: u.String(), format: strings.ToLower(strings.TrimSpace(cfg.Format)), client: &http.Client{}}
	switch f.format {
	case "":
		f.format = FormatCIDR
	case FormatCIDR, FormatJSON:
	default:
		return nil, fmt.Errorf("format %q is invalid (want %s or %s)", cfg.Format, FormatCIDR, FormatJSON)
	}
	if cfg.TokenEnv != "" {
		if f.token, err = sinkcfg.Secret(env.Getenv, "token_env", cfg.TokenEnv); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// Stop implements plugin.Lifecycle.
func (f *feed) Stop(context.Context) error {
	f.client.CloseIdleConnections()
	return nil
}

// Fetch GETs and parses the whole list.
func (f *feed) Fetch(ctx context.Context) ([]plugin.ThreatEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, err
	}
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("feed answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBody {
		return nil, fmt.Errorf("feed is larger than %d bytes", MaxBody)
	}
	if f.format == FormatJSON {
		return ParseJSON(body)
	}
	return ParseCIDR(body)
}

// ParseCIDR reads one network per line: a CIDR or a bare address (a host
// route). Blank lines are skipped; text after "#" or ";" is a comment, kept
// as the entry's comment (the DROP list style "192.0.2.0/24 ; SBL1").
func ParseCIDR(body []byte) ([]plugin.ThreatEntry, error) {
	var l list
	for i, line := range bytes.Split(body, []byte("\n")) {
		s, comment := string(line), ""
		if j := strings.IndexAny(s, "#;"); j >= 0 {
			s, comment = s[:j], s[j+1:]
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if err := l.add(s, comment); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	return l.out, nil
}

// ParseJSON reads {"entries": [{"prefix": "192.0.2.0/24", "comment": "..."}]}.
// prefix may be a bare address. Other keys are ignored.
func ParseJSON(body []byte) ([]plugin.ThreatEntry, error) {
	var doc struct {
		Entries *[]struct {
			Prefix  string `json:"prefix"`
			Comment string `json:"comment"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	if doc.Entries == nil {
		return nil, errors.New(`json: no "entries" list`)
	}
	var l list
	for i, e := range *doc.Entries {
		if err := l.add(strings.TrimSpace(e.Prefix), e.Comment); err != nil {
			return nil, fmt.Errorf("entries[%d]: %w", i, err)
		}
	}
	return l.out, nil
}

type list struct {
	out  []plugin.ThreatEntry
	seen map[netip.Prefix]bool
}

func (l *list) add(s, comment string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil || a.Zone() != "" {
			// The text is untrusted and ends up in logs and on the API.
			if len(s) > 64 {
				s = s[:64] + "..."
			}
			return fmt.Errorf("%q is not a CIDR or an address", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	switch {
	case p != p.Masked():
		return fmt.Errorf("%s has host bits set", p)
	case p.Bits() == 0:
		return fmt.Errorf("%s would match every address", p)
	case p.Addr().Is4In6():
		return fmt.Errorf("%s is an IPv4-mapped IPv6 prefix", p)
	}
	if l.seen[p] {
		return nil
	}
	if len(l.out) >= MaxEntries {
		return fmt.Errorf("more than %d entries", MaxEntries)
	}
	if l.seen == nil {
		l.seen = map[netip.Prefix]bool{}
	}
	l.seen[p] = true
	l.out = append(l.out, plugin.ThreatEntry{Prefix: p, Comment: cleanComment(comment)})
	return nil
}

// cleanComment keeps a short printable note: the feed is untrusted text
// that ends up in logs and in the mitigation rule's reason.
func cleanComment(s string) string {
	s = strings.Map(func(r rune) rune {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxComment {
		s = s[:maxComment]
	}
	return s
}
