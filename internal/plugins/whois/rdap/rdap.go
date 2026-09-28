// Package rdap is the built-in whois plugin. It asks an RDAP server
// (RFC 9082/9083) about an IP prefix or an ASN for the troubleshooting
// API. It only reads: it never announces routes or changes controller state.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "rdap"

// Defaults.
const (
	DefaultBaseURL  = "https://rdap.org"
	DefaultTimeout  = 5 * time.Second
	DefaultMaxBytes = 256 << 10
	maxRedirects    = 3
)

func init() { plugin.Whoises.Register(TypeName, New) }

// Config is the rdap plugin's config block.
type Config struct {
	// BaseURL is the RDAP service. rdap.org redirects to the right RIR.
	BaseURL  string        `yaml:"base_url"`
	Timeout  time.Duration `yaml:"timeout"`
	MaxBytes int           `yaml:"max_bytes"`
}

// Client is the rdap whois plugin.
type Client struct {
	plugin.Base
	base     *url.URL
	maxBytes int64
	http     *http.Client
}

// New is the plugin factory. It does not touch the network.
func New(c plugin.Config, _ plugin.Env) (plugin.Whois, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("base_url %q must be an http or https URL without credentials, query, or fragment", cfg.BaseURL)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Timeout < 0 || cfg.Timeout > time.Minute {
		return nil, fmt.Errorf("timeout %s must be between 0 and 1m", cfg.Timeout)
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MaxBytes < 1024 || cfg.MaxBytes > 4<<20 {
		return nil, fmt.Errorf("max_bytes %d must be between 1024 and %d", cfg.MaxBytes, 4<<20)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	secure := u.Scheme == "https"
	cl := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			if secure && req.URL.Scheme != "https" {
				return errors.New("refusing redirect from https to " + req.URL.Scheme)
			}
			return nil
		},
	}
	return &Client{base: u, maxBytes: int64(cfg.MaxBytes), http: cl}, nil
}

// response is the subset of an RDAP ip network or autnum object we show.
type response struct {
	Handle       string `json:"handle"`
	Name         string `json:"name"`
	Country      string `json:"country"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	StartAutnum  uint32 `json:"startAutnum"`
	EndAutnum    uint32 `json:"endAutnum"`
	Remarks      []struct {
		Title       string   `json:"title"`
		Description []string `json:"description"`
	} `json:"remarks"`
	ErrorCode   int      `json:"errorCode"`
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

// ParseQuery classifies a whois query. It returns the RDAP path segment
// ("ip/<prefix>" or "autnum/<n>") and the kind.
func ParseQuery(q string) (path, kind string, err error) {
	q = strings.TrimSpace(q)
	up := strings.ToUpper(q)
	if n, ok := strings.CutPrefix(up, "AS"); ok {
		up = n
	}
	if v, err := strconv.ParseUint(up, 10, 32); err == nil && up != "" {
		return "autnum/" + strconv.FormatUint(v, 10), "asn", nil
	}
	if p, err := netip.ParsePrefix(q); err == nil {
		return "ip/" + p.Masked().String(), "ip", nil
	}
	if a, err := netip.ParseAddr(q); err == nil && a.Zone() == "" {
		return "ip/" + a.Unmap().String(), "ip", nil
	}
	return "", "", fmt.Errorf("query %q is not an IP address, prefix, or ASN", q)
}

// Lookup implements plugin.Whois.
func (c *Client) Lookup(ctx context.Context, query string) (plugin.WhoisResult, error) {
	path, kind, err := ParseQuery(query)
	if err != nil {
		return plugin.WhoisResult{}, err
	}
	u := *c.base
	u.Path = c.base.Path + "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return plugin.WhoisResult{}, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return plugin.WhoisResult{}, fmt.Errorf("rdap: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return plugin.WhoisResult{}, fmt.Errorf("rdap: read: %w", err)
	}
	if int64(len(body)) > c.maxBytes {
		return plugin.WhoisResult{}, fmt.Errorf("rdap: response larger than %d bytes", c.maxBytes)
	}
	var r response
	if err := json.Unmarshal(body, &r); err != nil {
		if resp.StatusCode != http.StatusOK {
			return plugin.WhoisResult{}, fmt.Errorf("rdap: %s", resp.Status)
		}
		return plugin.WhoisResult{}, fmt.Errorf("rdap: decode: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := resp.Status
		if r.Title != "" {
			msg += ": " + r.Title
		}
		return plugin.WhoisResult{}, fmt.Errorf("rdap: %s", msg)
	}
	out := plugin.WhoisResult{Query: strings.TrimSpace(query), Kind: kind, Handle: r.Handle, Name: r.Name,
		Country: r.Country, Source: resp.Request.URL.String(), Raw: body}
	switch {
	case r.StartAddress != "" || r.EndAddress != "":
		out.Range = r.StartAddress + " - " + r.EndAddress
	case r.StartAutnum != 0 || r.EndAutnum != 0:
		out.Range = fmt.Sprintf("AS%d - AS%d", r.StartAutnum, r.EndAutnum)
	}
	for _, rm := range r.Remarks {
		line := strings.TrimSpace(strings.Join(rm.Description, " "))
		if rm.Title != "" {
			line = strings.TrimSpace(rm.Title + ": " + line)
		}
		if line != "" && len(out.Remarks) < 10 {
			out.Remarks = append(out.Remarks, line)
		}
	}
	return out, nil
}
