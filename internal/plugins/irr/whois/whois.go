// Package whois is the IRR whois source (#214): route/route6, as-set, and
// aut-num lookups over the whois protocol (TCP port 43) against an IRRd v4
// server or mirror, whose !s selects databases such as RADB, RIPE, ARIN,
// APNIC, AFRINIC, LACNIC, NTTCOM, ALTDB, and LEVEL3, or against a RIPE
// database style server (whois.ripe.net, whois.apnic.net,
// whois.afrinic.net). Each lookup is one connection, rate-limited. It only
// reads: it never announces and never changes the learned RIB.
package whois

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/irr"
	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "whois"

// Query dialects.
const (
	DialectIRRd = "irrd"
	DialectRIPE = "ripe"
)

// Defaults and bounds.
const (
	DefaultTimeout       = 10 * time.Second
	MinTimeout           = time.Second
	MaxTimeout           = time.Minute
	DefaultRatePerMinute = 60
	MaxRatePerMinute     = 600
	maxDatabases         = 32
	// maxResponse bounds one answer; a full as-set expansion of a large
	// transit is well under it.
	maxResponse = 64 << 20
)

func init() { plugin.IRRs.Register(TypeName, New) }

// Config is the plugin's config block.
type Config struct {
	// Address is the server as host:port.
	Address string `yaml:"address"`
	// Dialect is irrd (the ! commands) or ripe (RIPE database flags).
	Dialect string `yaml:"dialect"`
	// Databases are the IRR databases to query, in priority order (IRRd
	// !s, RIPE -s). Empty uses the server's default.
	Databases []string `yaml:"databases"`
	// Timeout bounds one lookup: dial, query, and answer.
	Timeout time.Duration `yaml:"timeout"`
	// RatePerMinute caps the connections opened to the server.
	RatePerMinute int `yaml:"rate_per_minute"`
}

var databaseName = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]*$`)

// Client queries one whois server.
type Client struct {
	plugin.Base
	cfg   Config
	limit *rate.Limiter
}

// New is the plugin factory. It validates the config and opens nothing.
func New(c plugin.Config, _ plugin.Env) (plugin.IRR, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if _, port, err := net.SplitHostPort(cfg.Address); err != nil || port == "" {
		return nil, fmt.Errorf("address %q must be host:port", cfg.Address)
	}
	switch cfg.Dialect {
	case "":
		cfg.Dialect = DialectIRRd
	case DialectIRRd, DialectRIPE:
	default:
		return nil, fmt.Errorf("dialect %q must be %s or %s", cfg.Dialect, DialectIRRd, DialectRIPE)
	}
	if len(cfg.Databases) > maxDatabases {
		return nil, fmt.Errorf("databases: at most %d", maxDatabases)
	}
	for i, d := range cfg.Databases {
		d = strings.ToUpper(strings.TrimSpace(d))
		if !databaseName.MatchString(d) {
			return nil, fmt.Errorf("databases[%d] %q is not a database name", i, cfg.Databases[i])
		}
		if slices.Contains(cfg.Databases[:i], d) {
			return nil, fmt.Errorf("databases[%d] %s is listed twice", i, d)
		}
		cfg.Databases[i] = d
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Timeout < MinTimeout || cfg.Timeout > MaxTimeout {
		return nil, fmt.Errorf("timeout %s must be between %s and %s", cfg.Timeout, MinTimeout, MaxTimeout)
	}
	if cfg.RatePerMinute == 0 {
		cfg.RatePerMinute = DefaultRatePerMinute
	}
	if cfg.RatePerMinute < 1 || cfg.RatePerMinute > MaxRatePerMinute {
		return nil, fmt.Errorf("rate_per_minute %d must be between 1 and %d", cfg.RatePerMinute, MaxRatePerMinute)
	}
	return &Client{cfg: cfg, limit: rate.NewLimiter(rate.Limit(float64(cfg.RatePerMinute)/60), 1)}, nil
}

// Routes returns the route and route6 objects for exactly prefix, ordered
// by the databases list.
func (c *Client) Routes(ctx context.Context, prefix netip.Prefix) ([]plugin.IRRRoute, time.Time, error) {
	prefix = prefix.Masked()
	var objs []irr.Object
	var err error
	if c.cfg.Dialect == DialectIRRd {
		objs, err = c.irrdObjects(ctx, "!r"+prefix.String())
	} else {
		objs, err = c.ripeObjects(ctx, "-x -T route,route6 "+prefix.String())
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	var out []plugin.IRRRoute
	for _, o := range objs {
		if rt, ok := irr.Route(o); ok && rt.Prefix == prefix {
			out = append(out, rt)
		}
	}
	slices.SortStableFunc(out, func(a, b plugin.IRRRoute) int { return c.rank(a.Database) - c.rank(b.Database) })
	return out, time.Now(), nil
}

// rank is a database's place in the databases list; unlisted ones go last.
func (c *Client) rank(db string) int {
	if i := slices.Index(c.cfg.Databases, db); i >= 0 {
		return i
	}
	return len(c.cfg.Databases)
}

// ASSetMembers expands an as-set: on the server for irrd (!i with ,1), set
// by set for ripe.
func (c *Client) ASSetMembers(ctx context.Context, name string) ([]uint32, time.Time, error) {
	if !irr.ValidASSetName(name) {
		return nil, time.Time{}, fmt.Errorf("whois: %q is not an as-set name", name)
	}
	if c.cfg.Dialect == DialectIRRd {
		body, found, err := c.irrd(ctx, "!i"+name+",1")
		if err != nil || !found {
			return nil, time.Now(), err
		}
		var out []uint32
		for _, tok := range strings.Fields(body) {
			if asn, ok := netpfx.ParseASN(tok); ok {
				out = append(out, asn)
			}
		}
		return out, time.Now(), nil
	}
	out, err := irr.Expand(name, func(set string) ([]uint32, []string, bool, error) {
		objs, err := c.ripeObjects(ctx, "-T as-set "+set)
		if err != nil {
			return nil, nil, false, err
		}
		for _, o := range objs {
			if o.Class() == "as-set" && strings.EqualFold(o[0].Value, set) {
				asns, sets := irr.Members(o)
				return asns, sets, true, nil
			}
		}
		return nil, nil, false, nil
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return out, time.Now(), nil
}

// ASName returns the as-name of the aut-num object for asn.
func (c *Client) ASName(ctx context.Context, asn uint32) (string, time.Time, error) {
	key := "AS" + strconv.FormatUint(uint64(asn), 10)
	var objs []irr.Object
	var err error
	if c.cfg.Dialect == DialectIRRd {
		objs, err = c.irrdObjects(ctx, "!maut-num,"+key)
	} else {
		objs, err = c.ripeObjects(ctx, "-T aut-num "+key)
	}
	if err != nil {
		return "", time.Time{}, err
	}
	for _, o := range objs {
		if o.Class() == "aut-num" && strings.EqualFold(o[0].Value, key) {
			return o.Get("as-name"), time.Now(), nil
		}
	}
	return "", time.Now(), nil
}

func (c *Client) irrdObjects(ctx context.Context, query string) ([]irr.Object, error) {
	body, found, err := c.irrd(ctx, query)
	if err != nil || !found {
		return nil, err
	}
	return parse(strings.NewReader(body))
}

func parse(r io.Reader) ([]irr.Object, error) {
	var objs []irr.Object
	err := irr.ParseRPSL(r, func(o irr.Object) error {
		objs = append(objs, o)
		return nil
	})
	return objs, err
}

// irrd sends !! (keep the connection for the next command), the !s
// database selection when set, and query, and reads the answers in order
// (IRRd whois framing: A<length> and the data then C, C alone for no
// entries, D for a key not found, F and a message for an error). found is
// false for C alone and D.
func (c *Client) irrd(ctx context.Context, query string) (string, bool, error) {
	conn, br, done, err := c.open(ctx)
	if err != nil {
		return "", false, err
	}
	defer done()
	var b strings.Builder
	b.WriteString("!!\n")
	if len(c.cfg.Databases) > 0 {
		b.WriteString("!s" + strings.Join(c.cfg.Databases, ",") + "\n")
	}
	b.WriteString(query + "\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return "", false, fmt.Errorf("whois: %w", err)
	}
	if len(c.cfg.Databases) > 0 {
		if _, _, err := readIRRd(br); err != nil {
			return "", false, fmt.Errorf("whois: !s: %w", err)
		}
	}
	body, found, err := readIRRd(br)
	if err != nil {
		return "", false, fmt.Errorf("whois: %s: %w", query, err)
	}
	return body, found, nil
}

func readIRRd(br *bufio.Reader) (string, bool, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", false, err
	}
	line = strings.TrimRight(line, "\r\n")
	switch {
	case line == "C" || line == "D":
		return "", false, nil
	case strings.HasPrefix(line, "F"):
		return "", false, fmt.Errorf("server error: %s", strings.TrimSpace(line[1:]))
	case strings.HasPrefix(line, "A"):
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < 0 || n > maxResponse {
			return "", false, fmt.Errorf("bad length line %.40q", line)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", false, err
		}
		end, err := br.ReadString('\n')
		if err != nil {
			return "", false, err
		}
		if strings.TrimRight(end, "\r\n") != "C" {
			return "", false, fmt.Errorf("answer not ended by C: %.40q", end)
		}
		return string(buf), true, nil
	}
	return "", false, fmt.Errorf("unexpected line %.40q", line)
}

// ripeNoEntries is the RIPE database's answer when nothing matched.
const ripeNoEntries = "%ERROR:101:"

// ripeObjects sends one RIPE-style query with -r (no contact objects) and
// -s for the databases, and parses the objects until the server closes.
func (c *Client) ripeObjects(ctx context.Context, query string) ([]irr.Object, error) {
	conn, br, done, err := c.open(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	q := "-r "
	if len(c.cfg.Databases) > 0 {
		q += "-s " + strings.Join(c.cfg.Databases, ",") + " "
	}
	if _, err := io.WriteString(conn, q+query+"\n"); err != nil {
		return nil, fmt.Errorf("whois: %w", err)
	}
	body, err := io.ReadAll(io.LimitReader(br, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("whois: %w", err)
	}
	if len(body) > maxResponse {
		return nil, errors.New("whois: answer too large")
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "%ERROR:") && !strings.HasPrefix(line, ripeNoEntries) {
			return nil, fmt.Errorf("whois: server error: %s", strings.TrimSpace(strings.TrimPrefix(line, "%")))
		}
	}
	return parse(strings.NewReader(string(body)))
}

// open waits on the rate limit and dials. The timeout covers the whole
// lookup, and ending ctx closes the connection so shutdown does not wait
// on a slow server. done closes it.
func (c *Client) open(ctx context.Context) (net.Conn, *bufio.Reader, func(), error) {
	if err := c.limit.Wait(ctx); err != nil {
		return nil, nil, nil, err
	}
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", c.cfg.Address)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("whois: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(c.cfg.Timeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return conn, bufio.NewReader(conn), func() { stop(); _ = conn.Close() }, nil
}
