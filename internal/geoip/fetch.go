package geoip

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// Environment variables with the download account. They are never read
// from the config file, logged, or returned by the API, and are sent only
// over https or to a loopback address.
const (
	UserEnv = "PACKETEER_GEOIP_USER"
	KeyEnv  = "PACKETEER_GEOIP_KEY"
)

const (
	fetchTimeout = 2 * time.Minute
	// maxDatabase bounds the database after decompression. Open reads the
	// whole file into memory, and a country database is about 10 MiB.
	maxDatabase = 128 << 20
	maxRedirect = 5
)

// Status is the outcome of the download, for the setup checklist.
type Status struct {
	// LastError is empty after a successful check.
	LastError string
}

// Fetcher keeps one database file fresh from a URL. It writes only that
// file, and only after the download parses as a country database.
type Fetcher struct {
	cfg    config.GeoIP
	user   string
	key    string
	client *http.Client
	log    *slog.Logger

	mu  sync.Mutex
	err string
}

// NewFetcher builds a fetcher from a validated block. user and key are the
// values of UserEnv and KeyEnv: both set sends basic auth, both empty sends
// none, one of them is an error.
func NewFetcher(cfg config.GeoIP, user, key string, log *slog.Logger) (*Fetcher, error) {
	if (user == "") != (key == "") {
		return nil, fmt.Errorf("geoip: set both %s and %s, or neither", UserEnv, KeyEnv)
	}
	f := &Fetcher{cfg: cfg, user: user, key: key, log: log}
	f.client = &http.Client{
		Timeout: fetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirect {
				return errors.New("too many redirects")
			}
			if !config.SecureURL(req.URL) {
				return errors.New("redirect to a non-https address refused")
			}
			return nil
		},
	}
	return f, nil
}

// Status reports the outcome of the last attempt.
func (f *Fetcher) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Status{LastError: f.err}
}

// Start fetches once when the file is missing or older than the refresh
// interval, so country rules find a database on start. A failure is
// returned and also kept in Status; the caller decides whether the start
// can go on.
func (f *Fetcher) Start(ctx context.Context) error {
	if fi, err := os.Stat(f.cfg.Path); err == nil && time.Since(fi.ModTime()) < f.cfg.Refresh {
		return nil
	}
	return f.Refresh(ctx)
}

// Run fetches again every refresh interval until ctx ends. A failure keeps
// the file in place and is tried again at the next interval.
func (f *Fetcher) Run(ctx context.Context) {
	t := time.NewTicker(f.cfg.Refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := f.Refresh(ctx); err != nil {
				f.log.Warn("geoip: refresh failed; the current file stays in place", "path", f.cfg.Path, "error", err)
			}
		}
	}
}

// Refresh downloads the database and replaces the file when it changed. The
// file is replaced by a rename, so a reader sees the old or the new one.
func (f *Fetcher) Refresh(ctx context.Context) (err error) {
	defer func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.err = ""
		if err != nil {
			f.err = err.Error()
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.URL, nil)
	if err != nil {
		return fmt.Errorf("geoip: %w", err)
	}
	if f.key != "" {
		if !config.SecureURL(req.URL) {
			return errors.New("geoip: refusing to send the account over plain http")
		}
		req.SetBasicAuth(f.user, f.key)
	}
	if fi, err := os.Stat(f.cfg.Path); err == nil {
		req.Header.Set("If-Modified-Since", fi.ModTime().UTC().Format(http.TimeFormat))
	}
	resp, err := f.client.Do(req)
	if err != nil {
		// The URL can carry a query; keep only the host in the message.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("geoip: download from %s: %w", req.URL.Host, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		f.log.Info("geoip: database is current", "path", f.cfg.Path)
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("geoip: download from %s: %s", req.URL.Host, resp.Status)
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.cfg.Path), ".geoip-*.tmp")
	if err != nil {
		return fmt.Errorf("geoip: %w", err)
	}
	defer os.Remove(tmp.Name())
	werr := extract(tmp, resp.Body)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("geoip: %w", werr)
	}
	db, err := Open(tmp.Name())
	if err != nil {
		return fmt.Errorf("geoip: the download is not a usable country database: %w", err)
	}
	if len(db.v4)+len(db.v6) == 0 {
		return errors.New("geoip: the download has no country networks")
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("geoip: %w", err)
	}
	// The server's modification time is what If-Modified-Since is compared
	// with on the next request.
	if lm, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		_ = os.Chtimes(tmp.Name(), lm, lm)
	}
	if err := os.Rename(tmp.Name(), f.cfg.Path); err != nil {
		return fmt.Errorf("geoip: %w", err)
	}
	f.log.Info("geoip: database updated; it is read at the next start", "path", f.cfg.Path, "v4_countries", len(db.v4), "v6_countries", len(db.v6))
	return nil
}

// extract writes the database in r to w. r is a raw .mmdb, a gzip of one,
// or a gzip tar archive holding one (the first .mmdb entry).
func extract(w io.Writer, r io.Reader) error {
	br := bufio.NewReader(r)
	if magic, _ := br.Peek(2); !bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		return copyLimited(w, br)
	}
	zr, err := gzip.NewReader(br)
	if err != nil {
		return err
	}
	zbr := bufio.NewReaderSize(zr, 1024)
	// A tar header has "ustar" at offset 257.
	if head, _ := zbr.Peek(512); len(head) < 512 || !bytes.Equal(head[257:262], []byte("ustar")) {
		return copyLimited(w, zbr)
	}
	tr := tar.NewReader(zbr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("the archive has no .mmdb file")
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeReg && strings.HasSuffix(h.Name, ".mmdb") {
			return copyLimited(w, tr)
		}
	}
}

func copyLimited(w io.Writer, r io.Reader) error {
	n, err := io.Copy(w, io.LimitReader(r, maxDatabase+1))
	if err != nil {
		return err
	}
	if n > maxDatabase {
		return fmt.Errorf("the database is over %d MiB", maxDatabase>>20)
	}
	return nil
}
