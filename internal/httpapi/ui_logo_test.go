package httpapi

import (
	"bytes"
	"image/png"
	"io/fs"
	"net/http"
	"testing"
)

// TestLogo checks the embedded mark (#327). The UI copies the 128px file
// and serves it without a session, because the sign-in page's favicon is
// requested before anyone is signed in. Pages do not link docs/.
func TestLogo(t *testing.T) {
	b, err := fs.ReadFile(webFS, "web/logo.png")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		t.Fatal("logo.png is not a PNG")
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Width != 128 || cfg.Height != 128 {
		t.Fatalf("logo.png is %dx%d, want the 128px mark", cfg.Width, cfg.Height)
	}
	// The 512px README file is about 170KB. The UI file is the smaller one.
	if len(b) < 1000 || len(b) > 40000 {
		t.Fatalf("logo.png is %d bytes, want the 128px mark", len(b))
	}
	if _, err := png.Decode(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}

	e := newRBAC(t, nil)
	rec := e.do(http.MethodGet, "/logo.png", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymous GET /logo.png = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("content-type %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("logo response missing nosniff")
	}
	if !bytes.Equal(rec.Body.Bytes(), b) {
		t.Fatalf("served %d bytes, embed is %d", rec.Body.Len(), len(b))
	}
	got, err := png.DecodeConfig(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Width != 128 || got.Height != 128 {
		t.Fatalf("served image is %dx%d", got.Width, got.Height)
	}
}
