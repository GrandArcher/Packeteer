package main

import (
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/upgrade"
)

func TestHandlerServesVerifiableRelease(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "packeteer")
	if err := os.WriteFile(bin, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	h, pub, err := handler("127.0.0.1:18190", bin, "9.9.9", "example/packeteer")
	if err != nil {
		t.Fatal(err)
	}
	get := func(method, path string) string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		b, _ := io.ReadAll(rec.Body)
		return string(b)
	}
	if !strings.Contains(get("GET", "/repos/example/packeteer/releases"), `"tag_name":"v9.9.9"`) {
		t.Fatal("no release listed")
	}
	sums, sig := get("GET", "/dl/SHA256SUMS"), get("GET", "/dl/SHA256SUMS.sig")
	if err := upgrade.VerifySignature(pub, []byte(sums), []byte(sig)); err != nil {
		t.Fatal(err)
	}
	get("POST", "/_corrupt?mode=sig")
	if err := upgrade.VerifySignature(pub, []byte(sums), []byte(get("GET", "/dl/SHA256SUMS.sig"))); err == nil {
		t.Fatal("corrupted signature verified")
	}
	get("POST", "/_corrupt?mode=sum")
	badSums := get("GET", "/dl/SHA256SUMS")
	if badSums == sums {
		t.Fatal("corrupted sums unchanged")
	}
	if err := upgrade.VerifySignature(pub, []byte(badSums), []byte(get("GET", "/dl/SHA256SUMS.sig"))); err != nil {
		t.Fatalf("sum mode must be signed so only the checksum check catches it: %v", err)
	}
	if _, _, err := handler("0.0.0.0:1", bin, "9.9.9", "x/y"); err == nil {
		t.Fatal("non-loopback listen accepted")
	}
}
