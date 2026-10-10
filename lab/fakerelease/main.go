// Command fakerelease is a lab stand-in for the GitHub releases API. It
// serves one signed release (v<version>) whose binary is the file you give
// it, so the upgrade e2e (lab/e2e-upgrade.sh) can run without the network.
// A fresh Ed25519 key is made on every start; its public key is written to
// -pubkey-file for the controller's upgrade.public_key. POST /_corrupt?mode=
// sig|sum|none makes the next downloads fail verification (sig: a signature that does not match; sum: a signed checksum file that does not match the binary), to prove a bad
// release changes nothing. It is a lab tool and it announces nothing.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/GrandArcher/Packeteer/internal/upgrade"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18190", "loopback address to listen on")
	binary := flag.String("binary", "", "the release's packeteer binary (linux, static)")
	version := flag.String("version", "9.9.9", "release version, without the v")
	repo := flag.String("repo", "example/packeteer", "owner/name the API serves")
	pubFile := flag.String("pubkey-file", "", "write the base64 public key here")
	flag.Parse()
	h, pub, err := handler(*listen, *binary, *version, *repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fakerelease:", err)
		os.Exit(1)
	}
	if *pubFile != "" {
		if err := os.WriteFile(*pubFile, []byte(pub), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "fakerelease:", err)
			os.Exit(1)
		}
	}
	log.Printf("fakerelease %s serving v%s of %s", *listen, *version, *repo)
	log.Fatal(http.ListenAndServe(*listen, h))
}

func handler(listen, binaryPath, version, repo string) (http.Handler, string, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || (host != "127.0.0.1" && host != "::1" && host != "localhost") {
		return nil, "", fmt.Errorf("listen %q must be a loopback address", listen)
	}
	bin, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, "", err
	}
	pub, priv, err := upgrade.GenerateKey()
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(bin)
	h := hex.EncodeToString(sum[:])
	sums := h + "  packeteer-linux-amd64\n" + h + "  packeteer-linux-arm64\n"
	sig, err := upgrade.Sign(priv, []byte(sums))
	if err != nil {
		return nil, "", err
	}
	otherSig, _ := upgrade.Sign(priv, []byte("not the checksum file"))
	// sum mode: a correctly signed checksum file that does not match the
	// binary, so only the checksum check can catch it.
	zero := strings.Repeat("0", 64)
	badSums := zero + "  packeteer-linux-amd64\n" + zero + "  packeteer-linux-arm64\n"
	badSumsSig, _ := upgrade.Sign(priv, []byte(badSums))
	var corrupt atomic.Value
	corrupt.Store("none")
	base := "http://" + listen
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/"+repo+"/releases", func(w http.ResponseWriter, r *http.Request) {
		var assets []string
		for _, n := range []string{"packeteer-linux-amd64", "packeteer-linux-arm64", "SHA256SUMS", "SHA256SUMS.sig"} {
			assets = append(assets, fmt.Sprintf(`{"name":%q,"browser_download_url":"%s/dl/%s"}`, n, base, n))
		}
		fmt.Fprintf(w, `[{"tag_name":"v%s","name":"Packeteer %s","body":"Lab release %s. Release notes are shown as text.","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z","assets":[%s]}]`,
			version, version, version, strings.Join(assets, ","))
	})
	mux.HandleFunc("GET /dl/{name}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("name") {
		case "SHA256SUMS":
			if corrupt.Load() == "sum" {
				fmt.Fprint(w, badSums)
				return
			}
			fmt.Fprint(w, sums)
		case "SHA256SUMS.sig":
			switch corrupt.Load() {
			case "sig":
				fmt.Fprint(w, otherSig)
				return
			case "sum":
				fmt.Fprint(w, badSumsSig)
				return
			}
			fmt.Fprint(w, sig)
		case "packeteer-linux-amd64", "packeteer-linux-arm64":
			_, _ = w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("POST /_corrupt", func(w http.ResponseWriter, r *http.Request) {
		m := r.URL.Query().Get("mode")
		if m != "sig" && m != "sum" && m != "none" {
			http.Error(w, "mode must be sig, sum, or none", http.StatusBadRequest)
			return
		}
		corrupt.Store(m)
		fmt.Fprintln(w, "ok", m)
	})
	return mux, pub, nil
}
