// Command relsign makes and signs the checksum file of a release (#196).
// The publish workflow runs it on a version tag; the controller's Settings
// upgrade verifies the result against upgrade.public_key.
//
//	relsign keygen                 print a new public and private key (base64)
//	relsign sign DIR FILE...       write DIR/SHA256SUMS and DIR/SHA256SUMS.sig
//
// sign reads the private key from PACKETEER_RELEASE_KEY. It never prints it.
// This is a release tool. It does not touch Packeteer's runtime or announce.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/upgrade"
)

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "relsign:", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: relsign keygen | relsign sign DIR FILE...")
	}
	switch args[0] {
	case "keygen":
		pub, priv, err := upgrade.GenerateKey()
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "public_key: %s\nprivate_key: %s\n", pub, priv)
		return nil
	case "sign":
		if len(args) < 3 {
			return fmt.Errorf("usage: relsign sign DIR FILE...")
		}
		key := getenv("PACKETEER_RELEASE_KEY")
		if key == "" {
			return fmt.Errorf("PACKETEER_RELEASE_KEY is not set")
		}
		return sign(args[1], args[2:], key)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func sign(dir string, files []string, key string) error {
	var sums strings.Builder
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		h := sha256.Sum256(data)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), filepath.Base(f))
	}
	sig, err := upgrade.Sign(key, []byte(sums.String()))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, upgrade.SumsAsset), []byte(sums.String()), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, upgrade.SigAsset), []byte(sig+"\n"), 0o644)
}
