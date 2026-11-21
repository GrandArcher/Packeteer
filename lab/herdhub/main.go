// Command herdhub is the local herd hub of the herd lab (lab/e2e-herd.sh,
// #659, #672): an https server that serves one hub list document at
// /herd.json, as a hub repository would publish it (docs/herd-hub.md), and
// optionally the identity document at /rsc.json (docs/herd.md, #708): the
// RPKI Signed Checklists that the lab rpki-client validated, read from its
// JSON output on every request. The script builds the list from the
// members' entries with "packeteer herd hub-check -list" and adds the
// entries a node must refuse. The hub signs and checks nothing and holds no
// measurements: every node checks every entry itself, and rpki-client
// checks every checklist. Each request is logged, so the script can see
// which members fetched what.
//
// With -relay-config it is also the seed node the hub list names: a herd
// pull API (mutual TLS, the herd code itself) that serves no records and
// whose peer list relays every entry file in the -relay directory as is,
// good and bad, so members find each other by peer exchange and must refuse
// the bad ones. It is a lab tool, not a public hub, and it announces
// nothing.
//
// Usage: herdhub -cert FILE -key FILE -list FILE [-rpki-client FILE] [-relay-config FILE -relay DIR]
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	cert := flag.String("cert", "", "TLS certificate")
	key := flag.String("key", "", "TLS key")
	list := flag.String("list", "", "hub list document to serve at /herd.json")
	rpkiOut := flag.String("rpki-client", "", "rpki-client -j -f output whose valid checklists are served at /rsc.json")
	relayCfg := flag.String("relay-config", "", "config of the seed node whose peer list relays the -relay entries")
	relayDir := flag.String("relay", "", "directory of entry documents the seed node relays")
	flag.Parse()
	if *cert == "" || *key == "" || *list == "" || (*relayCfg == "") != (*relayDir == "") {
		log.Fatal("herdhub: -cert, -key, and -list are required; -relay-config and -relay go together")
	}
	if *relayCfg != "" {
		if _, err := startRelay(*relayCfg, *relayDir, log.Default()); err != nil {
			log.Fatal("herdhub: ", err)
		}
	}
	docs := map[string]func() ([]byte, error){"/herd.json": func() ([]byte, error) { return os.ReadFile(*list) }}
	if *rpkiOut != "" {
		docs["/rsc.json"] = checklistDoc(*rpkiOut)
	}
	srv := &http.Server{Addr: ":8443", Handler: handler(docs, log.Default()), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

// handler serves each document at its path with GET, built on every request.
func handler(docs map[string]func() ([]byte, error), logger *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("herdhub: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		doc, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		b, err := doc()
		if err != nil {
			logger.Printf("herdhub: %s: %v", r.URL.Path, err)
			http.Error(w, "no document", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
}
