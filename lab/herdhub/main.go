// Command herdhub is the local herd hub of the herd lab (lab/e2e-herd.sh,
// #659): an https server that serves one hub list document at /herd.json,
// as a hub repository would publish it (docs/herd-hub.md). The script
// builds the list from the members' entries with "packeteer herd
// hub-check -list" and adds the entries a node must refuse. The hub signs
// and checks nothing and holds no measurements: every node checks every
// entry itself. Each request is logged, so the script can see which
// members fetched the list. It is a lab tool, not a public hub, and it
// announces nothing.
//
// Usage: herdhub -cert FILE -key FILE -list FILE [-listen ADDR]
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	listen := flag.String("listen", ":8443", "address to listen on")
	cert := flag.String("cert", "", "TLS certificate")
	key := flag.String("key", "", "TLS key")
	list := flag.String("list", "", "hub list document to serve")
	flag.Parse()
	if *cert == "" || *key == "" || *list == "" {
		log.Fatal("herdhub: -cert, -key, and -list are required")
	}
	srv := &http.Server{Addr: *listen, Handler: handler(*list, log.Default()), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

// handler serves the list file at GET /herd.json, read on every request.
func handler(list string, logger *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("herdhub: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		if r.URL.Path != "/herd.json" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		b, err := os.ReadFile(list)
		if err != nil {
			http.Error(w, "no hub list", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
}
