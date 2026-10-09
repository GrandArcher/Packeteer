// Command uiproxy is a loopback reverse proxy that adds HTTP basic auth.
// Headless Chrome does not send credentials from a user:pass URL on the
// page's later fetches, so the UI smoke test points Chrome here.
// It is a lab tool. It does not change Packeteer and it announces nothing.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18089", "loopback address to listen on")
	upstream := flag.String("upstream", "", "origin base URL, such as http://127.0.0.1:8080")
	user := flag.String("user", "", "basic auth user sent to the origin")
	password := flag.String("password", "", "basic auth password sent to the origin")
	flag.Parse()
	if err := serve(*listen, *upstream, *user, *password); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(listen, upstream, user, password string) error {
	h, err := handler(upstream, user, password)
	if err != nil {
		return err
	}
	if err := loopback(listen); err != nil {
		return err
	}
	log.Printf("uiproxy %s -> %s", listen, upstream)
	return http.ListenAndServe(listen, h)
}

func handler(upstream, user, password string) (http.Handler, error) {
	if user == "" || password == "" {
		return nil, fmt.Errorf("user and password are required")
	}
	u, err := url.Parse(upstream)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("upstream must be an absolute URL without userinfo")
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	orig := rp.Director
	rp.Director = func(r *http.Request) {
		orig(r)
		r.Host = u.Host
		r.SetBasicAuth(user, password)
	}
	return rp, nil
}

func loopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen %s must be a loopback address", addr)
	}
	return nil
}
