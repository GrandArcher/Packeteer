// Command uiproxy is a loopback reverse proxy that adds HTTP basic auth.
// Headless Chrome does not send credentials from a user:pass URL on the
// page's later fetches, so the UI smoke test points Chrome here.
// With -fixtures it also answers chosen API calls from canned files and
// adds a driver script to one page, because headless Chrome cannot click.
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
	fixtures := flag.String("fixtures", "", "directory with fixtures.json (canned API answers and a page driver); optional")
	flag.Parse()
	if err := serve(*listen, *upstream, *user, *password, *fixtures); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(listen, upstream, user, password, fixtures string) error {
	h, err := handler(upstream, user, password)
	if err != nil {
		return err
	}
	if fixtures != "" {
		f, err := loadFixtures(fixtures)
		if err != nil {
			return err
		}
		h = f.wrap(h)
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
	return &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(u)
		r.SetXForwarded()
		r.Out.SetBasicAuth(user, password)
	}}, nil
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
