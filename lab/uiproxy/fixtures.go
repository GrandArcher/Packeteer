package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// driverPath is where the injected page driver is served from.
const driverPath = "/__fixture-driver.js"

// maxMatchBody bounds how much of a request body a stub inspects.
const maxMatchBody = 4096

// stub answers one API call from a file instead of the origin. Contains is
// matched against the raw query (GET) or the request body (POST).
type stub struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Contains string `json:"contains"`
	Status   int    `json:"status"`
	File     string `json:"file"`
	body     []byte
}

// fixtures is dir/fixtures.json: the stubs, and a script added to one page.
type fixtures struct {
	Stubs  []*stub `json:"stubs"`
	Inject struct {
		Page   string `json:"page"`
		Script string `json:"script"`
	} `json:"inject"`
	driver []byte
}

func loadFixtures(dir string) (*fixtures, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "fixtures.json"))
	if err != nil {
		return nil, err
	}
	var f fixtures
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("fixtures.json: %w", err)
	}
	for _, s := range f.Stubs {
		if s.Method == "" || !strings.HasPrefix(s.Path, "/") || s.File == "" {
			return nil, fmt.Errorf("fixtures.json: a stub needs method, path, and file")
		}
		if s.Status == 0 {
			s.Status = http.StatusOK
		}
		if s.body, err = os.ReadFile(filepath.Join(dir, filepath.Base(s.File))); err != nil {
			return nil, err
		}
	}
	if f.Inject.Page != "" {
		if f.driver, err = os.ReadFile(filepath.Join(dir, filepath.Base(f.Inject.Script))); err != nil {
			return nil, err
		}
	}
	return &f, nil
}

func (f *fixtures) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.Inject.Page != "" && r.URL.Path == driverPath {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			_, _ = w.Write(f.driver)
			return
		}
		subject := r.URL.RawQuery
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(io.LimitReader(r.Body, maxMatchBody))
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
			subject = string(body)
		}
		for _, s := range f.Stubs {
			if s.Method == r.Method && s.Path == r.URL.Path && strings.Contains(subject, s.Contains) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(s.Status)
				_, _ = w.Write(s.body)
				return
			}
		}
		if f.Inject.Page == "" || r.URL.Path != f.Inject.Page {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		page := rec.Body.Bytes()
		if rec.Code == http.StatusOK {
			page = bytes.Replace(page, []byte("</body>"), []byte(`<script src="`+driverPath+`"></script></body>`), 1)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(page)))
		w.WriteHeader(rec.Code)
		_, _ = w.Write(page)
	})
}
