package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/herd"
)

// runHerd runs the "herd" subcommands, which work on hub entries and
// never start the controller.
func runHerd(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "entry":
			return runHerdEntry(args[1:], getenv, stdout, stderr)
		case "hub-check":
			return runHubCheck(args[1:], time.Now(), stdout, stderr)
		}
	}
	fmt.Fprintln(stderr, "usage: packeteer herd entry -url URL [flags]    print this node's signed hub entry\n       packeteer herd hub-check [-prune] [-list FILE] DIR    check a directory of hub entries")
	return 2
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// runHerdEntry prints the signed entry that joins this node to the hub
// list. It reads the existing node key and never creates one.
func runHerdEntry(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("herd entry", flag.ContinueOnError)
	fs.SetOutput(stderr)
	defaultPath := DefaultConfigPath
	if p := getenv(ConfigEnv); p != "" {
		defaultPath = p
	}
	path := fs.String("config", defaultPath, "path to the YAML config file (env "+ConfigEnv+")")
	endpoint := fs.String("url", "", "https://host:port peers reach this node's herd.listen at (required)")
	var others listFlag
	fs.Var(&others, "node", "another node of this ASN as ed25519:<key>=https://host:port (repeatable)")
	valid := fs.Duration("valid", 90*24*time.Hour, "how long the entry stays valid (at most "+herd.MaxEntryLife.String()+")")
	stmtURL := fs.String("statement-url", "", "https URL of the identity statement")
	stmtSum := fs.String("statement-sha256", "", "SHA-256 of the identity statement, in lowercase hex")
	rscURL := fs.String("rsc-url", "", "https URL of the RSC that signs the statement's digest")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "packeteer: herd entry: %v\n", err)
		return 1
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return fail(err)
	}
	if !cfg.HerdOn() || cfg.Herd.PreviewOnly {
		return fail(errors.New("herd is not serving: set herd.enabled and clear herd.preview_only"))
	}
	if *endpoint == "" {
		return fail(errors.New("-url is required"))
	}
	node, err := herd.OpenNode(cfg.Herd.KeyFile)
	if errors.Is(err, os.ErrNotExist) {
		return fail(fmt.Errorf("no node key at %s: start the controller once so it creates one", cfg.Herd.KeyFile))
	}
	if err != nil {
		return fail(err)
	}
	e := herd.Entry{
		ASN: cfg.ASN, RetentionDays: cfg.Herd.RetentionDays, Classes: cfg.Herd.Share.Classes,
		Nodes: []herd.EntryNode{{Key: node.PublicKey(), URL: *endpoint}},
	}
	for _, o := range others {
		k, u, ok := strings.Cut(o, "=")
		if !ok {
			return fail(fmt.Errorf("-node %q must be ed25519:<key>=https://host:port", o))
		}
		e.Nodes = append(e.Nodes, herd.EntryNode{Key: k, URL: u})
	}
	if *stmtURL != "" || *stmtSum != "" || *rscURL != "" {
		e.Identity = &herd.EntryIdentity{StatementURL: *stmtURL, StatementSHA256: *stmtSum, RSCURL: *rscURL}
	}
	now := time.Now()
	e.Issued, e.Expires = now, now.Add(*valid)
	doc, err := node.SignEntry(e)
	if err != nil {
		return fail(err)
	}
	if _, err := herd.CheckEntry(doc, now); err != nil {
		return fail(err)
	}
	fmt.Fprintf(stdout, "%s\n", doc)
	return 0
}

// runHubCheck is what the hub repository's CI runs on its entries
// directory: every entry passes herd.CheckEntry, sits in <asn>.json, and
// no ASN, key, or address is listed twice. -prune deletes the files whose
// entry has expired; -list writes the list document nodes fetch.
func runHubCheck(args []string, now time.Time, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("herd hub-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	prune := fs.Bool("prune", false, "delete the files of expired entries instead of failing on them")
	list := fs.String("list", "", "write the hub list document of the valid entries to this file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "packeteer: herd hub-check needs one directory")
		return 2
	}
	dir := fs.Arg(0)
	found, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return 1
	}
	slices.Sort(found)
	// Only regular *.json files are entries; dotfiles and directories are not.
	var names []string
	for _, name := range found {
		if fi, err := os.Stat(name); err == nil && fi.Mode().IsRegular() && !strings.HasPrefix(filepath.Base(name), ".") {
			names = append(names, name)
		}
	}
	var problems []string
	owner := map[string]string{}
	claim := func(what, name, file string) {
		if prev, dup := owner[what]; dup {
			problems = append(problems, fmt.Sprintf("%s: %s is also in %s", file, name, prev))
			return
		}
		owner[what] = file
	}
	type valid struct {
		asn uint32
		raw []byte
	}
	var ok []valid
	pruned := 0
	for _, name := range names {
		file := filepath.Base(name)
		raw, err := os.ReadFile(name)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		e, err := herd.CheckEntry(raw, now)
		switch {
		case errors.Is(err, herd.ErrExpired) && *prune:
			if err := os.Remove(name); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", file, err))
				continue
			}
			fmt.Fprintf(stdout, "pruned %s\n", file)
			pruned++
			continue
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: %v", file, err))
			continue
		case file != fmt.Sprintf("%d.json", e.ASN):
			problems = append(problems, fmt.Sprintf("%s: entry for asn %d must be named %d.json", file, e.ASN, e.ASN))
			continue
		}
		for _, n := range e.Nodes {
			claim("key "+n.Key, "a node key", file)
			claim("url "+n.URL, "a node url", file)
		}
		ok = append(ok, valid{e.ASN, raw})
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(stderr, p)
		}
		return 1
	}
	if *list != "" {
		slices.SortFunc(ok, func(a, b valid) int { return int(a.asn) - int(b.asn) })
		docs := make([][]byte, len(ok))
		for i, v := range ok {
			docs[i] = v.raw
		}
		b, err := herd.BuildHubList(docs, now)
		if err == nil {
			err = os.WriteFile(*list, append(b, '\n'), 0o644)
		}
		if err != nil {
			fmt.Fprintf(stderr, "packeteer: herd hub-check: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "%d entries ok, %d pruned\n", len(ok), pruned)
	return 0
}
