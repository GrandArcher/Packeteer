package herd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Herd data never enters a decision, a scorer, an announcer, or the RIB
// view (docs/design/herd.md, Hard rules 1 and 2). The only importers of this
// package are the daemon wiring, the ops API, and the lab key helper, the
// lab RPKI repository builder (it reads node key ids), and the hub stand-in.
func TestOnlyTheDaemonAndTheOpsAPIImportHerd(t *testing.T) {
	allowed := map[string]bool{"cmd/controller": true, "internal/httpapi": true, "lab/mkherdkeys": true, "lab/mkrpki": true, "lab/herdhub": true}
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		rel = filepath.ToSlash(rel)
		if rel == "internal/herd" || allowed[rel] {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			if strings.HasSuffix(imp.Path.Value, `/internal/herd"`) {
				t.Errorf("%s imports internal/herd: herd must stay out of decisions and announcing", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Herd itself reaches nothing that decides or announces (#686): of this
// module's packages it imports only the config, the probe results it
// records, the RIB view it reads, and the plugin interfaces of its store.
func TestHerdImportsNothingThatDecidesOrAnnounces(t *testing.T) {
	allowed := map[string]bool{
		`"github.com/GrandArcher/Packeteer/internal/config"`: true,
		`"github.com/GrandArcher/Packeteer/internal/probe"`:  true,
		`"github.com/GrandArcher/Packeteer/internal/rib"`:    true,
		`"github.com/GrandArcher/Packeteer/pkg/plugin"`:      true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if strings.HasPrefix(imp.Path.Value, `"github.com/GrandArcher/Packeteer/`) && !allowed[imp.Path.Value] {
				t.Errorf("%s imports %s: herd may only read config, probe results, the RIB view, and its store", path, imp.Path.Value)
			}
		}
	}
}
