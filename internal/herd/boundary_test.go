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
// package are the daemon wiring and the ops API.
func TestOnlyTheDaemonAndTheOpsAPIImportHerd(t *testing.T) {
	allowed := map[string]bool{"cmd/controller": true, "internal/httpapi": true}
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
