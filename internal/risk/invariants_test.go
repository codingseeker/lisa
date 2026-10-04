package risk

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var forbiddenCalls = []string{
	"time.Now",
	"time.Since",
	"os.Getenv",
	"os.ReadFile",
	"os.Open",
	"os.Stat",
	"os.Lstat",
	"rand.Int",
	"rand.Intn",
	"rand.Float64",
	"rand.Shuffle",
	"rand.Read",
	"math/rand.Read",
}

var forbiddenImports = map[string]string{
	"os":        "scoring must not read the filesystem or the environment",
	"time":      "scoring must not read the clock",
	"math/rand": "scoring must not be random",
	"net":       "scoring must not reach the network",
	"os/exec":   "scoring must not run anything",
}

func TestScoringHasNoSourceOfNonDeterminism(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory failed: %v", err)
	}

	fileset := token.NewFileSet()
	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(".", name)
		parsed, err := parser.ParseFile(fileset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s failed: %v", path, err)
		}
		inspected++

		for _, spec := range parsed.Imports {
			imported := strings.Trim(spec.Path.Value, `"`)
			if reason, forbidden := forbiddenImports[imported]; forbidden {
				t.Errorf("%s imports %q: %s", name, imported, reason)
			}
		}

		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			packageName, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			invocation := packageName.Name + "." + selector.Sel.Name
			for _, forbidden := range forbiddenCalls {
				if invocation == forbidden {
					t.Errorf("%s calls %s, which would make a score depend on something "+
						"other than the finding", name, invocation)
				}
			}
			return true
		})
	}

	if inspected == 0 {
		t.Fatal("no non-test sources were inspected; the guard would pass vacuously")
	}
	t.Logf("inspected %d risk sources for non-deterministic inputs", inspected)
}

func TestScoringNeverConsultsCuratedContext(t *testing.T) {
	source, err := os.ReadFile("risk.go")
	if err != nil {
		t.Fatalf("reading risk.go failed: %v", err)
	}
	text := string(source)

	for _, forbidden := range []string{".Reference", "ReferenceContext", "gtfo"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("risk.go mentions %q; scoring must not read curated reference context", forbidden)
		}
	}
}
