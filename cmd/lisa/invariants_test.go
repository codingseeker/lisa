package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var forbiddenImports = map[string]string{
	"os/exec":  "the tool must never execute binaries, commands or payloads",
	"net":      "the tool must never open a network connection",
	"net/http": "the tool must never make an HTTP request",
	"net/rpc":  "no RPC surface is required",
	"plugin":   "loading code at runtime is an arbitrary code execution primitive",
	"unsafe":   "unsafe pointer arithmetic has no place in a metadata scanner",
}

var forbiddenCalls = []string{
	"syscall.Exec",
	"syscall.ForkExec",
	"syscall.StartProcess",
	"syscall.Forkpty",
	"unix.Exec",
	"exec.Command",
	"exec.CommandContext",
	"exec.LookPath",
}

func productionSources(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	var sources []string

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "testdata", "vendor", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		sources = append(sources, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s failed: %v", root, err)
	}
	if len(sources) == 0 {
		t.Fatalf("no production Go sources were found under %s; the guard would pass vacuously", root)
	}
	return sources
}

func TestProductionSourcesHaveNoExecutionOrNetworkPrimitives(t *testing.T) {
	sources := productionSources(t)
	fileset := token.NewFileSet()

	for _, path := range sources {
		parsed, err := parser.ParseFile(fileset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s failed: %v", path, err)
		}

		for _, spec := range parsed.Imports {
			name, convErr := strconv.Unquote(spec.Path.Value)
			if convErr != nil {
				continue
			}
			if reason, forbidden := forbiddenImports[name]; forbidden {
				t.Errorf("%s imports %q: %s", path, name, reason)
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
			pkg, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			invocation := pkg.Name + "." + selector.Sel.Name
			for _, forbidden := range forbiddenCalls {
				if invocation == forbidden {
					t.Errorf("%s calls %s; the tool must never execute other programs", path, invocation)
				}
			}
			return true
		})
	}
	t.Logf("inspected %d production Go sources for execution and network primitives", len(sources))
}

func TestCuratedDatasetIsSelfContainedAndVersionControlled(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "gtfo", "data", "gtfobins.tsv")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the curated dataset is missing at %s: %v", path, err)
	}
	text := string(content)

	for index, line := range strings.Split(text, "\n") {
		record := strings.TrimSpace(line)
		if record == "" || strings.HasPrefix(record, "#") {
			continue
		}
		for _, unwanted := range []string{"http://", "https://", "ftp://", "://"} {
			if strings.Contains(record, unwanted) {
				t.Errorf("dataset line %d references %q; records must be self contained", index+1, unwanted)
			}
		}
	}
	if !strings.Contains(text, "GTFOBins") {
		t.Error("the dataset does not document its provenance")
	}
	if !strings.Contains(text, "MIT") {
		t.Error("the dataset does not record the upstream licence")
	}
}

func TestCuratedATTACKDatasetIsSelfContainedAndAttributed(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "attack", "data", "techniques.tsv")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the curated ATT&CK dataset is missing at %s: %v", path, err)
	}
	text := string(content)

	if !strings.Contains(text, "MITRE") {
		t.Error("the ATT&CK dataset does not credit MITRE")
	}
	if !strings.Contains(text, "Apache License") {
		t.Error("the ATT&CK dataset does not record the upstream licence")
	}
	if !strings.Contains(text, "dataset_version:") {
		t.Error("the ATT&CK dataset does not record a dataset version")
	}
	if !strings.Contains(text, "not evidence") {
		t.Error("the ATT&CK dataset does not state that a mapping is not evidence of activity")
	}

	records := 0
	for index, line := range strings.Split(text, "\n") {
		record := strings.TrimSpace(line)
		if record == "" || strings.HasPrefix(record, "#") {
			continue
		}
		records++
		fields := strings.Split(record, "\t")
		if len(fields) != 6 {
			t.Errorf("ATT&CK dataset line %d has %d fields, want 6", index+1, len(fields))
			continue
		}
		if !strings.HasPrefix(fields[4], "https://attack.mitre.org/techniques/") {
			t.Errorf("ATT&CK dataset line %d cites %q; only framework documentation may be referenced",
				index+1, fields[4])
		}

		if strings.Contains(fields[5], "http") {
			t.Errorf("ATT&CK dataset line %d embeds a link in its relevance note", index+1)
		}
	}
	if records == 0 {
		t.Error("the ATT&CK dataset contains no records")
	}
	if records > 64 {
		t.Errorf("the ATT&CK dataset holds %d records; it should stay small and reviewable", records)
	}
}
