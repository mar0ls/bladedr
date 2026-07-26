package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func loadOpenAPI(t *testing.T) map[string]map[string]any {
	t.Helper()
	data, err := openAPIFS.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI string                    `yaml:"openapi"`
		Paths   map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Fatalf("OpenAPI version = %q", doc.OpenAPI)
	}
	return doc.Paths
}

// registeredRoutes reads the route table out of the source rather than a hand-kept list,
// by pulling the string literal out of every mux.HandleFunc("METHOD /path", …) in this
// package. A list maintained by hand is the thing that goes stale — it can only catch
// routes someone remembered to add to it, which are the ones least likely to be missing.
//
// /ui routes are excluded: those are server-rendered pages, not the machine contract.
// Everything else served — /api/v1, plus the operational endpoints scrapers rely on — is
// in scope.
func registeredRoutes(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	routes := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "HandleFunc" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			pattern, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			method, path, ok := strings.Cut(pattern, " ")
			if ok && !strings.HasPrefix(path, "/ui") {
				routes[method+" "+path] = true
			}
			return true
		})
	}
	if len(routes) == 0 {
		t.Fatal("found no routes in the source; the extractor is broken, not the spec")
	}
	return routes
}

// The spec is the published contract for /api/v1, and docs/stability.md tells clients it
// covers every route. That has to be enforced, not asserted: a route absent from the spec
// is undocumented surface, and a spec entry with no route is a promise nothing keeps.
func TestOpenAPICoversEveryRoute(t *testing.T) {
	spec := loadOpenAPI(t)
	specOps := map[string]bool{}
	for path, item := range spec {
		for method := range item {
			switch strings.ToLower(method) {
			case "get", "post", "put", "patch", "delete":
				specOps[strings.ToUpper(method)+" "+path] = true
			}
		}
	}

	var missing, extra []string
	routes := registeredRoutes(t)
	for op := range routes {
		if !specOps[op] {
			missing = append(missing, op)
		}
	}
	for op := range specOps {
		if !routes[op] {
			extra = append(extra, op)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("routes served but absent from openapi.yaml (%d):\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("openapi.yaml documents operations that no route serves (%d):\n  %s",
			len(extra), strings.Join(extra, "\n  "))
	}
	t.Logf("%d operations, spec and routes agree", len(routes))
}
