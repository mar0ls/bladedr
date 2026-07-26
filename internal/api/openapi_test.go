package api

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenAPISpecParsesAndCoversCoreRoutes(t *testing.T) {
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
	for _, path := range []string{
		"/api/v1/hosts", "/api/v1/hosts/{id}/scans", "/api/v1/scan-jobs/{id}",
		"/api/v1/observations", "/api/v1/export-targets", "/api/v1/retention/run",
		"/api/v1/responses", "/api/v1/responses/{id}/approve",
		"/api/v1/responses/{id}/reject",
	} {
		if doc.Paths[path] == nil {
			t.Errorf("OpenAPI is missing %s", path)
		}
	}
}
