package api

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"
)

func TestOpenAPIMatchesRoutes(t *testing.T) {
	var spec struct {
		OpenAPI string `json:"openapi"`
		Paths   map[string]map[string]struct {
			OperationID string `json:"operationId"`
			Summary     string `json:"summary"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(OpenAPI, &spec); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(spec.OpenAPI, "3.") {
		t.Fatalf("openapi version %q", spec.OpenAPI)
	}

	documented := map[string]bool{}
	for path, ops := range spec.Paths {
		for method, op := range ops {
			if op.OperationID == "" || !strings.Contains(op.Summary, "Role:") {
				t.Errorf("%s %s: needs an operationId and a summary naming the role", method, path)
			}
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}
	registered := map[string]bool{}
	for pattern := range (&server{}).routes() {
		registered[pattern] = true
	}
	if !maps.Equal(documented, registered) {
		t.Fatalf("openapi.json and routes() disagree:\n documented %v\n registered %v", documented, registered)
	}
}
