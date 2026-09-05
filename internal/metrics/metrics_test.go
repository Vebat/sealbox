package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCounts(t *testing.T) {
	var reg Registry
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/things/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") == "missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(reg.Middleware(mux))
	defer srv.Close()

	for _, path := range []string{"/v1/things/a", "/v1/things/b", "/v1/things/missing", "/nowhere"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	for _, want := range []string{
		`sealbox_requests_total{route="GET /v1/things/{id}",status="200"} 2`,
		`sealbox_requests_total{route="GET /v1/things/{id}",status="404"} 1`,
		`sealbox_requests_total{route="other",status="404"} 1`,
		`sealbox_request_duration_seconds_count{route="GET /v1/things/{id}"} 3`,
		"# TYPE sealbox_requests_total counter",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %s in:\n%s", want, body)
		}
	}
	if strings.Contains(string(body), "things/a") {
		t.Error("metrics must carry the route pattern, not the path with its id")
	}
}
