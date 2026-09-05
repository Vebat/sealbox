// Package metrics counts requests per route and status and exposes them in
// the Prometheus text format. It is served on its own address, never on the
// API port: request counts say who is busy, which is more than the API
// should tell an unauthenticated caller.
package metrics

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Registry holds the counters. The zero value is ready to use.
type Registry struct {
	mu       sync.Mutex
	requests map[key]int64
	seconds  map[string]float64
	count    map[string]int64
}

type key struct {
	route  string
	status int
}

// Middleware counts every request that passes through it by the mux pattern
// it matched and the status it answered with.
func (g *Registry) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		route := r.Pattern
		if route == "" {
			route = "other"
		}
		g.mu.Lock()
		if g.requests == nil {
			g.requests, g.seconds, g.count = map[key]int64{}, map[string]float64{}, map[string]int64{}
		}
		g.requests[key{route, rec.status}]++
		g.seconds[route] += time.Since(start).Seconds()
		g.count[route]++
		g.mu.Unlock()
	})
}

// Handler renders the counters in the Prometheus text format.
func (g *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		g.mu.Lock()
		defer g.mu.Unlock()
		var b strings.Builder
		b.WriteString("# HELP sealbox_requests_total Requests by route and status.\n# TYPE sealbox_requests_total counter\n")
		keys := make([]key, 0, len(g.requests))
		for k := range g.requests {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].route < keys[j].route || keys[i].route == keys[j].route && keys[i].status < keys[j].status
		})
		for _, k := range keys {
			fmt.Fprintf(&b, "sealbox_requests_total{route=%q,status=\"%d\"} %d\n", k.route, k.status, g.requests[k])
		}
		b.WriteString("# HELP sealbox_request_duration_seconds Time spent answering, by route.\n# TYPE sealbox_request_duration_seconds summary\n")
		routes := make([]string, 0, len(g.count))
		for route := range g.count {
			routes = append(routes, route)
		}
		slices.Sort(routes)
		for _, route := range routes {
			fmt.Fprintf(&b, "sealbox_request_duration_seconds_sum{route=%q} %g\n", route, g.seconds[route])
			fmt.Fprintf(&b, "sealbox_request_duration_seconds_count{route=%q} %d\n", route, g.count[route])
		}
		w.Write([]byte(b.String()))
	})
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
