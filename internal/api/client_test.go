package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/Vebat/sealbox/client"
)

// The Go client is tested here, against the real handlers, so that it and
// the API cannot drift apart unnoticed.
func TestGoClient(t *testing.T) {
	ctx := context.Background()
	srv := newServer(t)
	c := client.New(srv.URL+"/", adminKey)

	id, err := c.Create(ctx, "customers", map[string]string{"email": "ivan@example.com", "passport": "4510 123456"})
	if err != nil {
		t.Fatal(err)
	}

	var masked map[string]string
	if err := c.Get(ctx, "customers", id, false, &masked); err != nil || masked["email"] != "i***@example.com" || masked["passport"] != "***" {
		t.Fatalf("masked get: %v, %v", masked, err)
	}
	var full map[string]string
	if err := c.Get(ctx, "customers", id, true, &full); err != nil || full["email"] != "ivan@example.com" {
		t.Fatalf("full get: %v, %v", full, err)
	}

	if ids, err := c.Search(ctx, "customers", "email", " IVAN@example.com"); err != nil || !slices.Equal(ids, []string{id}) {
		t.Fatalf("search: %v, %v", ids, err)
	}

	batch, err := c.CreateBatch(ctx, "customers", []any{
		map[string]string{"email": "a@example.com"},
		map[string]string{"email": "b@example.com"},
	})
	if err != nil || len(batch) != 2 {
		t.Fatalf("batch create: %v, %v", batch, err)
	}
	objects, missing, err := c.Reveal(ctx, "customers", append(batch, "tok_nope"), false)
	if err != nil || len(objects) != 2 || !slices.Equal(missing, []string{"tok_nope"}) {
		t.Fatalf("reveal: %v, %v, %v", objects, missing, err)
	}
	objects, _, err = c.Reveal(ctx, "customers", batch[:1], true)
	if err != nil || string(objects[batch[0]]) != `{"email":"a@example.com"}` {
		t.Fatalf("reveal full: %s, %v", objects[batch[0]], err)
	}
	// A 404 that is not the vault's own "object not found" is a routing
	// error, for example a wrong base URL, and must not look like a missing
	// object. A collection name with a slash is escaped and simply not found.
	var e *client.Error
	if err := client.New(srv.URL+"/nope", adminKey).Delete(ctx, "customers", batch[0]); !errors.As(err, &e) || e.Status != http.StatusNotFound || errors.Is(err, client.ErrNotFound) {
		t.Fatalf("wrong base URL: %v", err)
	}
	if err := c.Delete(ctx, "cust/omers", batch[0]); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("escaped collection: %v", err)
	}

	if err := c.Delete(ctx, "customers", id); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, "customers", id); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := c.Get(ctx, "customers", id, false, &masked); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}

	// Refusals come back as *client.Error with the status and the server's message.
	err = client.New(srv.URL, supportKey).Delete(ctx, "customers", batch[0])
	if !errors.As(err, &e) || e.Status != http.StatusForbidden || e.Message == "" {
		t.Fatalf("forbidden: %v", err)
	}
	_, err = c.Create(ctx, "customers", map[string]string{"email": "nope"})
	if !errors.As(err, &e) || e.Status != http.StatusBadRequest {
		t.Fatalf("invalid object: %v", err)
	}
}
