// Package client is a small Go client for the sealbox HTTP API.
//
//	c := client.New("https://sealbox.internal:8080", os.Getenv("SEALBOX_KEY"))
//	id, err := c.Create(ctx, "customers", map[string]string{"email": "ivan@example.com"})
//	var masked map[string]string
//	err = c.Get(ctx, "customers", id, false, &masked)
//
// Other languages: generate a client from /openapi.json.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrNotFound is returned when an object does not exist or was deleted.
var ErrNotFound = errors.New("sealbox: object not found")

// Error is any other non-2xx answer from the server.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("sealbox: %d %s", e.Status, e.Message) }

// Client talks to one sealbox server with one API key.
type Client struct {
	base string
	key  string
	HTTP *http.Client // defaults to http.DefaultClient; replace to set timeouts or TLS
}

// New returns a client for baseURL, for example "https://sealbox.internal:8080".
func New(baseURL, apiKey string) *Client {
	return &Client{base: strings.TrimRight(baseURL, "/"), key: apiKey, HTTP: http.DefaultClient}
}

// Create stores one object and returns its id. Role: write.
func (c *Client) Create(ctx context.Context, collection string, object any) (string, error) {
	var res struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, "POST", collectionPath(collection)+"/objects", object, &res)
	return res.ID, err
}

// CreateBatch stores up to 1000 objects in one transaction and returns their
// ids in order. One invalid object fails the whole batch. Role: write.
func (c *Client) CreateBatch(ctx context.Context, collection string, objects []any) ([]string, error) {
	var res struct {
		IDs []string `json:"ids"`
	}
	err := c.do(ctx, "POST", collectionPath(collection)+"/objects/batch", map[string]any{"objects": objects}, &res)
	return res.IDs, err
}

// Get decodes one object into out: masked values, or the plaintext when
// full is true. Role: read_masked or read_full.
func (c *Client) Get(ctx context.Context, collection, id string, full bool, out any) error {
	path := collectionPath(collection) + "/objects/" + url.PathEscape(id)
	if full {
		path += "?reveal=full"
	}
	return c.do(ctx, "GET", path, nil, out)
}

// Reveal reads up to 1000 objects in one call, keyed by id. Ids that are
// unknown or deleted come back in missing. Role: read_masked or read_full.
func (c *Client) Reveal(ctx context.Context, collection string, ids []string, full bool) (objects map[string]json.RawMessage, missing []string, err error) {
	reveal := "masked"
	if full {
		reveal = "full"
	}
	var res struct {
		Objects map[string]json.RawMessage `json:"objects"`
		Missing []string                   `json:"missing"`
	}
	err = c.do(ctx, "POST", collectionPath(collection)+"/objects/reveal", map[string]any{"ids": ids, "reveal": reveal}, &res)
	return res.Objects, res.Missing, err
}

// Delete crypto-shreds one object. Role: delete.
func (c *Client) Delete(ctx context.Context, collection, id string) error {
	return c.do(ctx, "DELETE", collectionPath(collection)+"/objects/"+url.PathEscape(id), nil, nil)
}

// Search returns the ids of objects whose indexed field equals value after
// normalization, at most 100. Role: search.
func (c *Client) Search(ctx context.Context, collection, field, value string) ([]string, error) {
	var res struct {
		IDs []string `json:"ids"`
	}
	err := c.do(ctx, "POST", collectionPath(collection)+"/search", map[string]string{field: value}, &res)
	return res.IDs, err
}

func collectionPath(collection string) string { return "/v1/collections/" + url.PathEscape(collection) }

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		// Only the vault's own "object not found" is ErrNotFound. A 404 with
		// any other body is a wrong base URL or path and stays an *Error.
		if resp.StatusCode == http.StatusNotFound && e.Error == "object not found" {
			return ErrNotFound
		}
		return &Error{Status: resp.StatusCode, Message: e.Error}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
