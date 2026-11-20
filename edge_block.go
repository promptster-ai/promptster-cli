package main

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strings"
)

// Render's edge WAF 403s some request bodies before they reach the API, with
// an HTML "Blocked" page. It doesn't read compressed bodies, so a client
// resends a blocked body gzipped to a route the API inflates. Plain goes first
// so a backend that doesn't inflate that route (self-hosted, or older) keeps
// working.

// edgeBlocked reports whether a response is the edge's block page rather than
// the API's own answer: the API answers in JSON.
func edgeBlocked(resp *http.Response) bool {
	return resp.StatusCode == http.StatusForbidden &&
		strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
}

func gzipBytes(body []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
