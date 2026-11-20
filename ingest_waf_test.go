package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The tool_intent a Claude Code Bash call made on 2026-11-20 (session
// 5c7884cb). Render's WAF 403'd it plain, so it never reached the timeline and
// grading said no tests were run.
func pytestToolIntent() Event {
	e := newEvent("tool_intent", "s1")
	e.Data = map[string]interface{}{
		"toolName":     "Bash",
		"inputPreview": `{"command":"(source .venv/bin/activate 2>/dev/null; python -m pytest -q 2>&1 | tail -30)"}`,
	}
	return e
}

// wafServer stands in for Render's edge in front of the API: plain bodies
// holding the test command get the HTML block page, gzipped ones pass through
// to an API that inflates them.
func wafServer(t *testing.T, got *Event, requests *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(requests, 1)
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Errorf("gzip reader: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			body = zr
		}
		raw, _ := io.ReadAll(body)
		if r.Header.Get("Content-Encoding") != "gzip" && strings.Contains(string(raw), "python -m pytest") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<!DOCTYPE html><title>Blocked</title>"))
			return
		}
		if err := json.Unmarshal(raw, got); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
}

func TestIngestSendsWAFBlockedEventGzipped(t *testing.T) {
	var got Event
	var requests int32
	srv := wafServer(t, &got, &requests)
	defer srv.Close()
	t.Setenv("PROMPTSTER_API_URL", srv.URL)

	want := pytestToolIntent()
	if err := ingestEventWithClient(&http.Client{Timeout: 3 * time.Second}, want, "PST-k"); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	gotData, _ := got.Data.(map[string]interface{})
	wantData, _ := want.Data.(map[string]interface{})
	if got.ID != want.ID || gotData["inputPreview"] != wantData["inputPreview"] {
		t.Fatalf("server got %+v, want %+v", got, want)
	}
	if n := atomic.LoadInt32(&requests); n != 2 {
		t.Fatalf("requests = %d, want 2 (plain, then gzipped)", n)
	}
}

func TestIngestSendsUnblockedEventOncePlain(t *testing.T) {
	var got Event
	var requests int32
	srv := wafServer(t, &got, &requests)
	defer srv.Close()
	t.Setenv("PROMPTSTER_API_URL", srv.URL)

	e := newEvent("tool_intent", "s1")
	e.Data = map[string]interface{}{"toolName": "Bash", "inputPreview": `{"command":"ls"}`}
	if err := ingestEventWithClient(&http.Client{Timeout: 3 * time.Second}, e, "PST-k"); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if n := atomic.LoadInt32(&requests); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
}

func TestIngestDoesNotRetryAnAPIForbidden(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"session_scope"}`))
	}))
	defer srv.Close()
	t.Setenv("PROMPTSTER_API_URL", srv.URL)

	err := ingestEventWithClient(&http.Client{Timeout: 3 * time.Second}, pytestToolIntent(), "PST-k")
	if err == nil || !ingestRejectedPermanently(err) {
		t.Fatalf("err = %v, want a permanent 403", err)
	}
	if n := atomic.LoadInt32(&requests); n != 1 {
		t.Fatalf("requests = %d, want 1 (the API's own 403 is not the edge)", n)
	}
}

func TestIngestGzipResendRejectedByOldBackend(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		if r.Header.Get("Content-Encoding") != "gzip" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// A backend that doesn't inflate: its JSON parser sees gzip bytes.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"Unexpected token"}`))
	}))
	defer srv.Close()
	t.Setenv("PROMPTSTER_API_URL", srv.URL)

	err := ingestEventWithClient(&http.Client{Timeout: 3 * time.Second}, pytestToolIntent(), "PST-k")
	if err == nil || !strings.Contains(err.Error(), "edge blocked the plain send (HTTP 403)") {
		t.Fatalf("err = %v, want it to name the edge block", err)
	}
	if !ingestRejectedPermanently(err) {
		t.Fatalf("err = %v, want the resend's 400 still reachable", err)
	}
	if n := atomic.LoadInt32(&requests); n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}
}
