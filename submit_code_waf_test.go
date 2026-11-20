package main

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The diff `promptster done` sent on session a7bf0aa1 (2026-11-20). Render's
// WAF 403'd it plain, twice, and the candidate was told the assessment was
// NOT marked complete.
func blockedSubmission() submitCodePayload {
	return submitCodePayload{
		SessionID: "s1",
		Diff:      "+Reproduced with `python -m src.run_experiment --rank-ratio 0.7 1.0`.\n",
		BaseSha:   "abc",
		BundleKey: "org/s1/bundle.tar.gz",
	}
}

// submitEdge stands in for Render's edge in front of the API: a plain body
// holding the command gets the HTML block page; anything else reaches api.
func submitEdge(t *testing.T, requests *int32, api func(w http.ResponseWriter, got submitCodePayload)) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if r.Header.Get("Content-Encoding") != "gzip" && strings.Contains(string(raw), "python -m") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<!DOCTYPE html>\n<html><head><title>Blocked</title></head></html>"))
			return
		}
		var got submitCodePayload
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		api(w, got)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("PROMPTSTER_API_URL", srv.URL)
}

func TestSubmitCodeResendsWAFBlockedDiffGzipped(t *testing.T) {
	var requests int32
	var got submitCodePayload
	submitEdge(t, &requests, func(w http.ResponseWriter, p submitCodePayload) {
		got = p
		w.WriteHeader(http.StatusOK)
	})
	want := blockedSubmission()
	if err := apiSubmitCode("PST-k", want); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if got.Diff != want.Diff || got.SessionID != want.SessionID {
		t.Fatalf("server got %+v, want %+v", got, want)
	}
	if n := atomic.LoadInt32(&requests); n != 2 {
		t.Fatalf("requests = %d, want 2 (plain, then gzipped)", n)
	}
}

func TestSubmitCodeSendsUnblockedDiffOncePlain(t *testing.T) {
	var requests int32
	submitEdge(t, &requests, func(w http.ResponseWriter, _ submitCodePayload) { w.WriteHeader(http.StatusOK) })
	p := blockedSubmission()
	p.Diff = "+fixed the off-by-one\n"
	if err := apiSubmitCode("PST-k", p); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if n := atomic.LoadInt32(&requests); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
}

func TestSubmitCodeGzipResendStillSeesAssessmentClosed(t *testing.T) {
	var requests int32
	submitEdge(t, &requests, func(w http.ResponseWriter, _ submitCodePayload) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"Invalid key or session mismatch","code":"assessment_closed"}`))
	})
	if err := apiSubmitCode("PST-k", blockedSubmission()); !errors.Is(err, errAssessmentClosed) {
		t.Fatalf("err = %v, want errAssessmentClosed", err)
	}
}

func TestSubmitCodeErrorIsOneLineWithoutHTML(t *testing.T) {
	var requests int32
	// An edge that blocks gzip too: the candidate gets one plain line.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<!DOCTYPE html>\n<html><head><title>Blocked</title></head></html>"))
	}))
	defer srv.Close()
	t.Setenv("PROMPTSTER_API_URL", srv.URL)

	err := apiSubmitCode("PST-k", blockedSubmission())
	if err == nil || strings.ContainsAny(err.Error(), "<\n") {
		t.Fatalf("err = %q, want one plain line", err)
	}
	if n := atomic.LoadInt32(&requests); n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}

	// The API's own JSON errors stay whole, compacted to one line.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("{\n  \"error\": \"bundleSize: Expected number,\\n received string\"\n}"))
	}))
	defer srv2.Close()
	t.Setenv("PROMPTSTER_API_URL", srv2.URL)
	err = apiSubmitCode("PST-k", blockedSubmission())
	if err == nil || err.Error() != `HTTP 400: {"error":"bundleSize: Expected number,\n received string"}` {
		t.Fatalf("err = %q", err)
	}
}
