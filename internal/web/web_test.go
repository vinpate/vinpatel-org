package web

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vinpatel.org/site/internal/config"
)

var testBuild = time.Date(2026, 10, 5, 20, 0, 0, 0, time.UTC)

// fakeLookup answers only for the inputs a correct handler asks about.
type fakeLookup struct{}

func (fakeLookup) DMARCPolicy(_ context.Context, domain string) string {
	if domain == "vinpatel.org" {
		return "reject"
	}
	return ""
}

func (fakeLookup) ASOrg(_ context.Context, asn uint32) string {
	if asn == 13335 {
		return "CLOUDFLARENET - Cloudflare, Inc., US"
	}
	return ""
}

func testOptions(t *testing.T) Options {
	t.Helper()
	cfg, err := config.Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return Options{
		Config:    cfg,
		Version:   "abc1234",
		BuildTime: testBuild,
		Lookup:    fakeLookup{},
		Logger:    slog.New(slog.DiscardHandler),
	}
}

func newHandler(t *testing.T, o Options) http.Handler {
	t.Helper()
	h, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

// serve sends one request through h. Header keys must be in canonical form.
func serve(h http.Handler, method, host, target string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = host
	for k, vs := range header {
		req.Header[k] = vs
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNewRequiresDependencies(t *testing.T) {
	o := testOptions(t)
	o.Lookup = nil
	if _, err := New(o); err == nil {
		t.Error("New without Lookup succeeded")
	}
	o = testOptions(t)
	o.Logger = nil
	if _, err := New(o); err == nil {
		t.Error("New without Logger succeeded")
	}
}

func TestRoutes(t *testing.T) {
	h := newHandler(t, testOptions(t))
	cases := []struct {
		name, host, target string
		status             int
		contentType        string
		body               string
		location           string
	}{
		{"healthz on apex", "vinpatel.org", "/healthz", 200, "text/plain; charset=utf-8", "ok\n", ""},
		{"healthz on loopback", "127.0.0.1:8080", "/healthz", 200, "text/plain; charset=utf-8", "ok\n", ""},
		{"robots", "vinpatel.org", "/robots.txt", 200, "text/plain; charset=utf-8", "User-agent: *\nAllow: /\n", ""},
		{"security.txt", "vinpatel.org", "/.well-known/security.txt", 200, "text/plain; charset=utf-8", "Contact: mailto:mail@vinpatel.org\n", ""},
		{"favicon.ico", "vinpatel.org", "/favicon.ico", 204, "", "", ""},
		{"stylesheet", "vinpatel.org", "/style.css", 200, "text/css; charset=utf-8", "--paper", ""},
		{"icon", "vinpatel.org", "/favicon.svg", 200, "image/svg+xml", "<svg", ""},
		{"apex with port", "vinpatel.org:8080", "/robots.txt", 200, "text/plain; charset=utf-8", "Allow: /", ""},
		{"apex uppercase", "VINPATEL.ORG", "/robots.txt", 200, "text/plain; charset=utf-8", "Allow: /", ""},
		{"apex trailing dot", "vinpatel.org.", "/robots.txt", 200, "text/plain; charset=utf-8", "Allow: /", ""},
		{"unknown apex path", "vinpatel.org", "/wp-login.php", 404, "text/html; charset=utf-8", `<link rel="stylesheet" href="/style.css">`, ""},
		{"mta-sts policy", "mta-sts.vinpatel.org", "/.well-known/mta-sts.txt", 200, "text/plain; charset=utf-8", "version: STSv1\r\n", ""},
		{"mta-sts elsewhere", "mta-sts.vinpatel.org", "/", 404, "text/plain; charset=utf-8", "not found\n", ""},
		{"policy only on mta-sts host", "vinpatel.org", "/.well-known/mta-sts.txt", 404, "text/html; charset=utf-8", "", ""},
		{"www to apex", "www.vinpatel.org", "/some/path?x=1", 308, "", "", "https://vinpatel.org/some/path?x=1"},
		{"unknown host to apex", "evil.example", "/", 308, "", "", "https://vinpatel.org/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(h, http.MethodGet, tc.host, tc.target, nil)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if tc.contentType != "" && rec.Header().Get("Content-Type") != tc.contentType {
				t.Errorf("Content-Type = %q, want %q", rec.Header().Get("Content-Type"), tc.contentType)
			}
			if !strings.Contains(rec.Body.String(), tc.body) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tc.body)
			}
			if tc.location != "" && rec.Header().Get("Location") != tc.location {
				t.Errorf("Location = %q, want %q", rec.Header().Get("Location"), tc.location)
			}
		})
	}
}

func TestSecurityTXT(t *testing.T) {
	rec := serve(newHandler(t, testOptions(t)), http.MethodGet, "vinpatel.org", "/.well-known/security.txt", nil)
	want := "Contact: mailto:mail@vinpatel.org\n" +
		"Expires: 2027-10-04T20:00:00Z\n" +
		"Preferred-Languages: en\n" +
		"Canonical: https://vinpatel.org/.well-known/security.txt\n"
	if rec.Body.String() != want {
		t.Errorf("security.txt =\n%s\nwant\n%s", rec.Body.String(), want)
	}
}

func TestMTASTSPolicyFollowsConfig(t *testing.T) {
	o := testOptions(t)
	rec := serve(newHandler(t, o), http.MethodGet, "mta-sts.vinpatel.org", "/.well-known/mta-sts.txt", nil)
	want := "version: STSv1\r\nmode: testing\r\nmx: mx01.mail.icloud.com\r\nmx: mx02.mail.icloud.com\r\nmax_age: 604800\r\n"
	if rec.Body.String() != want {
		t.Errorf("default policy = %q, want %q", rec.Body.String(), want)
	}

	o.Config.MTASTSMode = "enforce"
	o.Config.MTASTSMX = []string{"*.mx.example.net"}
	o.Config.MTASTSMaxAge = 86400
	rec = serve(newHandler(t, o), http.MethodGet, "mta-sts.vinpatel.org", "/.well-known/mta-sts.txt", nil)
	want = "version: STSv1\r\nmode: enforce\r\nmx: *.mx.example.net\r\nmax_age: 86400\r\n"
	if rec.Body.String() != want {
		t.Errorf("enforce policy = %q, want %q", rec.Body.String(), want)
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	want := map[string]string{
		"Strict-Transport-Security":    "max-age=63072000; includeSubDomains",
		"Content-Security-Policy":      "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	h := newHandler(t, testOptions(t))
	requests := []struct{ method, host, target string }{
		{http.MethodGet, "vinpatel.org", "/"},
		{http.MethodGet, "vinpatel.org", "/style.css"},
		{http.MethodGet, "vinpatel.org", "/missing"},
		{http.MethodGet, "mta-sts.vinpatel.org", "/.well-known/mta-sts.txt"},
		{http.MethodGet, "www.vinpatel.org", "/"},
		{http.MethodPost, "vinpatel.org", "/"},
		{http.MethodGet, "127.0.0.1:8080", "/healthz"},
	}
	for _, rq := range requests {
		rec := serve(h, rq.method, rq.host, rq.target, nil)
		for name, value := range want {
			if got := rec.Header().Get(name); got != value {
				t.Errorf("%s %s%s: %s = %q, want %q", rq.method, rq.host, rq.target, name, got, value)
			}
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := newHandler(t, testOptions(t))
	for _, tc := range []struct{ method, host string }{
		{http.MethodPost, "vinpatel.org"},
		{http.MethodPut, "mta-sts.vinpatel.org"},
		{http.MethodDelete, "evil.example"},
		{http.MethodOptions, "vinpatel.org"},
	} {
		rec := serve(h, tc.method, tc.host, "/", nil)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s %s = %d, Allow %q; want 405, \"GET, HEAD\"", tc.method, tc.host, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

func TestHEADSendsHeadersOnly(t *testing.T) {
	srv := httptest.NewServer(newHandler(t, testOptions(t)))
	defer srv.Close()
	for _, path := range []string{"/robots.txt", "/style.css", "/.well-known/security.txt"} {
		req, err := http.NewRequest(http.MethodHead, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "vinpatel.org"
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(body) != 0 || resp.ContentLength <= 0 {
			t.Errorf("HEAD %s = %d, %d body bytes, Content-Length %d; want 200, 0, >0", path, resp.StatusCode, len(body), resp.ContentLength)
		}
		if server := resp.Header.Get("Server"); server != "" {
			t.Errorf("HEAD %s sent Server: %q", path, server)
		}
	}
}

func TestStaticAssetsRevalidate(t *testing.T) {
	h := newHandler(t, testOptions(t))
	rec := serve(h, http.MethodGet, "vinpatel.org", "/style.css", nil)
	etag := rec.Header().Get("ETag")
	if etag == "" || rec.Header().Get("Cache-Control") != "public, max-age=86400" {
		t.Fatalf("ETag %q, Cache-Control %q", etag, rec.Header().Get("Cache-Control"))
	}
	rec = serve(h, http.MethodGet, "vinpatel.org", "/style.css", http.Header{"If-None-Match": {etag}})
	if rec.Code != http.StatusNotModified {
		t.Errorf("conditional GET = %d, want 304", rec.Code)
	}
}

func TestStripIPHeaders(t *testing.T) {
	var seen http.Header
	h := stripIPHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, name := range []string{"CF-Connecting-IP", "CF-Connecting-IPv6", "CF-Pseudo-IPv4", "True-Client-IP", "X-Forwarded-For", "X-Real-IP", "Forwarded"} {
		req.Header.Set(name, "203.0.113.7")
	}
	req.Header.Set("CF-Ray", "8c1f2a3b4d5e6f70-SJC")
	h.ServeHTTP(httptest.NewRecorder(), req)
	for name, values := range seen {
		for _, v := range values {
			if strings.Contains(v, "203.0.113.7") {
				t.Errorf("handler saw %s: %s", name, v)
			}
		}
	}
	if seen.Get("CF-Ray") == "" {
		t.Error("CF-Ray was stripped too")
	}
}

func TestLogsCarryNoVisitorData(t *testing.T) {
	for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
		t.Run(level.String(), func(t *testing.T) {
			var buf bytes.Buffer
			o := testOptions(t)
			o.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level}))
			serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/robots.txt", http.Header{
				"X-Forwarded-For":  {"203.0.113.7"},
				"Cf-Connecting-Ip": {"203.0.113.7"},
				"User-Agent":       {"secret-agent/1.0"},
				"Referer":          {"https://referrer.example/"},
				"Cf-Ray":           {"8c1f2a3b4d5e6f70-SJC"},
			})
			out := buf.String()
			for _, leak := range []string{"203.0.113.7", "secret-agent", "referrer.example"} {
				if strings.Contains(out, leak) {
					t.Errorf("log contains %q:\n%s", leak, out)
				}
			}
			for _, want := range []string{`"path":"/robots.txt"`, `"status":200`, `"ray":"8c1f2a3b4d5e6f70-SJC"`, `"duration_ms":`} {
				if !strings.Contains(out, want) {
					t.Errorf("log lacks %s:\n%s", want, out)
				}
			}
			if level == slog.LevelDebug && !strings.Contains(out, `"Cf-Connecting-Ip"`) {
				t.Errorf("debug log should list header names:\n%s", out)
			}
		})
	}
}

func TestHealthChecksAreNotLogged(t *testing.T) {
	var buf bytes.Buffer
	o := testOptions(t)
	o.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	serve(newHandler(t, o), http.MethodGet, "127.0.0.1:8080", "/healthz", nil)
	if buf.Len() != 0 {
		t.Errorf("healthcheck was logged: %s", buf.String())
	}
}
