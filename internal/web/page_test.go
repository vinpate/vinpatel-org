package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

var edgeHeaders = http.Header{
	"Cf-Ray":       {"8c1f2a3b4d5e6f70-SJC"},
	"X-Edge-Proto": {"HTTP/3"},
	"X-Edge-Tls":   {"TLSv1.3"},
	"X-Edge-Asn":   {"13335"},
	"Cf-Ipcity":    {"San Jose"},
	"Cf-Ipcountry": {"US"},
}

type staticLookup struct{ dmarc, org string }

func (l staticLookup) DMARCPolicy(context.Context, string) (string, time.Duration) { return l.dmarc, 0 }
func (l staticLookup) ASOrg(context.Context, uint32) string                        { return l.org }

var originLine = regexp.MustCompile(`<p class="origin">origin \d+\.\d\d ms(?: · dmarc [a-z0-9 ]+)? · ` + regexp.QuoteMeta(runtime.Version()) + ` · \d+ goroutines · \d+\.\d MB heap</p>`)

func TestIndexReflectsTheRequest(t *testing.T) {
	rec := serve(newHandler(t, testOptions(t)), http.MethodGet, "vinpatel.org", "/", edgeHeaders)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<h1 class="domain">vinpatel.org</h1>`,
		`<dt>served</dt><dd>SJC · ray 8c1f2a3b4d5e6f70-SJC</dd>`,
		`<dt>proto</dt><dd>HTTP/3 · TLSv1.3</dd>`,
		`<dt>from</dt><dd>AS13335 · CLOUDFLARENET - Cloudflare, Inc., US · San Jose, US</dd>`,
		`<dt>build</dt><dd>abc1234 · <time datetime="2026-10-05T20:00:00Z">2026-10-05</time></dd>`,
		`<dt>mail</dt><dd>dmarc p=reject · mta-sts testing</dd>`,
		`<a href="mailto:mail@vinpatel.org">mail@vinpatel.org</a>`,
		`<a href="https://github.com/vinpate" rel="me">github.com/vinpate</a>`,
		`<a href="https://www.linkedin.com/in/vin-pate" rel="me">linkedin.com/in/vin-pate</a>`,
		`<a href="https://bsky.app/profile/vinfa.bsky.social" rel="me">bsky.app/profile/vinfa.bsky.social</a>`,
		`<a href="https://www.instagram.com/vinfral7" rel="me">instagram.com/vinfral7</a>`,
		`<a href="https://nirvanalabs.io">`,
		`it is your own request, reflected.`,
		` · dmarc cached 14m ago · `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if !originLine.MatchString(body) {
		t.Errorf("page lacks the origin line:\n%s", body)
	}
	h := rec.Header()
	if got := h.Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := h.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %s, body is %d bytes", got, len(body))
	}
	if got := h.Get("Server-Timing"); !strings.HasPrefix(got, "origin;dur=") {
		t.Errorf("Server-Timing = %q", got)
	}
}

func TestIndexWithoutEdgeHeaders(t *testing.T) {
	o := testOptions(t)
	o.BuildTime = time.Time{}
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	for _, absent := range []string{"<dt>served</dt>", "<dt>proto</dt>", "<dt>from</dt>", "ray 8c1f", "<time"} {
		if strings.Contains(body, absent) {
			t.Errorf("page should omit %s", absent)
		}
	}
	for _, want := range []string{
		"<dt>build</dt><dd>abc1234</dd>",
		"<dt>mail</dt><dd>dmarc p=reject · mta-sts testing</dd>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
}

func TestLookupMissesOmitParts(t *testing.T) {
	o := testOptions(t)
	o.Lookup = staticLookup{}
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", edgeHeaders).Body.String()
	for _, want := range []string{
		"<dt>from</dt><dd>AS13335 · San Jose, US</dd>",
		"<dt>mail</dt><dd>mta-sts testing</dd>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if strings.Contains(body, "dmarc cached") || strings.Contains(body, "dmarc fetched") {
		t.Errorf("origin line mentions dmarc without an answer:\n%s", body)
	}
}

func TestFreshDMARCAnswerReadsAsJustNow(t *testing.T) {
	o := testOptions(t)
	o.Lookup = staticLookup{dmarc: "reject"}
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	if !strings.Contains(body, " · dmarc fetched just now · ") {
		t.Errorf("page lacks a just-now dmarc note:\n%s", body)
	}
}

func TestIndexEscapesEdgeValues(t *testing.T) {
	o := testOptions(t)
	o.Lookup = staticLookup{org: `<img src=x onerror=alert(1)>`}
	h := http.Header{"Cf-Ipcity": {"<script>alert(1)</script>"}, "X-Edge-Asn": {"64500"}}
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", h).Body.String()
	if strings.Contains(body, "<script>") || strings.Contains(body, "<img") {
		t.Fatalf("unescaped markup in page:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("city not shown escaped")
	}
}

func TestTraceJSON(t *testing.T) {
	rec := serve(newHandler(t, testOptions(t)), http.MethodGet, "vinpatel.org", "/trace", edgeHeaders)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"ms":`)) {
		t.Errorf("trace lacks origin ms: %s", rec.Body)
	}
	var got traceDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body)
	}
	if !got.Build.Time.Equal(testBuild) {
		t.Errorf("build.time = %v, want %v", got.Build.Time, testBuild)
	}
	if got.Origin.Go != runtime.Version() || got.Origin.Goroutines < 1 || got.Origin.HeapBytes < 1 || got.Origin.MS < 0 {
		t.Errorf("origin = %+v", got.Origin)
	}
	got.Origin, got.Build.Time = originRow{}, testBuild
	want := traceDoc{
		Served: &servedRow{Colo: "SJC", Ray: "8c1f2a3b4d5e6f70-SJC"},
		Proto:  &protoRow{HTTP: "HTTP/3", TLS: "TLSv1.3"},
		From:   &fromRow{ASN: 13335, ASOrg: "CLOUDFLARENET - Cloudflare, Inc., US", City: "San Jose", Country: "US"},
		Build:  buildRow{Version: "abc1234", Time: testBuild},
		Mail:   mailRow{DMARC: "reject", DMARCAgeS: 840, MTASTS: "testing"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("trace = %+v\nwant %+v", got, want)
	}
}

func TestTraceJSONOmitsMissingRows(t *testing.T) {
	o := testOptions(t)
	o.BuildTime = time.Time{}
	rec := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/trace", nil)
	var got map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"served", "proto", "from"} {
		if _, ok := got[key]; ok {
			t.Errorf("trace has %q without edge headers", key)
		}
	}
	for _, key := range []string{"build", "mail", "origin"} {
		if _, ok := got[key]; !ok {
			t.Errorf("trace lacks %q", key)
		}
	}
	if strings.Contains(string(got["build"]), `"time"`) {
		t.Errorf("build has a time without a build time: %s", got["build"])
	}
}

func TestIndexHEAD(t *testing.T) {
	srv := httptest.NewServer(newHandler(t, testOptions(t)))
	defer srv.Close()
	req, err := http.NewRequest(http.MethodHead, srv.URL+"/", nil)
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
		t.Errorf("HEAD / = %d, %d body bytes, Content-Length %d; want 200, 0, >0", resp.StatusCode, len(body), resp.ContentLength)
	}
}

func TestPageStaysSmallAndSelfContained(t *testing.T) {
	h := newHandler(t, testOptions(t))
	page := serve(h, http.MethodGet, "vinpatel.org", "/", edgeHeaders).Body.String()
	css := serve(h, http.MethodGet, "vinpatel.org", "/style.css", nil).Body.String()
	icon := serve(h, http.MethodGet, "vinpatel.org", "/favicon.svg", nil).Body.String()
	if total := len(page) + len(css) + len(icon); total > 15*1024 {
		t.Errorf("page weight = %d bytes, budget is 15360", total)
	}
	if strings.Contains(page, "<script") || strings.Contains(page, " style=") {
		t.Error("page has script or inline style, which the CSP forbids")
	}
	for _, m := range regexp.MustCompile(`<link [^>]*href="([^"]+)"`).FindAllStringSubmatch(page, -1) {
		if !strings.HasPrefix(m[1], "/") && m[1] != "https://vinpatel.org/" {
			t.Errorf("page loads an external resource: %s", m[1])
		}
	}
	if strings.Contains(css, "url(") || strings.Contains(css, "@import") {
		t.Error("stylesheet fetches external resources")
	}
}
