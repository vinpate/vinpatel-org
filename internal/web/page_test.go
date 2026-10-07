package web

import (
	"bytes"
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

	"vinpatel.org/site/internal/resolve"
)

var edgeHeaders = http.Header{
	"Cf-Ray":       {"8c1f2a3b4d5e6f70-SJC"},
	"X-Edge-Proto": {"HTTP/3"},
	"X-Edge-Tls":   {"TLSv1.3"},
	"X-Edge-Asn":   {"13335"},
	"Cf-Ipcity":    {"San Jose"},
	"Cf-Ipcountry": {"US"},
}

var (
	timingLine  = regexp.MustCompile(`<p class="timing">origin \d+\.\d\d ms(?: · p50 \d+\.\d\d ms · p99 \d+\.\d\d ms over [\d,]+ requests?)?</p>`)
	runtimeLine = regexp.MustCompile(`<p class="runtime">(?:mail dns [a-z0-9 ]+ · )?` + regexp.QuoteMeta(runtime.Version()) + ` · \d+ goroutines · \d+\.\d MB heap</p>`)
)

func TestIndexReflectsTheRequest(t *testing.T) {
	rec := serve(newHandler(t, testOptions(t)), http.MethodGet, "vinpatel.org", "/", edgeHeaders)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<p class="domain">vinpatel.org</p>`,
		`<dt>served</dt><dd>SJC · ray 8c1f2a3b4d5e6f70-SJC</dd>`,
		`<dt>proto</dt><dd>HTTP/3 · TLSv1.3</dd>`,
		`<dt>from</dt><dd>AS13335 · CLOUDFLARENET - Cloudflare, Inc., US · San Jose, US</dd>`,
		`<dt>build</dt><dd>abc1234 · <time datetime="2026-10-05T20:00:00Z">2026-10-05</time></dd>`,
		`<dt>mail</dt><dd>spf ~all · dkim sig1 · dmarc p=reject · mta-sts testing · tls-rpt · dnssec</dd>`,
		`<a href="mailto:mail@vinpatel.org">mail@vinpatel.org</a>`,
		`<a href="https://github.com/vinpate" rel="me">github.com/vinpate</a>`,
		`<a href="https://www.linkedin.com/in/vin-pate" rel="me">linkedin.com/in/vin-pate</a>`,
		`<a href="https://bsky.app/profile/vinfa.bsky.social" rel="me">bsky.app/profile/vinfa.bsky.social</a>`,
		`<a href="https://www.instagram.com/vinfral7" rel="me">instagram.com/vinfral7</a>`,
		`<a href="https://nirvanalabs.io">`,
		`The origin never logs your address, browser or referrer`,
		`what you see above is your own request, reflected.`,
		`<p class="runtime">mail dns cached 14m ago · `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if !timingLine.MatchString(body) || !runtimeLine.MatchString(body) {
		t.Errorf("page lacks the footer lines:\n%s", body)
	}
	h := rec.Header()
	if got := h.Get("Cache-Control"); got != "private, no-store, no-transform" {
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
		"<dt>mail</dt><dd>spf ~all · dkim sig1 · dmarc p=reject · mta-sts testing · tls-rpt · dnssec</dd>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
}

func TestLookupMissesOmitParts(t *testing.T) {
	o := testOptions(t)
	o.Lookup = fakeLookup{}
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", edgeHeaders).Body.String()
	for _, want := range []string{
		"<dt>from</dt><dd>AS13335 · San Jose, US</dd>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if n := strings.Count(body, "<dt>mail</dt>"); n != 1 {
		t.Errorf("page has %d mail rows, want only the contact row when nothing is confirmed:\n%s", n, body)
	}
	if strings.Contains(body, "mail dns") {
		t.Errorf("runtime line mentions mail dns without an answer:\n%s", body)
	}
}

func TestFreshMailAnswerReadsAsJustNow(t *testing.T) {
	o := testOptions(t)
	o.Lookup = fakeLookup{mail: resolve.Mail{DMARC: "reject"}}
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	if !strings.Contains(body, `<p class="runtime">mail dns fetched just now · `) {
		t.Errorf("page lacks a just-now mail dns note:\n%s", body)
	}
	body = serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	if !strings.Contains(body, "<dt>mail</dt><dd>dmarc p=reject</dd>") {
		t.Errorf("one known part should still make a row:\n%s", body)
	}
}

func TestFooterOmitsPercentilesBeforeAnySample(t *testing.T) {
	h := newHandler(t, testOptions(t))
	first := serve(h, http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	if strings.Contains(first, "p50") || strings.Contains(first, "requests") {
		t.Errorf("first page shows percentiles with no samples:\n%s", first)
	}
	for range 3 {
		serve(h, http.MethodGet, "vinpatel.org", "/", nil)
	}
	later := serve(h, http.MethodGet, "vinpatel.org", "/trace", nil)
	var got traceDoc
	if err := json.Unmarshal(later.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Origin.Requests != 4 || got.Origin.P50MS <= 0 || got.Origin.P99MS < got.Origin.P50MS {
		t.Errorf("origin = %+v, want 4 requests and p99 >= p50 > 0", got.Origin)
	}
	page := serve(h, http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	if !strings.Contains(page, " over 5 requests</p>") {
		t.Errorf("page lacks the request count:\n%s", page)
	}
}

func TestOriginTimeFeedsThePercentiles(t *testing.T) {
	s := &site{lookup: fakeLookup{}}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	first := s.trace(r, time.Now().Add(-20*time.Millisecond)).Origin
	next := s.trace(r, time.Now()).Origin
	ms := func(f float64) time.Duration { return time.Duration(f * float64(time.Millisecond)) }
	within(t, "p50", ms(next.P50MS), ms(first.MS))
	within(t, "p99", ms(next.P99MS), ms(first.MS))
	if first.Requests != 0 || next.Requests != 1 {
		t.Errorf("requests = %d, then %d; want 0, then 1", first.Requests, next.Requests)
	}
}

func TestTimingLineCountsRequests(t *testing.T) {
	for requests, want := range map[uint64]string{
		1:    "origin 0.50 ms · p50 0.10 ms · p99 0.20 ms over 1 request",
		1204: "origin 0.50 ms · p50 0.10 ms · p99 0.20 ms over 1,204 requests",
	} {
		doc := traceDoc{Origin: originRow{MS: 0.5, P50MS: 0.1, P99MS: 0.2, Requests: requests}}
		if got := doc.TimingLine(); got != want {
			t.Errorf("TimingLine() with %d requests = %q, want %q", requests, got, want)
		}
	}
}

func TestCommas(t *testing.T) {
	for n, want := range map[uint64]string{0: "0", 999: "999", 1000: "1,000", 1204: "1,204", 1234567: "1,234,567"} {
		if got := commas(n); got != want {
			t.Errorf("commas(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestIndexEscapesEdgeValues(t *testing.T) {
	o := testOptions(t)
	o.Lookup = fakeLookup{org: `<img src=x onerror=alert(1)>`}
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
		Mail:   mailRow{SPF: "~all", DKIM: "sig1", DMARC: "reject", MTASTS: "testing", TLSRPT: true, DNSSEC: true, AgeS: 840},
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
	if n := strings.Count(page, "<script"); n != 1 || !strings.Contains(page, `<script type="application/ld+json">`) {
		t.Errorf("page has %d script elements; only the JSON-LD data block is allowed", n)
	}
	if strings.Contains(page, " style=") {
		t.Error("page has an inline style, which the CSP forbids")
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
