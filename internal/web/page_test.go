package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	"vinpatel.org/site/internal/posture"
	"vinpatel.org/site/internal/resolve"
)

const (
	confirmedSentence = " that reached your inbox at a major provider such as Gmail, Outlook, iCloud or Yahoo was sent from this domain, because the domain tells receivers to reject anything else that uses its address."
	limitsSentence    = "That does not cover a lookalike domain, or a familiar display name on a different address."
	weakerSentence    = "Right now this domain does not tell receivers to reject every forged message, so this page makes no claim about mail from mail@"
	unconfirmed       = "This page could not confirm the domain's mail settings right now, so it makes no claim about mail from mail@"
	privacySentence   = "This server never logs your address, browser or referrer; what you see above is your own request, reflected."
)

// fullRow is the mail row for DNS that publishes exactly what d declares.
func fullRow(d posture.Declaration) string {
	return fmt.Sprintf("spf %s · dkim %s · dmarc p=%s · mta-sts %s · tls-rpt · dnssec", allTerm(d), d.DKIM.Selector, d.DMARC.P, d.MTASTS.Mode)
}

var edgeHeaders = http.Header{
	"Cf-Ray":       {"8c1f2a3b4d5e6f70-SJC"},
	"X-Edge-Proto": {"HTTP/3"},
	"X-Edge-Tls":   {"TLSv1.3"},
	"X-Edge-Asn":   {"13335"},
	"Cf-Ipcity":    {"San Jose"},
	"Cf-Ipcountry": {"US"},
}

var (
	timingLine  = regexp.MustCompile(`<p class="timing">server \d+\.\d\d ms(?: · p50 \d+\.\d\d ms · p99 \d+\.\d\d ms over [\d,]+ requests?)?</p>`)
	runtimeLine = regexp.MustCompile(`<p class="runtime">(?:mail dns [a-z0-9 ]+ · )?` + regexp.QuoteMeta(runtime.Version()) + ` · \d+ goroutines · \d+\.\d MB heap</p>`)
)

func TestIndexReflectsTheRequest(t *testing.T) {
	o := testOptions(t)
	rec := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", edgeHeaders)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<p class="domain">vinpatel.org</p>`,
		`<dt>served</dt><dd>SJC · ray 8c1f2a3b4d5e6f70-SJC</dd>`,
		`<dt>protocol</dt><dd>HTTP/3 · TLSv1.3</dd>`,
		`<dt>from</dt><dd>AS13335 · CLOUDFLARENET - Cloudflare, Inc., US · San Jose, US</dd>`,
		`<dt>build</dt><dd>abc1234 · <time datetime="2026-10-05T20:00:00Z">2026-10-05</time></dd>`,
		`<dt>mail</dt><dd>` + fullRow(*o.Declaration) + ` · cached 14m ago</dd>`,
		`<p class="verdict">A message from mail@vinpatel.org` + confirmedSentence + " " + limitsSentence + `</p>`,
		`<p class="note">` + privacySentence + `</p>`,
		`<a href="mailto:mail@vinpatel.org">mail@vinpatel.org</a>`,
		`<a href="https://github.com/vinpate" rel="me">github.com/vinpate</a>`,
		`<a href="https://www.linkedin.com/in/vin-pate" rel="me">linkedin.com/in/vin-pate</a>`,
		`<a href="https://bsky.app/profile/vinfa.bsky.social" rel="me">bsky.app/profile/vinfa.bsky.social</a>`,
		`<a href="https://www.instagram.com/vinfral7" rel="me">instagram.com/vinfral7</a>`,
		`<a href="https://nirvanalabs.io">`,
		`This server never logs your address, browser or referrer`,
		`what you see above is your own request, reflected.`,
		`<p class="runtime">mail dns cached 14m ago · `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if verdict, request := strings.Index(body, `<p class="verdict">`), strings.Index(body, `<h2 id="request">`); verdict < 0 || verdict > request {
		t.Errorf("verdict at %d, request section at %d; want the verdict first", verdict, request)
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
	for _, absent := range []string{"<dt>served</dt>", "<dt>protocol</dt>", "<dt>from</dt>", "ray 8c1f", "<time"} {
		if strings.Contains(body, absent) {
			t.Errorf("page should omit %s", absent)
		}
	}
	for _, want := range []string{
		"<dt>build</dt><dd>abc1234</dd>",
		"<dt>mail</dt><dd>" + fullRow(*o.Declaration) + " · cached 14m ago</dd>",
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
		`<p class="verdict">` + unconfirmed + "vinpatel.org.</p>",
		`<p class="note">` + privacySentence + `</p>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if n := strings.Count(body, "<dt>mail</dt>"); n != 1 {
		t.Errorf("page has %d mail rows, want only the contact row when nothing is confirmed:\n%s", n, body)
	}
	for _, claim := range []string{"mail dns", confirmedSentence, weakerSentence, "declared"} {
		if strings.Contains(body, claim) {
			t.Errorf("page says %q without an answer:\n%s", claim, body)
		}
	}
}

func TestFreshMailAnswerReadsAsJustNow(t *testing.T) {
	o := testOptions(t)
	d := *o.Declaration
	o = withMail(o, func(m *resolve.Mail) {
		*m = resolve.Mail{DMARC: d.DMARC.P, Observed: posture.Observation{DMARC: posture.Present, DMARCRecords: 1, DMARCP: d.DMARC.P}}
	})
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	if !strings.Contains(body, `<p class="runtime">mail dns fetched just now · `) {
		t.Errorf("page lacks a just-now mail dns note:\n%s", body)
	}
	want := "<dt>mail</dt><dd>spf unconfirmed · dkim unconfirmed · dmarc p=reject · mta-sts unconfirmed · tls-rpt unconfirmed · dnssec not authenticated by the resolver · fetched just now</dd>"
	if !strings.Contains(body, want) {
		t.Errorf("one answered check should still make a row, the rest unconfirmed; want %s in\n%s", want, body)
	}
	if !strings.Contains(body, `<p class="verdict">A message from mail@vinpatel.org`+confirmedSentence) {
		t.Errorf("DMARC alone decides the verdict:\n%s", body)
	}
}

func TestWeakerPolicyWithdrawsTheClaim(t *testing.T) {
	o := withMail(testOptions(t), func(m *resolve.Mail) { m.DMARC, m.Observed.DMARCP = "none", "none" })
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	for _, want := range []string{
		`<p class="verdict">` + weakerSentence + "vinpatel.org.</p>",
		" · dmarc p=none (declared reject) · ",
		`<p class="note">Where the mail row says “declared”, what was observed differs from what build <a href="https://github.com/vinpate/vinpatel-org/blob/abc1234/internal/posture/mail.json">abc1234</a> declares. ` + privacySentence + `</p>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if strings.Contains(body, confirmedSentence) || strings.Contains(body, limitsSentence) {
		t.Errorf("page vouches for mail under p=none:\n%s", body)
	}
}

func TestMissingDKIMKeyKeepsTheVerdict(t *testing.T) {
	o := withMail(testOptions(t), func(m *resolve.Mail) { m.DKIM, m.Observed.DKIM = "", posture.Absent })
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	for _, want := range []string{
		`<p class="verdict">A message from mail@vinpatel.org` + confirmedSentence,
		" · no dkim (declared " + o.Declaration.DKIM.Selector + ") · ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
}

func TestDeclarationRelaxedAheadOfDNS(t *testing.T) {
	o := testOptions(t)
	relaxed := *o.Declaration
	relaxed.DMARC.P = "none"
	o.Declaration = &relaxed
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	for _, want := range []string{
		`<p class="verdict">A message from mail@vinpatel.org` + confirmedSentence,
		" · dmarc p=reject (declared none) · ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
}

func TestUnauthenticatedAnswerIsTheResolversWord(t *testing.T) {
	o := withMail(testOptions(t), func(m *resolve.Mail) { m.DNSSEC, m.Observed.DNSSEC = false, false })
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	for _, want := range []string{
		" · dnssec not authenticated by the resolver · cached 14m ago</dd>",
		`<p class="verdict">A message from mail@vinpatel.org` + confirmedSentence,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
}

func TestDifferingNoteNamesTheBuild(t *testing.T) {
	cases := map[string]string{
		"dev":   "differs from what this local build declares. ",
		"local": "differs from what this local build declares. ",
		"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b": `differs from what build <a href="https://github.com/vinpate/vinpatel-org/blob/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b/internal/posture/mail.json">1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b</a> declares. `,
	}
	for version, want := range cases {
		t.Run(version, func(t *testing.T) {
			o := withMail(testOptions(t), func(m *resolve.Mail) { m.Observed.TLSRPTRUA = "mailto:tls@example.org" })
			o.Version = version
			body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
			if !strings.Contains(body, want) {
				t.Errorf("note lacks %s:\n%s", want, body)
			}
			if !strings.Contains(body, " · tls-rpt mailto:tls@example.org (declared "+o.Declaration.TLSRPT.RUA+") · ") {
				t.Errorf("row lacks the differing tls-rpt entry:\n%s", body)
			}
		})
	}
}

func TestLookupsDisabled(t *testing.T) {
	o := testOptions(t)
	o.Config.DoHURL = ""
	o.Lookup = fakeLookup{}
	h := newHandler(t, o)
	if body := serve(h, http.MethodGet, "vinpatel.org", "/", nil).Body.String(); !strings.Contains(body, unconfirmed+"vinpatel.org.") {
		t.Errorf("page lacks the could-not-confirm statement:\n%s", body)
	}
	var got traceDoc
	if err := json.Unmarshal(serve(h, http.MethodGet, "vinpatel.org", "/trace", nil).Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Mail.Lookups != "disabled" || got.Mail.Verdict != "unconfirmed" {
		t.Errorf("mail = lookups %q, verdict %q; want disabled, unconfirmed", got.Mail.Lookups, got.Mail.Verdict)
	}
	if c := got.Mail.Checks.DMARC; c.Declared != o.Declaration.DMARC.P || c.Match != nil || c.AgeS != nil || c.Observed.State != "unknown" || c.Observed.Records == nil {
		t.Errorf("dmarc check = %+v, want the declared intent, no match, no age and an empty list of records", c)
	}
}

func TestMTASTSAgeIsTheOlderFetch(t *testing.T) {
	for older, edit := range map[string]func(m *resolve.Mail){
		"policy": func(m *resolve.Mail) { m.Lookups.Policy.Age = 20 * time.Minute },
		"record": func(m *resolve.Mail) { m.Lookups.MTASTS.Age = 20 * time.Minute },
	} {
		t.Run(older, func(t *testing.T) {
			o := withMail(testOptions(t), edit)
			var got traceDoc
			if err := json.Unmarshal(serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/trace", nil).Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if age := got.Mail.Checks.MTASTS.AgeS; age == nil || *age != 1200 {
				t.Errorf("mta_sts age_s = %v, want 1200 from the older %s fetch", age, older)
			}
		})
	}
}

func TestDNSSECUnconfirmedWithOnlyTheDKIMAnswer(t *testing.T) {
	o := testOptions(t)
	selector := o.Declaration.DKIM.Selector
	o = withMail(o, func(m *resolve.Mail) {
		*m = resolve.Mail{DKIM: selector, Age: 14 * time.Minute, Observed: posture.Observation{DKIM: posture.Present}}
	})
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	for _, want := range []string{
		"<dt>mail</dt><dd>spf unconfirmed · dkim " + selector + " · dmarc unconfirmed · mta-sts unconfirmed · tls-rpt unconfirmed · dnssec unconfirmed · cached 14m ago</dd>",
		`<p class="verdict">` + unconfirmed + "vinpatel.org.</p>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s:\n%s", want, body)
		}
	}
}

// countingLookup records what the page asks the resolver.
type countingLookup struct {
	fakeLookup
	selectors *[]string
}

func (l countingLookup) Mail(ctx context.Context, domain, selector string) resolve.Mail {
	*l.selectors = append(*l.selectors, selector)
	return l.fakeLookup.Mail(ctx, domain, selector)
}

func TestSelectorOverrideIsAskedAndReadsAsDiffering(t *testing.T) {
	o := testOptions(t)
	o.Config.DKIMSelector = "other"
	l := o.Lookup.(fakeLookup)
	l.selector = "other"
	var asked []string
	o.Lookup = countingLookup{l, &asked}
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	if !reflect.DeepEqual(asked, []string{"other"}) {
		t.Errorf("selectors asked = %q, want one lookup with the configured selector", asked)
	}
	if want := " · dkim other (declared " + o.Declaration.DKIM.Selector + ") · "; !strings.Contains(body, want) {
		t.Errorf("page lacks %s:\n%s", want, body)
	}
}

func TestEmbeddedDeclarationIsTheDefault(t *testing.T) {
	o := testOptions(t)
	o.Declaration = nil
	var got traceDoc
	if err := json.Unmarshal(serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/trace", nil).Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	d, err := posture.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Mail.Checks.SPF.Declared != d.SPF || got.Mail.Checks.DMARC.Declared != d.DMARC.P {
		t.Errorf("declared spf %q, dmarc %q; want the embedded declaration's", got.Mail.Checks.SPF.Declared, got.Mail.Checks.DMARC.Declared)
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
		1:    "server 0.50 ms · p50 0.10 ms · p99 0.20 ms over 1 request",
		1204: "server 0.50 ms · p50 0.10 ms · p99 0.20 ms over 1,204 requests",
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

func TestMailRowEscapesDNSText(t *testing.T) {
	o := withMail(testOptions(t), func(m *resolve.Mail) { m.Observed.SPFRecord = "v=spf1 <script>alert(1)</script> ~all" })
	body := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	if strings.Contains(body, "<script>alert") {
		t.Fatalf("unescaped DNS text in page:\n%s", body)
	}
	if !strings.Contains(body, "<dd>spf v=spf1 &lt;script&gt;alert(1)&lt;/script&gt; ~all (declared ") {
		t.Errorf("differing spf record not shown escaped:\n%s", body)
	}
}

func TestTraceJSON(t *testing.T) {
	o := testOptions(t)
	d := *o.Declaration
	rec := serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/trace", edgeHeaders)
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
	l := fullMail(d).Lookups
	answered := func(a resolve.Answer) mailAnswer {
		return mailAnswer{State: "present", Name: a.Name, Records: a.Records, CNAMEs: a.CNAMEs, AD: a.AD}
	}
	matches, age := true, 840
	check := func(declared string, a mailAnswer) mailCheck {
		return mailCheck{Declared: declared, Observed: a, Match: &matches, AgeS: &age}
	}
	sts := answered(l.MTASTS)
	sts.Policy = l.Policy.Records[0]
	want := traceDoc{
		Served: &servedRow{Colo: "SJC", Ray: "8c1f2a3b4d5e6f70-SJC"},
		Proto:  &protoRow{HTTP: "HTTP/3", TLS: "TLSv1.3"},
		From:   &fromRow{ASN: 13335, ASOrg: "CLOUDFLARENET - Cloudflare, Inc., US", City: "San Jose", Country: "US"},
		Build:  buildRow{Version: "abc1234", Time: testBuild},
		Mail: mailRow{
			SPF: allTerm(d), DKIM: d.DKIM.Selector, DMARC: d.DMARC.P, MTASTS: d.MTASTS.Mode, TLSRPT: true, DNSSEC: true, AgeS: 840,
			Verdict:    "confirmed",
			DeclaredBy: "abc1234",
			Lookups:    "enabled",
			Checks: mailChecks{
				SPF:    check(d.SPF, answered(l.SPF)),
				DKIM:   check(d.DKIM.Selector, answered(l.DKIM)),
				DMARC:  check(d.DMARC.P, answered(l.DMARC)),
				MTASTS: check(fmt.Sprintf("%s max_age %d", d.MTASTS.Mode, d.MTASTS.MaxAge), sts),
				TLSRPT: check(d.TLSRPT.RUA, answered(l.TLSRPT)),
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		g, _ := json.MarshalIndent(got, "", "  ")
		w, _ := json.MarshalIndent(want, "", "  ")
		t.Errorf("trace =\n%s\nwant\n%s", g, w)
	}
}

func TestTraceShowsAFreshAnswerAsZeroSeconds(t *testing.T) {
	o := withMail(testOptions(t), func(m *resolve.Mail) {
		m.Age, m.Lookups.SPF.Age, m.Lookups.DMARC.Age = 0, 0, 0
	})
	var got map[string]any
	if err := json.Unmarshal(serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/trace", nil).Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	checks := got["mail"].(map[string]any)["checks"].(map[string]any)
	for _, name := range []string{"spf", "dmarc"} {
		if age, ok := checks[name].(map[string]any)["age_s"]; !ok || age != float64(0) {
			t.Errorf("%s age_s = %v (present %v), want 0", name, age, ok)
		}
	}
}

func TestTraceNamesWhatDiffers(t *testing.T) {
	o := withMail(testOptions(t), func(m *resolve.Mail) {
		m.DMARC, m.Observed.DMARCP, m.Lookups.DMARC.Records = "none", "none", []string{"v=DMARC1; p=none"}
		m.DKIM, m.Observed.DKIM, m.Lookups.DKIM.Records = "", posture.Absent, []string{"v=DKIM1; p="}
		m.TLSRPT, m.Observed.TLSRPT, m.Lookups.TLSRPT = false, posture.Unknown, resolve.Answer{Name: m.Lookups.TLSRPT.Name}
	})
	var got map[string]any
	if err := json.Unmarshal(serve(newHandler(t, o), http.MethodGet, "vinpatel.org", "/trace", nil).Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// at reads got by the public key names, so a renamed field fails here.
	at := func(path string) (any, bool) {
		var v any = got
		for _, k := range strings.Split(path, ".") {
			m, ok := v.(map[string]any)
			if !ok {
				return nil, false
			}
			if v, ok = m[k]; !ok {
				return nil, false
			}
		}
		return v, true
	}
	for path, want := range map[string]any{
		"mail.verdict":                       "weaker",
		"mail.declared_by":                   "abc1234",
		"mail.lookups":                       "enabled",
		"mail.checks.dmarc.declared":         o.Declaration.DMARC.P,
		"mail.checks.dmarc.observed.state":   "present",
		"mail.checks.dmarc.observed.records": []any{"v=DMARC1; p=none"},
		"mail.checks.dmarc.match":            false,
		"mail.checks.dkim.observed.state":    "absent",
		"mail.checks.dkim.observed.records":  []any{"v=DKIM1; p="},
		"mail.checks.dkim.match":             false,
		"mail.checks.dkim.age_s":             float64(840),
		"mail.checks.spf.match":              true,
		"mail.checks.spf.observed.ad":        true,
		"mail.checks.tls_rpt.observed.state": "unknown",
		"mail.checks.tls_rpt.match":          nil,
		"mail.checks.tls_rpt.age_s":          nil,
	} {
		if v, ok := at(path); !ok || !reflect.DeepEqual(v, want) {
			t.Errorf("%s = %#v (present %v), want %#v", path, v, ok, want)
		}
	}
	if p, _ := at("mail.checks.mta_sts.observed.policy"); p == "" || p == nil {
		t.Errorf("mail.checks.mta_sts.observed.policy = %#v, want the policy text", p)
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
