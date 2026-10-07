package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"vinpatel.org/site/internal/edge"
	"vinpatel.org/site/internal/resolve"
)

// traceDoc is the request trace in the shape /trace returns. Rows with no
// inputs are nil and drop out of both the JSON and the page.
type traceDoc struct {
	Served *servedRow `json:"served,omitempty"`
	Proto  *protoRow  `json:"proto,omitempty"`
	From   *fromRow   `json:"from,omitempty"`
	Build  buildRow   `json:"build"`
	Mail   mailRow    `json:"mail"`
	Origin originRow  `json:"origin"`
}

type servedRow struct {
	Colo string `json:"colo,omitempty"`
	Ray  string `json:"ray,omitempty"`
}

type protoRow struct {
	HTTP string `json:"http,omitempty"`
	TLS  string `json:"tls,omitempty"`
}

type fromRow struct {
	ASN     uint32 `json:"asn,omitempty"`
	ASOrg   string `json:"as_org,omitempty"`
	City    string `json:"city,omitempty"`
	Country string `json:"country,omitempty"`
}

type buildRow struct {
	Version string    `json:"version"`
	Time    time.Time `json:"time,omitzero"`
}

// mailRow is the mail posture a sending server would find. Empty and false
// mean unconfirmed; AgeS is the age of the oldest answer behind it.
type mailRow struct {
	SPF    string `json:"spf,omitempty"`
	DKIM   string `json:"dkim,omitempty"`
	DMARC  string `json:"dmarc,omitempty"`
	MTASTS string `json:"mta_sts,omitempty"`
	TLSRPT bool   `json:"tls_rpt"`
	DNSSEC bool   `json:"dnssec"`
	AgeS   int    `json:"age_s,omitempty"`
}

func (m mailRow) known() bool {
	return m.SPF != "" || m.DKIM != "" || m.DMARC != "" || m.MTASTS != "" || m.TLSRPT || m.DNSSEC
}

func (m mailRow) String() string {
	return join(
		prefix("spf ", m.SPF),
		prefix("dkim ", m.DKIM),
		prefix("dmarc p=", m.DMARC),
		prefix("mta-sts ", m.MTASTS),
		flag("tls-rpt", m.TLSRPT),
		flag("dnssec", m.DNSSEC),
	)
}

// originRow describes the process that answered: how long it spent on
// parsing and lookups for this request, the p50 and p99 of that time over
// every page and trace since it started, and what it is running on.
type originRow struct {
	MS         float64 `json:"ms"`
	P50MS      float64 `json:"p50_ms,omitempty"`
	P99MS      float64 `json:"p99_ms,omitempty"`
	Requests   uint64  `json:"requests"`
	Go         string  `json:"go"`
	Goroutines int     `json:"goroutines"`
	HeapBytes  uint64  `json:"heap_bytes"`
}

type row struct {
	Key   string
	Value string
	Time  time.Time
}

type page struct {
	Site    string
	Profile profile
	Head    head
	Trace   traceDoc
}

func (s *site) index(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, err := s.execute("index.html", page{Site: s.cfg.SiteHost, Profile: vin, Head: s.head, Trace: s.trace(r, start)})
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Server-Timing", serverTiming(time.Since(start)))
	writeBody(w, http.StatusOK, "text/html; charset=utf-8", "private, no-store, no-transform", body)
}

func (s *site) traceJSON(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, err := json.MarshalIndent(s.trace(r, start), "", "  ")
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Server-Timing", serverTiming(time.Since(start)))
	writeBody(w, http.StatusOK, "application/json", "no-store", append(body, '\n'))
}

// trace gathers what the edge and DNS say about this request. Origin.MS
// and the percentiles both cover parsing and lookups, and this request
// joins the histogram only after it is read, so no response counts
// itself. Server-Timing on the response adds rendering.
func (s *site) trace(r *http.Request, start time.Time) traceDoc {
	t := edge.Parse(r.Header)
	var org string
	var mail resolve.Mail
	var wg sync.WaitGroup
	wg.Go(func() { org = s.lookup.ASOrg(r.Context(), t.ASN) })
	wg.Go(func() { mail = s.lookup.Mail(r.Context(), s.cfg.SiteHost, s.cfg.DKIMSelector) })
	wg.Wait()

	doc := traceDoc{
		Build: buildRow{Version: s.version, Time: s.built},
		Mail: mailRow{
			SPF: mail.SPF, DKIM: mail.DKIM, DMARC: mail.DMARC, MTASTS: mail.MTASTS,
			TLSRPT: mail.TLSRPT, DNSSEC: mail.DNSSEC, AgeS: int(mail.Age.Seconds()),
		},
	}
	if t.Colo != "" || t.Ray != "" {
		doc.Served = &servedRow{Colo: t.Colo, Ray: t.Ray}
	}
	if t.HTTP != "" || t.TLS != "" {
		doc.Proto = &protoRow{HTTP: t.HTTP, TLS: t.TLS}
	}
	if t.ASN != 0 || t.City != "" || t.Country != "" {
		doc.From = &fromRow{ASN: t.ASN, ASOrg: org, City: t.City, Country: t.Country}
	}
	d := time.Since(start)
	snap := s.latency.snapshot()
	doc.Origin = originRow{
		MS:         millis(d),
		P50MS:      millis(snap.quantile(0.5)),
		P99MS:      millis(snap.quantile(0.99)),
		Requests:   snap.total,
		Go:         runtime.Version(),
		Goroutines: runtime.NumGoroutine(),
		HeapBytes:  heapBytes(),
	}
	s.latency.observe(d)
	return doc
}

func heapBytes() uint64 {
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return sample[0].Value.Uint64()
}

// Rows lays the trace out as the page's "this request" list.
func (d traceDoc) Rows() []row {
	var rows []row
	if d.Served != nil {
		rows = append(rows, row{Key: "served", Value: join(d.Served.Colo, prefix("ray ", d.Served.Ray))})
	}
	if d.Proto != nil {
		rows = append(rows, row{Key: "proto", Value: join(d.Proto.HTTP, d.Proto.TLS)})
	}
	if d.From != nil {
		var asn string
		if d.From.ASN != 0 {
			asn = fmt.Sprintf("AS%d", d.From.ASN)
		}
		place := strings.Join(nonEmpty(d.From.City, d.From.Country), ", ")
		rows = append(rows, row{Key: "from", Value: join(asn, d.From.ASOrg, place)})
	}
	rows = append(rows, row{Key: "build", Value: d.Build.Version, Time: d.Build.Time})
	if d.Mail.known() {
		rows = append(rows, row{Key: "mail", Value: d.Mail.String()})
	}
	return rows
}

// TimingLine is the footer's first line: this response, then every page
// and trace since the process started.
func (d traceDoc) TimingLine() string {
	var since string
	if d.Origin.Requests > 0 {
		noun := "requests"
		if d.Origin.Requests == 1 {
			noun = "request"
		}
		since = fmt.Sprintf("p50 %.2f ms · p99 %.2f ms over %s %s", d.Origin.P50MS, d.Origin.P99MS, commas(d.Origin.Requests), noun)
	}
	return join(fmt.Sprintf("origin %.2f ms", d.Origin.MS), since)
}

// RuntimeLine is the footer's second line: how fresh the DNS knowledge is
// and what the process runs on.
func (d traceDoc) RuntimeLine() string {
	var dns string
	if d.Mail.known() {
		dns = "mail dns " + cachedAgo(time.Duration(d.Mail.AgeS)*time.Second)
	}
	return join(
		dns,
		d.Origin.Go,
		fmt.Sprintf("%d goroutines", d.Origin.Goroutines),
		fmt.Sprintf("%.1f MB heap", float64(d.Origin.HeapBytes)/1e6),
	)
}

func commas(n uint64) string {
	s := strconv.FormatUint(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func cachedAgo(age time.Duration) string {
	switch {
	case age < time.Second:
		return "fetched just now"
	case age < time.Minute:
		return fmt.Sprintf("cached %ds ago", int(age.Seconds()))
	case age < time.Hour:
		return fmt.Sprintf("cached %dm ago", int(age.Minutes()))
	default:
		return fmt.Sprintf("cached %dh ago", int(age.Hours()))
	}
}

func join(parts ...string) string { return strings.Join(nonEmpty(parts...), " · ") }

func nonEmpty(parts ...string) []string {
	return slices.DeleteFunc(parts, func(p string) bool { return p == "" })
}

func prefix(p, v string) string {
	if v == "" {
		return ""
	}
	return p + v
}

func flag(name string, on bool) string {
	if !on {
		return ""
	}
	return name
}

func serverTiming(d time.Duration) string {
	return fmt.Sprintf("origin;dur=%.2f", millis(d))
}
