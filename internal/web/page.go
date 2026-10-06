package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"runtime/metrics"
	"slices"
	"strings"
	"sync"
	"time"

	"vinpatel.org/site/internal/edge"
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

type mailRow struct {
	DMARC     string `json:"dmarc,omitempty"`
	DMARCAgeS int    `json:"dmarc_age_s,omitempty"`
	MTASTS    string `json:"mta_sts"`
}

// originRow describes the process that answered: how long it spent on
// parsing and lookups, and what it is running on.
type originRow struct {
	MS         float64 `json:"ms"`
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
	Site  string
	Trace traceDoc
}

func (s *site) index(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, err := s.execute("index.html", page{Site: s.cfg.SiteHost, Trace: s.trace(r, start)})
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Server-Timing", serverTiming(time.Since(start)))
	writeBody(w, http.StatusOK, "text/html; charset=utf-8", "private, no-store", body)
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
// covers parsing and lookups; Server-Timing on the response adds rendering.
func (s *site) trace(r *http.Request, start time.Time) traceDoc {
	t := edge.Parse(r.Header)
	var org, dmarc string
	var dmarcAge time.Duration
	var wg sync.WaitGroup
	wg.Go(func() { org = s.lookup.ASOrg(r.Context(), t.ASN) })
	wg.Go(func() { dmarc, dmarcAge = s.lookup.DMARCPolicy(r.Context(), s.cfg.SiteHost) })
	wg.Wait()

	doc := traceDoc{
		Build: buildRow{Version: s.version, Time: s.built},
		Mail:  mailRow{DMARC: dmarc, DMARCAgeS: int(dmarcAge.Seconds()), MTASTS: s.cfg.MTASTSMode},
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
	doc.Origin = originRow{
		MS:         millis(time.Since(start)),
		Go:         runtime.Version(),
		Goroutines: runtime.NumGoroutine(),
		HeapBytes:  heapBytes(),
	}
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
	return append(rows,
		row{Key: "build", Value: d.Build.Version, Time: d.Build.Time},
		row{Key: "mail", Value: join(prefix("dmarc p=", d.Mail.DMARC), "mta-sts "+d.Mail.MTASTS)},
	)
}

// OriginLine is the page's footer: what answered, and how fresh its DNS
// knowledge is.
func (d traceDoc) OriginLine() string {
	var dmarc string
	if d.Mail.DMARC != "" {
		dmarc = "dmarc " + cachedAgo(time.Duration(d.Mail.DMARCAgeS)*time.Second)
	}
	return join(
		fmt.Sprintf("origin %.2f ms", d.Origin.MS),
		dmarc,
		d.Origin.Go,
		fmt.Sprintf("%d goroutines", d.Origin.Goroutines),
		fmt.Sprintf("%.1f MB heap", float64(d.Origin.HeapBytes)/1e6),
	)
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

func serverTiming(d time.Duration) string {
	return fmt.Sprintf("origin;dur=%.2f", millis(d))
}
