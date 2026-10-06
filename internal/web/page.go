package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"vinpatel.org/site/internal/edge"
)

// traceDoc is the request trace in the shape /trace returns. Rows with no
// inputs are nil and drop out of both the JSON and the page.
type traceDoc struct {
	Served servedRow `json:"served"`
	Proto  *protoRow `json:"proto,omitempty"`
	From   *fromRow  `json:"from,omitempty"`
	Build  buildRow  `json:"build"`
	Mail   mailRow   `json:"mail"`
}

type servedRow struct {
	Colo     string  `json:"colo,omitempty"`
	Ray      string  `json:"ray,omitempty"`
	OriginMS float64 `json:"origin_ms"`
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
	DMARC  string `json:"dmarc,omitempty"`
	MTASTS string `json:"mta_sts"`
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

// trace gathers what the edge and DNS say about this request. OriginMS
// covers parsing and lookups; Server-Timing on the response adds rendering.
func (s *site) trace(r *http.Request, start time.Time) traceDoc {
	t := edge.Parse(r.Header)
	var org, dmarc string
	var wg sync.WaitGroup
	wg.Go(func() { org = s.lookup.ASOrg(r.Context(), t.ASN) })
	wg.Go(func() { dmarc = s.lookup.DMARCPolicy(r.Context(), s.cfg.SiteHost) })
	wg.Wait()

	doc := traceDoc{
		Served: servedRow{Colo: t.Colo, Ray: t.Ray},
		Build:  buildRow{Version: s.version, Time: s.built},
		Mail:   mailRow{DMARC: dmarc, MTASTS: s.cfg.MTASTSMode},
	}
	if t.HTTP != "" || t.TLS != "" {
		doc.Proto = &protoRow{HTTP: t.HTTP, TLS: t.TLS}
	}
	if t.ASN != 0 || t.City != "" || t.Country != "" {
		doc.From = &fromRow{ASN: t.ASN, ASOrg: org, City: t.City, Country: t.Country}
	}
	doc.Served.OriginMS = millis(time.Since(start))
	return doc
}

// Rows lays the trace out as the page's "this request" list.
func (d traceDoc) Rows() []row {
	rows := []row{{Key: "served", Value: join(d.Served.Colo, prefix("ray ", d.Served.Ray), fmt.Sprintf("origin %.2f ms", d.Served.OriginMS))}}
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
	return fmt.Sprintf("origin;dur=%.2f", float64(d.Microseconds())/1000)
}
