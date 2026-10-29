// Package edge reads the facts Cloudflare attaches to a request on its way
// to the origin.
package edge

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Trace is what the edge reported about one request. Values that are
// absent or malformed stay empty so the page can omit them.
type Trace struct {
	Colo    string
	Ray     string
	HTTP    string
	TLS     string
	ASN     uint32
	City    string
	Country string
}

const maxCityLen = 64

var (
	rayPattern     = regexp.MustCompile(`^[0-9a-f]{16}-([A-Z]{3})$`)
	httpPattern    = regexp.MustCompile(`^HTTP/[1-3](\.[0-9])?$`)
	tlsPattern     = regexp.MustCompile(`^TLSv1(\.[0-3])?$`)
	countryPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]$`)
)

func Parse(h http.Header) Trace {
	t := Trace{
		HTTP:    match(httpPattern, h.Get("X-Edge-Proto")),
		TLS:     match(tlsPattern, h.Get("X-Edge-Tls")),
		ASN:     asn(h.Get("X-Edge-Asn")),
		City:    city(h.Get("CF-IPCity")),
		Country: country(h.Get("CF-IPCountry")),
	}
	if m := rayPattern.FindStringSubmatch(strings.TrimSpace(h.Get("CF-Ray"))); m != nil {
		t.Ray, t.Colo = m[0], m[1]
	}
	return t
}

func match(p *regexp.Regexp, v string) string {
	v = strings.TrimSpace(v)
	if p.MatchString(v) {
		return v
	}
	return ""
}

func asn(v string) uint32 {
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func city(v string) string {
	v = strings.TrimSpace(v)
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > maxCityLen {
		return ""
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return v
}

// country drops XX, Cloudflare's code for an unknown location.
func country(v string) string {
	if v = match(countryPattern, v); v == "XX" {
		return ""
	}
	return v
}
