package edge

import (
	"net/http"
	"strings"
	"testing"
)

func header(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestParse(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		want Trace
	}{
		{"full", header(
			"CF-Ray", "8c1f2a3b4d5e6f70-SJC",
			"X-Edge-Proto", "HTTP/3",
			"X-Edge-Tls", "TLSv1.3",
			"X-Edge-Asn", "13335",
			"CF-IPCity", "San Jose",
			"CF-IPCountry", "US",
		), Trace{Colo: "SJC", Ray: "8c1f2a3b4d5e6f70-SJC", HTTP: "HTTP/3", TLS: "TLSv1.3", ASN: 13335, City: "San Jose", Country: "US"}},
		{"no headers", http.Header{}, Trace{}},
		{"lowercase colo", header("CF-Ray", "8c1f2a3b4d5e6f70-sjc"), Trace{}},
		{"ray without colo", header("CF-Ray", "8c1f2a3b4d5e6f70"), Trace{}},
		{"ray with extra segment", header("CF-Ray", "8c1f2a3b4d5e6f70-SJC-LAX"), Trace{}},
		{"short ray", header("CF-Ray", "8c1f-SJC"), Trace{}},
		{"http/1.1 over tls 1.2", header("X-Edge-Proto", "HTTP/1.1", "X-Edge-Tls", "TLSv1.2"), Trace{HTTP: "HTTP/1.1", TLS: "TLSv1.2"}},
		{"markup in proto and tls", header("X-Edge-Proto", "<b>HTTP/3</b>", "X-Edge-Tls", "TLSv1.3; evil"), Trace{}},
		{"asn with prefix", header("X-Edge-Asn", "AS13335"), Trace{}},
		{"negative asn", header("X-Edge-Asn", "-1"), Trace{}},
		{"asn overflow", header("X-Edge-Asn", "4294967296"), Trace{}},
		{"largest asn", header("X-Edge-Asn", "4294967295"), Trace{ASN: 4294967295}},
		{"unknown country", header("CF-IPCountry", "XX"), Trace{}},
		{"tor exit", header("CF-IPCountry", "T1"), Trace{Country: "T1"}},
		{"lowercase country", header("CF-IPCountry", "us"), Trace{}},
		{"unicode city", header("CF-IPCity", "São Paulo"), Trace{City: "São Paulo"}},
		{"control character in city", header("CF-IPCity", "San\x07Jose"), Trace{}},
		{"invalid utf-8 city", header("CF-IPCity", "\xff\xfe"), Trace{}},
		{"overlong city", header("CF-IPCity", strings.Repeat("a", 65)), Trace{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Parse(tc.h); got != tc.want {
				t.Errorf("Parse() = %+v\nwant %+v", got, tc.want)
			}
		})
	}
}
