package posture

import (
	"encoding/json/v2"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// variant returns the embedded declaration with edit applied to its decoded
// form, encoded again.
func variant(t *testing.T, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(mailJSON, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func object(m map[string]any, key string) map[string]any { return m[key].(map[string]any) }

func TestEmbeddedDeclarationLoads(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var want, got any
	if err := json.Unmarshal(mailJSON, &want); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Load() = %s\nwant the file's values %s", b, mailJSON)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(m map[string]any)
		names string
	}{
		{"typo in a field name", func(m map[string]any) { m["tlsrpt"] = m["tls_rpt"]; delete(m, "tls_rpt") }, "tlsrpt"},
		{"mis-cased key", func(m map[string]any) { m["Domain"] = m["domain"]; delete(m, "domain") }, "Domain"},
		{"mis-cased nested key", func(m map[string]any) { d := object(m, "dmarc"); d["P"] = d["p"]; delete(d, "p") }, `"P"`},
		{"missing dmarc", func(m map[string]any) { delete(m, "dmarc") }, "dmarc.p"},
		{"dmarc policy outside the set", func(m map[string]any) { object(m, "dmarc")["p"] = "bogus" }, "dmarc.p"},
		{"subdomain policy outside the set", func(m map[string]any) { object(m, "dmarc")["sp"] = "rejct" }, "dmarc.sp"},
		{"dkim alignment outside the set", func(m map[string]any) { object(m, "dmarc")["adkim"] = "strict" }, "dmarc.adkim"},
		{"spf alignment outside the set", func(m map[string]any) { object(m, "dmarc")["aspf"] = "strict" }, "dmarc.aspf"},
		{"mta-sts mode outside the set", func(m map[string]any) { object(m, "mta_sts")["mode"] = "always" }, "mta_sts.mode"},
		{"max age of zero", func(m map[string]any) { object(m, "mta_sts")["max_age"] = 0 }, "mta_sts.max_age"},
		{"max age past a year", func(m map[string]any) { object(m, "mta_sts")["max_age"] = 31557601 }, "mta_sts.max_age"},
		{"max age as a string", func(m map[string]any) { object(m, "mta_sts")["max_age"] = fmt.Sprint(object(m, "mta_sts")["max_age"]) }, "max_age"},
		{"empty mx list", func(m map[string]any) { m["mx"] = []any{} }, "mx"},
		{"mx that is not a host", func(m map[string]any) { m["mx"] = append(m["mx"].([]any), "mx 02") }, "mx"},
		{"empty domain", func(m map[string]any) { m["domain"] = "" }, "domain"},
		{"spf that is not an spf record", func(m map[string]any) { m["spf"] = strings.TrimPrefix(m["spf"].(string), "v=spf1 ") }, "spf"},
		{"selector that is not a dns name", func(m map[string]any) { object(m, "dkim")["selector"] = "has space" }, "dkim.selector"},
		{"dkim target that is not a dns name", func(m map[string]any) { object(m, "dkim")["target"] = "has space.example" }, "dkim.target"},
		{"empty dmarc reports address", func(m map[string]any) { object(m, "dmarc")["rua"] = "" }, "dmarc.rua"},
		{"empty tls reports address", func(m map[string]any) { object(m, "tls_rpt")["rua"] = "" }, "tls_rpt.rua"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(variant(t, tc.edit))
			if err == nil || !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("error = %v, want one naming %s", err, tc.names)
			}
		})
	}
}

func TestLoadAccepts(t *testing.T) {
	cases := []struct {
		name string
		edit func(m map[string]any)
	}{
		{"quarantine", func(m map[string]any) { object(m, "dmarc")["p"] = "quarantine" }},
		{"enforce", func(m map[string]any) { object(m, "mta_sts")["mode"] = "enforce" }},
		{"shortest max age", func(m map[string]any) { object(m, "mta_sts")["max_age"] = 1 }},
		{"longest max age", func(m map[string]any) { object(m, "mta_sts")["max_age"] = 31557600 }},
		{"one mx", func(m map[string]any) { m["mx"] = m["mx"].([]any)[:1] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parse(variant(t, tc.edit)); err != nil {
				t.Fatalf("parse: %v", err)
			}
		})
	}
}
