package web

import (
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var ldBlock = regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`)

func TestJSONLDDescribesThePerson(t *testing.T) {
	page := serve(newHandler(t, testOptions(t)), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	m := ldBlock.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("page has no JSON-LD block:\n%s", page)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(m[1]), &got); err != nil {
		t.Fatalf("JSON-LD does not parse: %v\n%s", err, m[1])
	}
	for key, want := range map[string]any{
		"@context": "https://schema.org",
		"@type":    "Person",
		"name":     "Vin Patel",
		"url":      "https://vinpatel.org/",
		"email":    "mailto:mail@vinpatel.org",
		"jobTitle": "Infrastructure engineer",
	} {
		if got[key] != want {
			t.Errorf("%s = %v, want %v", key, got[key], want)
		}
	}
	alumni, _ := got["alumniOf"].(map[string]any)
	if alumni["name"] != "Nirvana Labs" || alumni["url"] != "https://nirvanalabs.io" || alumni["@type"] != "Organization" {
		t.Errorf("alumniOf = %v", got["alumniOf"])
	}
	var me []any
	for _, m := range regexp.MustCompile(`<a href="([^"]+)" rel="me">`).FindAllStringSubmatch(page, -1) {
		me = append(me, m[1])
	}
	if !reflect.DeepEqual(got["sameAs"], me) {
		t.Errorf("sameAs = %v, page's rel=me links are %v", got["sameAs"], me)
	}
}

func TestJSONLDEscapesHTML(t *testing.T) {
	p := vin
	p.Bio = "</script><script>alert(1)</script> & co"
	p.Links = []link{{"x", "x", "https://x.example/?a=1&b=2"}}
	out, err := p.jsonLD("vinpatel.org")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "</script") || strings.Contains(string(out), "<script") {
		t.Errorf("JSON-LD can close the script element:\n%s", out)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("escaped JSON-LD does not parse: %v", err)
	}
	if got["sameAs"].([]any)[0] != "https://x.example/?a=1&b=2" {
		t.Errorf("escaping changed the value: %v", got["sameAs"])
	}
}

func TestHeadDescribesThePage(t *testing.T) {
	page := serve(newHandler(t, testOptions(t)), http.MethodGet, "vinpatel.org", "/", nil).Body.String()
	for _, want := range []string{
		`<title>Vin Patel · infrastructure engineer</title>`,
		`<meta name="description" content="Vin Patel, infrastructure engineer; co-founding engineer at Nirvana Labs from 2022 to 2026. Reach me at mail@vinpatel.org.">`,
		`<meta property="og:type" content="profile">`,
		`<meta property="og:title" content="Vin Patel · infrastructure engineer">`,
		`<meta property="og:url" content="https://vinpatel.org/">`,
		`<meta property="profile:first_name" content="Vin">`,
		`<meta property="profile:last_name" content="Patel">`,
		`<p class="domain">vinpatel.org</p>`,
		`<h1 class="name">Vin Patel</h1>`,
		`<p class="title">Infrastructure engineer</p>`,
		`<p class="former">Co-founding engineer, <a href="https://nirvanalabs.io">Nirvana Labs</a>, 2022–2026</p>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if n := strings.Count(page, "<h1"); n != 1 {
		t.Errorf("page has %d h1 elements, want 1", n)
	}
}
