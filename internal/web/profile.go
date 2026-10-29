package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// profile is the one place the page's facts about its owner live. The
// template, the head and the JSON-LD block all render from it.
type profile struct {
	GivenName  string
	FamilyName string
	Role       string
	Former     role
	Bio        string
	Links      []link
}

type role struct {
	Title    string
	Org, URL string
	From, To int
}

// link is one row of the records list; every link carries rel="me".
type link struct {
	Label, Text, URL string
}

var vin = profile{
	GivenName:  "Vin",
	FamilyName: "Patel",
	Role:       "Infrastructure engineer",
	Former:     role{Title: "Co-founding engineer", Org: "Nirvana Labs", URL: "https://nirvanalabs.io", From: 2022, To: 2026},
	Bio:        "I build infrastructure: the storage, replication and coordination layers other software assumes just work. This domain exists so my mail comes from somewhere that is mine.",
	Links: []link{
		{"github", "github.com/vinpate", "https://github.com/vinpate"},
		{"linkedin", "linkedin.com/in/vin-pate", "https://www.linkedin.com/in/vin-pate"},
		{"bluesky", "bsky.app/profile/vinfa.bsky.social", "https://bsky.app/profile/vinfa.bsky.social"},
		{"photos", "instagram.com/vinfral7", "https://www.instagram.com/vinfral7"},
	},
}

func (p profile) Name() string { return p.GivenName + " " + p.FamilyName }

func (p profile) title() string { return p.Name() + " · " + lowerFirst(p.Role) }

func (p profile) description(site string) string {
	return fmt.Sprintf("%s, %s; %s at %s from %d to %d. Reach me at mail@%s.",
		p.Name(), lowerFirst(p.Role), lowerFirst(p.Former.Title), p.Former.Org, p.Former.From, p.Former.To, site)
}

// jsonLD is a schema.org Person. encoding/json writes <, > and & as
// \u003c, \u003e and \u0026, so the output cannot close the script
// element it is placed in; that is what makes it safe to insert unescaped.
func (p profile) jsonLD(site string) ([]byte, error) {
	sameAs := make([]string, 0, len(p.Links))
	for _, l := range p.Links {
		sameAs = append(sameAs, l.URL)
	}
	doc := map[string]any{
		"@context":    "https://schema.org",
		"@type":       "Person",
		"name":        p.Name(),
		"givenName":   p.GivenName,
		"familyName":  p.FamilyName,
		"url":         "https://" + site + "/",
		"email":       "mailto:mail@" + site,
		"jobTitle":    p.Role,
		"description": p.Bio,
		"alumniOf":    map[string]any{"@type": "Organization", "name": p.Former.Org, "url": p.Former.URL},
		"sameAs":      sameAs,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("json-ld: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func lowerFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToLower(r)) + strings.TrimPrefix(s, s[:n])
}
