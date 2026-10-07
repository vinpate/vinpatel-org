package config

import (
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

func env(vars map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := vars[key]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	got, err := Load(env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{
		Listen:       ":8080",
		SiteHost:     "vinpatel.org",
		DKIMSelector: "sig1",
		DoHURL:       "https://cloudflare-dns.com/dns-query",
		LogLevel:     slog.LevelInfo,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Load() = %+v\nwant %+v", got, want)
	}
	if got.WWWHost() != "www.vinpatel.org" {
		t.Errorf("WWWHost = %q", got.WWWHost())
	}
}

func TestLoadOverrides(t *testing.T) {
	got, err := Load(env(map[string]string{
		"LISTEN":        "127.0.0.1:9000",
		"SITE_HOST":     " Example.ORG. ",
		"DKIM_SELECTOR": " Sig2 ",
		"DOH_URL":       "https://dns.example/dns-query",
		"LOG_LEVEL":     "debug",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{
		Listen:       "127.0.0.1:9000",
		SiteHost:     "example.org",
		DKIMSelector: "sig2",
		DoHURL:       "https://dns.example/dns-query",
		LogLevel:     slog.LevelDebug,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Load() = %+v\nwant %+v", got, want)
	}
}

func TestLoadBlankUsesDefaultButEmptyDoHDisables(t *testing.T) {
	got, err := Load(env(map[string]string{"SITE_HOST": "  ", "DOH_URL": ""}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.SiteHost != "vinpatel.org" {
		t.Errorf("SiteHost = %q, want the default", got.SiteHost)
	}
	if got.DoHURL != "" {
		t.Errorf("DoHURL = %q, want empty so lookups are disabled", got.DoHURL)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct{ key, value string }{
		{"LISTEN", "8080"},
		{"LISTEN", "localhost:http"},
		{"SITE_HOST", "https://vinpatel.org"},
		{"SITE_HOST", "vinpatel.org/path"},
		{"SITE_HOST", "-bad.example"},
		{"SITE_HOST", "a..b"},
		{"DKIM_SELECTOR", "sig 1"},
		{"DKIM_SELECTOR", "-sig1"},
		{"DKIM_SELECTOR", "sig1..mail"},
		{"DOH_URL", "http://cloudflare-dns.com/dns-query"},
		{"DOH_URL", "cloudflare-dns.com"},
		{"LOG_LEVEL", "loud"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			_, err := Load(env(map[string]string{tc.key: tc.value}))
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("error = %v, want one naming %s", err, tc.key)
			}
		})
	}
}

func TestLoadReportsEveryProblem(t *testing.T) {
	_, err := Load(env(map[string]string{"DKIM_SELECTOR": "-x", "LOG_LEVEL": "loud"}))
	for _, key := range []string{"DKIM_SELECTOR", "LOG_LEVEL"} {
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("error = %v, want it to name %s", err, key)
		}
	}
}
