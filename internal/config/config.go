// Package config reads the server's settings from the environment.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Config struct {
	Listen       string
	SiteHost     string
	DKIMSelector string
	DoHURL       string
	LogLevel     slog.Level
}

func (c Config) WWWHost() string { return "www." + c.SiteHost }

// Load reads configuration through lookup, normally os.LookupEnv. Unset or
// blank variables take their defaults, except DOH_URL, where an explicit
// empty value disables DNS lookups. Every invalid value is reported at once.
func Load(lookup func(string) (string, bool)) (Config, error) {
	get := func(key, fallback string) string {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return fallback
	}

	c := Config{
		Listen:       get("LISTEN", ":8080"),
		SiteHost:     strings.TrimSuffix(strings.ToLower(get("SITE_HOST", "vinpatel.org")), "."),
		DKIMSelector: strings.ToLower(get("DKIM_SELECTOR", "sig1")),
		DoHURL:       "https://cloudflare-dns.com/dns-query",
	}
	if v, ok := lookup("DOH_URL"); ok {
		c.DoHURL = strings.TrimSpace(v)
	}

	var errs []error
	if _, port, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, fmt.Errorf("LISTEN %q: %w", c.Listen, err))
	} else if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		errs = append(errs, fmt.Errorf("LISTEN %q: port must be a number", c.Listen))
	}
	if !validHost(c.SiteHost) {
		errs = append(errs, fmt.Errorf("SITE_HOST %q: want a bare hostname", c.SiteHost))
	}
	if !validHost(c.DKIMSelector) {
		errs = append(errs, fmt.Errorf("DKIM_SELECTOR %q: want a DNS name such as sig1", c.DKIMSelector))
	}
	if c.DoHURL != "" {
		if u, err := url.Parse(c.DoHURL); err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, fmt.Errorf("DOH_URL %q: want an https URL, or empty to disable lookups", c.DoHURL))
		}
	}
	if err := c.LogLevel.UnmarshalText([]byte(get("LOG_LEVEL", "info"))); err != nil {
		errs = append(errs, fmt.Errorf("LOG_LEVEL: %w", err))
	}
	return c, errors.Join(errs...)
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for label := range strings.SplitSeq(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
