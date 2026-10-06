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

// maxMTASTSAge is the RFC 8461 ceiling for max_age: one year in seconds.
const maxMTASTSAge = 31557600

type Config struct {
	Listen       string
	SiteHost     string
	MTASTSMode   string
	MTASTSMX     []string
	MTASTSMaxAge int
	DoHURL       string
	LogLevel     slog.Level
}

func (c Config) WWWHost() string    { return "www." + c.SiteHost }
func (c Config) MTASTSHost() string { return "mta-sts." + c.SiteHost }

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
		Listen:     get("LISTEN", ":8080"),
		SiteHost:   strings.TrimSuffix(strings.ToLower(get("SITE_HOST", "vinpatel.org")), "."),
		MTASTSMode: get("MTA_STS_MODE", "testing"),
		DoHURL:     "https://cloudflare-dns.com/dns-query",
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
	switch c.MTASTSMode {
	case "testing", "enforce", "none":
	default:
		errs = append(errs, fmt.Errorf("MTA_STS_MODE %q: want testing, enforce or none", c.MTASTSMode))
	}
	for mx := range strings.SplitSeq(get("MTA_STS_MX", "mx01.mail.icloud.com,mx02.mail.icloud.com"), ",") {
		mx = strings.ToLower(strings.TrimSpace(mx))
		if !validHost(strings.TrimPrefix(mx, "*.")) {
			errs = append(errs, fmt.Errorf("MTA_STS_MX entry %q: want a hostname or *.hostname", mx))
			continue
		}
		c.MTASTSMX = append(c.MTASTSMX, mx)
	}
	maxAge := get("MTA_STS_MAX_AGE", "604800")
	if n, err := strconv.Atoi(maxAge); err != nil || n < 1 || n > maxMTASTSAge {
		errs = append(errs, fmt.Errorf("MTA_STS_MAX_AGE %q: want 1 to %d seconds", maxAge, maxMTASTSAge))
	} else {
		c.MTASTSMaxAge = n
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
