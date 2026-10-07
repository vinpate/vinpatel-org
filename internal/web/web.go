// Package web serves vinpatel.org: the page, its trace, and the small
// protocol files around it.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vinpatel.org/site/internal/config"
	"vinpatel.org/site/internal/resolve"
)

//go:embed templates static
var content embed.FS

// Lookup is the DNS knowledge the page needs; *resolve.Resolver satisfies it.
type Lookup interface {
	// Mail is what a sending server would find for domain, with selector
	// as the DKIM selector to check. Unknown parts are zero.
	Mail(ctx context.Context, domain, selector string) resolve.Mail
	ASOrg(ctx context.Context, asn uint32) string
}

type Options struct {
	Config    config.Config
	Version   string
	BuildTime time.Time
	Lookup    Lookup
	Logger    *slog.Logger
}

type site struct {
	cfg      config.Config
	version  string
	built    time.Time
	lookup   Lookup
	log      *slog.Logger
	tmpl     *template.Template
	security string
	head     head
	latency  histogram
}

// head is what the page's <head> and JSON-LD say; fixed for the process.
type head struct {
	Title, Description string
	JSONLD             template.JS
}

func New(o Options) (http.Handler, error) {
	if o.Lookup == nil || o.Logger == nil {
		return nil, errors.New("web: Options.Lookup and Options.Logger are required")
	}
	tmpl, err := template.ParseFS(content, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: templates: %w", err)
	}
	css, err := asset("static/style.css")
	if err != nil {
		return nil, err
	}
	icon, err := asset("static/favicon.svg")
	if err != nil {
		return nil, err
	}
	ld, err := vin.jsonLD(o.Config.SiteHost)
	if err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}

	s := &site{
		cfg:      o.Config,
		version:  o.Version,
		built:    o.BuildTime.UTC(),
		lookup:   o.Lookup,
		log:      o.Logger,
		tmpl:     tmpl,
		security: securityTXT(o.Config.SiteHost, o.BuildTime),
		head:     head{Title: vin.title(), Description: vin.description(o.Config.SiteHost), JSONLD: template.JS(ld)},
	}

	apex := http.NewServeMux()
	apex.Handle("/style.css", css)
	apex.Handle("/favicon.svg", icon)
	apex.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusNoContent)
	})
	apex.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		text(w, http.StatusOK, "User-agent: *\nAllow: /\n", "public, max-age=86400")
	})
	apex.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		text(w, http.StatusOK, s.security, "public, max-age=86400")
	})
	apex.HandleFunc("/{$}", s.index)
	apex.HandleFunc("/trace", s.traceJSON)
	apex.HandleFunc("/", s.notFound)

	var h http.Handler = s.route(apex)
	h = allowMethods(h)
	h = stripIPHeaders(h)
	h = securityHeaders(h)
	return logRequests(o.Logger, h), nil
}

// route answers /healthz on every host so the loopback healthcheck works,
// then splits by host: the apex mux, and a permanent redirect to the apex
// for anything else, www included.
func (s *site) route(apex http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			text(w, http.StatusOK, "ok\n", "no-store")
			return
		}
		if hostname(r.Host) == s.cfg.SiteHost {
			apex.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "https://"+s.cfg.SiteHost+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}

func hostname(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// securityTXT expires 364 days after the build, inside RFC 9116's one-year
// limit, so a site that stops being rebuilt stops vouching for its contact.
func securityTXT(host string, built time.Time) string {
	if built.IsZero() {
		built = time.Now()
	}
	expires := built.UTC().AddDate(0, 0, 364).Truncate(time.Second)
	return "Contact: mailto:mail@" + host + "\n" +
		"Expires: " + expires.Format(time.RFC3339) + "\n" +
		"Preferred-Languages: en\n" +
		"Canonical: https://" + host + "/.well-known/security.txt\n"
}

func asset(name string) (http.Handler, error) {
	body, err := fs.ReadFile(content, name)
	if err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
	}), nil
}

func (s *site) notFound(w http.ResponseWriter, r *http.Request) {
	body, err := s.execute("404.html", struct{ Site string }{s.cfg.SiteHost})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeBody(w, http.StatusNotFound, "text/html; charset=utf-8", "no-store, no-transform", body)
}

func (s *site) execute(name string, data any) ([]byte, error) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return nil, fmt.Errorf("render %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

func (s *site) fail(w http.ResponseWriter, err error) {
	s.log.Error("render failed", "err", err)
	text(w, http.StatusInternalServerError, "internal error\n", "no-store")
}

func writeBody(w http.ResponseWriter, status int, contentType, cacheControl string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", cacheControl)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	w.Write(body)
}

func text(w http.ResponseWriter, status int, body, cacheControl string) {
	writeBody(w, status, "text/plain; charset=utf-8", cacheControl, []byte(body))
}
