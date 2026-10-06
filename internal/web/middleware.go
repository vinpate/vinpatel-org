package web

import (
	"log/slog"
	"math"
	"net/http"
	"slices"
	"time"
)

var securityHeaderValues = [][2]string{
	{"Strict-Transport-Security", "max-age=63072000; includeSubDomains"},
	{"Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"},
	{"X-Content-Type-Options", "nosniff"},
	{"X-Frame-Options", "DENY"},
	{"Referrer-Policy", "no-referrer"},
	{"Permissions-Policy", "camera=(), microphone=(), geolocation=()"},
	{"Cross-Origin-Opener-Policy", "same-origin"},
	{"Cross-Origin-Resource-Policy", "same-origin"},
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		for _, kv := range securityHeaderValues {
			h.Set(kv[0], kv[1])
		}
		next.ServeHTTP(w, r)
	})
}

// ipHeaders are deleted before any handler runs. The edge already strips
// them; this keeps the origin anonymous if that edge setting ever changes.
var ipHeaders = []string{
	"CF-Connecting-IP", "CF-Connecting-IPv6", "CF-Pseudo-IPv4",
	"True-Client-IP", "X-Forwarded-For", "X-Real-IP", "Forwarded",
}

func stripIPHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range ipHeaders {
			r.Header.Del(name)
		}
		next.ServeHTTP(w, r)
	})
}

func allowMethods(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			text(w, http.StatusMethodNotAllowed, "method not allowed\n", "no-store")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type recorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status, r.wroteHeader = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// logRequests writes one line per request with a fixed set of fields. It
// never logs addresses, user agents or referrers. At debug level it also
// logs the sorted header names, never their values, so the edge
// configuration can be checked from the origin. Health checks, which
// Docker sends every 30 seconds, are not logged.
func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		if log.Enabled(r.Context(), slog.LevelDebug) {
			names := make([]string, 0, len(r.Header))
			for name := range r.Header {
				names = append(names, name)
			}
			slices.Sort(names)
			log.Debug("request headers", "names", names)
		}
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Info("request",
			"host", r.Host,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.bytes,
			"duration_ms", millis(time.Since(start)),
			"ray", r.Header.Get("CF-Ray"),
		)
	})
}

func millis(d time.Duration) float64 {
	return math.Round(float64(d.Microseconds())/10) / 100
}
