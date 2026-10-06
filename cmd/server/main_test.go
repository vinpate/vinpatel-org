package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vinpatel.org/site/internal/config"
)

func TestLoopback(t *testing.T) {
	cases := map[string]string{
		":8080":          "127.0.0.1:8080",
		"0.0.0.0:9000":   "127.0.0.1:9000",
		"[::]:8080":      "127.0.0.1:8080",
		"127.0.0.1:8081": "127.0.0.1:8081",
		"localhost:80":   "localhost:80",
	}
	for listen, want := range cases {
		got, err := loopback(listen)
		if err != nil || got != want {
			t.Errorf("loopback(%q) = %q, %v; want %q", listen, got, err, want)
		}
	}
	if _, err := loopback("8080"); err == nil {
		t.Error(`loopback("8080") succeeded`)
	}
}

func TestProbe(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "ok\n")
	}))
	defer healthy.Close()
	if err := probe(healthy.Listener.Addr().String(), time.Second); err != nil {
		t.Errorf("probe(healthy) = %v", err)
	}

	sick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer sick.Close()
	if err := probe(sick.Listener.Addr().String(), time.Second); err == nil {
		t.Error("probe(503) succeeded")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	if err := probe(closed, time.Second); err == nil {
		t.Error("probe(closed port) succeeded")
	}
}

func TestServerLimits(t *testing.T) {
	srv := newServer(http.NotFoundHandler(), slog.New(slog.DiscardHandler))
	if srv.ReadHeaderTimeout != 5*time.Second || srv.ReadTimeout != 10*time.Second ||
		srv.WriteTimeout != 10*time.Second || srv.IdleTimeout != 60*time.Second ||
		srv.MaxHeaderBytes != 16<<10 {
		t.Errorf("limits = %v %v %v %v %d", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout, srv.MaxHeaderBytes)
	}
}

func TestRunServesUntilCancelled(t *testing.T) {
	cfg, err := config.Load(func(key string) (string, bool) {
		if key == "DOH_URL" {
			return "", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, ln, slog.New(slog.DiscardHandler)) }()

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "vinpatel.org"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `<h1 class="domain">vinpatel.org</h1>`) {
		t.Fatalf("GET / = %d\n%s", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return within 5s of cancel")
	}
}
