// Command server runs the vinpatel.org origin.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vinpatel.org/site/internal/config"
	"vinpatel.org/site/internal/resolve"
	"vinpatel.org/site/internal/web"
)

// Set at link time: -ldflags "-X main.version=<sha> -X main.buildTime=<RFC 3339>".
var (
	version   = "dev"
	buildTime = ""
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe /healthz on LISTEN over loopback and exit 0 if healthy")
	flag.Parse()

	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	if *healthcheck {
		if err := probe(cfg.Listen, 2*time.Second); err != nil {
			fmt.Fprintln(os.Stderr, "healthcheck:", err)
			os.Exit(1)
		}
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logger.Error("listen", "addr", cfg.Listen, "err", err)
		os.Exit(1)
	}
	if err := run(ctx, cfg, ln, logger); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config.Config, ln net.Listener, logger *slog.Logger) error {
	built, _ := time.Parse(time.RFC3339, buildTime)
	handler, err := web.New(web.Options{
		Config:    cfg,
		Version:   version,
		BuildTime: built,
		Lookup:    resolve.New(resolve.Options{Endpoint: cfg.DoHURL}),
		Logger:    logger,
	})
	if err != nil {
		return err
	}
	srv := newServer(handler, logger)

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	logger.Info("listening", "addr", ln.Addr().String(), "version", version, "build_time", buildTime)

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		return err
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func newServer(h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

// probe is the container healthcheck. A scratch image has no shell or curl,
// so the binary checks itself over loopback.
func probe(listen string, timeout time.Duration) error {
	addr, err := loopback(listen)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: timeout}).Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /healthz: status %d", resp.StatusCode)
	}
	return nil
}

func loopback(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}
