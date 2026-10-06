# vinpatel.org

The site behind `mail@vinpatel.org`. It is one page that reflects your own
request as it reached Cloudflare: the data center that answered, the HTTP
and TLS versions you negotiated, the network you came from, the build that
rendered the page, and the domain's mail policy. The footer adds a line
about the origin itself: how long it took to answer, the Go version, and
the goroutines and memory in use. `GET /trace` returns the same data as
JSON.

## How it runs

```
visitor ─HTTPS─▶ Cloudflare edge ─▶ fallback Worker ─▶ Tunnel ─▶ cloudflared ─▶ web
```

- `web` is a Go program that uses only the standard library. It ships as a
  `scratch` image and runs as an unprivileged user on a read-only
  filesystem with every capability dropped.
- The host publishes no ports. `cloudflared` dials out to Cloudflare and
  nothing dials in.
- The origin drops visitor IP headers before any handler runs and never
  logs an IP address, user agent or referrer. There are no cookies,
  scripts or third-party requests.
- When the origin is unreachable, a Cloudflare Worker serves a static
  contact card instead of an error page.
- `compose.yaml` is the whole runtime and `infra/` declares the Cloudflare
  side in Terraform, so moving to another Docker host needs no DNS change.

## Layout

| Path | What it is |
|------|------------|
| `cmd/server` | entry point, server limits, graceful shutdown, `-healthcheck` |
| `internal/config` | environment variables and their validation |
| `internal/edge` | Cloudflare request headers to a trace |
| `internal/resolve` | DNS-over-HTTPS TXT lookups behind a bounded, coalescing cache |
| `internal/web` | routes, middleware, the template and the stylesheet |
| `edge/fallback.js` | the Worker that serves the offline card |
| `infra/` | tunnel, DNS, transform and redirect rules, zone settings, Worker |
| `compose.yaml` | `web` and `cloudflared` |

## Develop

```sh
mise install
go test -race ./...
node --test edge/fallback.test.js
SITE_HOST=localhost DOH_URL= go run ./cmd/server    # then open http://localhost:8080
```

`scripts/smoke.sh IMAGE` checks a built image the way CI does.

## Configuration

| Variable | Default |
|----------|---------|
| `LISTEN` | `:8080` |
| `SITE_HOST` | `vinpatel.org` |
| `MTA_STS_MODE` | `testing` |
| `MTA_STS_MX` | `mx01.mail.icloud.com,mx02.mail.icloud.com` |
| `MTA_STS_MAX_AGE` | `604800` |
| `DOH_URL` | `https://cloudflare-dns.com/dns-query`; empty disables lookups |
| `LOG_LEVEL` | `info`; `debug` adds request header names, never values |
