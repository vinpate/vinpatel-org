# vinpatel.org

The site behind `mail@vinpatel.org`. It is one page that reflects your own
request as it reached Cloudflare: the data center that answered, the HTTP
and TLS versions you negotiated, the network you came from, the build that
rendered the page, and the domain's mail setup. The footer adds two
lines about the origin itself: how long it spent preparing this
response, beside the p50 and p99 of every page and trace since it
started, then how old its mail DNS answers are, the Go version, and the
goroutines and memory in use. `GET /trace` returns the same data as
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
  logs an IP address, user agent or referrer. There are no cookies, no
  JavaScript and no third-party requests; the one `script` element is a
  JSON-LD description of the page for search engines.
- When the origin is unreachable, a Cloudflare Worker serves a static
  contact card instead of an error page.
- The MTA-STS policy is served by a second Worker from text Terraform
  builds, so it stays fetchable while the origin is down and its DNS
  `id` changes with it.
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
| `edge/mta-sts.js` | the Worker that serves the mail policy |
| `infra/` | tunnel, DNS including the mail records, transform and redirect rules, zone settings, Workers |
| `compose.yaml` | `web` and `cloudflared` |
| `Dockerfile` | two-stage build to a `scratch` image |
| `scripts/` | the image smoke test and the tunnel token helper |
| `.github/` | the CI workflow and Dependabot |

## Develop

```sh
mise install
go test -race ./...
node --test "edge/*.test.js"
SITE_HOST=localhost DOH_URL= go run ./cmd/server    # then open http://localhost:8080
```

`scripts/smoke.sh IMAGE` checks a built image the way CI does.

## Deploy

Secrets never live in the repository. The `op://` references in
`infra/op.env` and `.env.tpl` point at items in a 1Password vault, and the
1Password CLI fills them in at run time.

```sh
op run --env-file infra/op.env -- terraform -chdir=infra apply   # tunnel, DNS, rules, Workers
op run --env-file infra/op.env -- scripts/tunnel-token.sh        # store the tunnel's connector token
op inject -i .env.tpl -o .env                                    # render the environment file
docker compose up -d                                             # start web and cloudflared
```

The host needs Docker, the 1Password CLI and, for the first two commands,
Terraform. Every merge to `main` publishes a new image; set `IMAGE_TAG`
in `.env` to pin one.

## Configuration

| Variable | Default |
|----------|---------|
| `LISTEN` | `:8080` |
| `SITE_HOST` | `vinpatel.org` |
| `DKIM_SELECTOR` | `sig1`; the selector whose key the mail row checks |
| `DOH_URL` | `https://cloudflare-dns.com/dns-query`; empty disables lookups |
| `LOG_LEVEL` | `info`; `debug` adds request header names, never values |
