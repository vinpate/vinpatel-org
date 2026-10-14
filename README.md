# vinpatel.org

The site behind `mail@vinpatel.org`. One page reflects your request as it
reached Cloudflare: the data center that answered, the HTTP and TLS
versions, your network, the build that rendered it and the domain's mail
setup, checked live. The footer reports on the origin: this response's
time with the p50 and p99 since start, the age of its DNS answers, the Go
version, goroutines and heap. `GET /trace` returns the same as JSON.

## How it works

```
visitor ─HTTPS─▶ Cloudflare edge ─▶ fallback Worker ─▶ Tunnel ─▶ cloudflared ─▶ web
```

- **No public inbound ports.** The containers publish no ports;
  `cloudflared` dials out to Cloudflare (`compose.yaml`). The VM accepts
  only SSH, and only from `ssh_cidr` (`infra/host.tf`).
- **A small, locked-down origin.** `web` uses only Go's standard library,
  ships as a `scratch` image and runs unprivileged on a read-only
  filesystem with no capabilities. CI smoke-tests it that way before
  publishing (`scripts/smoke.sh`).
- **Nothing about the visitor is kept.** IP headers are deleted before any
  handler runs, and no IP address, user agent or referrer is logged
  (`internal/web/middleware.go`). There are no cookies, no JavaScript and
  no third-party requests; the one `script` element is JSON-LD for search
  engines (`internal/web/profile.go`).
- **Lookups cannot stall the page.** Mail records come over
  DNS-over-HTTPS through a bounded cache that coalesces concurrent misses
  and remembers failures briefly (`internal/resolve`).
- **Percentiles without locks.** Each response time is one atomic add to a
  log-bucketed histogram, with nothing allocated per request
  (`internal/web/latency.go`); pages also send it as `Server-Timing`.
- **An outage shows a card, not an error.** When the origin is
  unreachable, a Worker serves a static contact card (`edge/fallback.js`).
  A second Worker serves the MTA-STS policy from text Terraform builds, so
  the policy outlives an outage and its DNS `id` follows its content
  (`edge/mta-sts.js`, `infra/mail.tf`).
- **The edge is code.** `infra/` declares the tunnel, DNS including the
  mail records, the transform and redirect rules, the zone and bot
  settings and both Workers. HTML responses say `Cache-Control:
  no-transform`, so Cloudflare injects nothing into them.

## Code map

| Path | What it is |
|------|------------|
| `cmd/server` | entry point, server limits, graceful shutdown, `-healthcheck` |
| `internal/config` | environment variables and their validation |
| `internal/edge` | Cloudflare request headers to a trace |
| `internal/resolve` | DNS-over-HTTPS lookups, the cache and the mail posture |
| `internal/web` | routes, middleware, the page, its template and stylesheet |
| `edge/` | the two Workers and their tests |
| `infra/` | the Cloudflare side and the Oracle Cloud host, in Terraform |
| `scripts/` | the image smoke test and the tunnel token and host secret helpers |
| `.github/` | CI and Dependabot |

A request enters at `internal/web/web.go`, passes the handlers in
`middleware.go`, and is rendered by `page.go` from `internal/edge` and
`internal/resolve`.

## Develop

```sh
mise install
go test -race ./...
node --test "edge/*.test.js"
SITE_HOST=localhost DOH_URL= go run ./cmd/server    # then open http://localhost:8080
```

`scripts/smoke.sh IMAGE` checks a built image the way CI does.

## Deploy

Secrets stay in 1Password: `infra/op.env` and `.env.tpl` hold only
`op://` references, filled in at run time. No secret enters Terraform
state or the host's metadata.

```sh
terraform -chdir=infra init
op run --env-file infra/op.env -- terraform -chdir=infra apply       # tunnel, DNS, rules, Workers, host
op run --env-file infra/op.env -- scripts/tunnel-token.sh            # store the tunnel's connector token
scripts/host-env.sh "$(terraform -chdir=infra output -raw host_ip)"  # send .env and the GHCR login, start
```

The host is an Oracle Cloud Always Free VM that accepts SSH only from
`ssh_cidr` (`infra/host.tf`). cloud-init installs Docker and clones this
repository (`infra/cloud-init.yaml`), so the host needs neither Terraform
nor the 1Password CLI; these commands run from a machine with both and
SSH. `scripts/host-env.sh` sends the rendered `.env` and a GHCR login
with a classic `read:packages` token; rerun it whenever Terraform
replaces the VM.

Every merge to `main` publishes `ghcr.io/vinpate/vinpatel-org:sha-<commit>`
and `:latest`. An hourly timer on the host pulls this repository and the
images and restarts what changed, so new images and Dependabot's
cloudflared bumps land within about an hour; set `IMAGE_TAG` in the host's
`.env` to pin one.

## Verify a build

The page's `build` row names the commit it runs; each image's provenance
attestation and SBOM tie it to that commit and the CI run that built it:

```sh
curl -s https://vinpatel.org/trace     # build.version
docker buildx imagetools inspect ghcr.io/vinpate/vinpatel-org:latest --format '{{json .Provenance}}'
```

## Configuration

| Variable | Default |
|----------|---------|
| `LISTEN` | `:8080` |
| `SITE_HOST` | `vinpatel.org` |
| `DKIM_SELECTOR` | `sig1`; the selector whose key the mail row checks |
| `DOH_URL` | `https://cloudflare-dns.com/dns-query`; empty disables lookups |
| `LOG_LEVEL` | `info`; `debug` adds request header names, never values |
