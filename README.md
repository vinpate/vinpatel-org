# vinpatel.org

The site behind `mail@vinpatel.org`. It says whether a message from that
address could have been forged, and claims only what the domain's DNS
records confirm when you load the page. It also shows how your request
reached the site; `GET /trace` returns the same as JSON.

## How it works

```
visitor ─▶ Cloudflare ─▶ Cloudflare Tunnel ─▶ cloudflared ─▶ server
```

- The server is one Go program that uses only the standard library. It
  runs on a home server and listens on `127.0.0.1:8080`; `cloudflared`
  beside it connects out to Cloudflare, so no port is open to the
  internet.
- `internal/posture/mail.json` declares the mail setup once. Terraform
  publishes the DNS records from it (`infra/mail.tf`), and the page
  compares what DNS returns with it. The verdict rests on the live DMARC
  record alone.
- The server logs no IP address, browser or referrer. The page sets no
  cookies, runs no JavaScript and loads nothing from other sites.
- When the server is down, a Cloudflare Worker shows a contact card
  instead (`edge/fallback.js`). A second Worker serves the MTA-STS policy,
  so the policy stays up too (`edge/mta-sts.js`).
- `infra/` holds the Cloudflare setup in Terraform: the tunnel, DNS,
  rules and both Workers.

## Develop

```sh
mise install
go test -race ./...
node --test "edge/*.test.js"
SITE_HOST=localhost DOH_URL= go run ./cmd/server  # open http://localhost:8080
```

An empty `DOH_URL` turns DNS lookups off, so the local page makes no mail
claim. `scripts/build.sh` builds the release binaries into `dist/` as CI
does, and `scripts/smoke.sh BINARY` runs CI's checks against a built server.

## Deploy

Secrets stay in 1Password; `infra/op.env` holds only `op://` references.

```sh
make init
make plan   # plan the Cloudflare changes and keep the plan in 1Password
make apply  # apply exactly that plan
op run --env-file infra/op.env -- scripts/tunnel-token.sh  # store the tunnel token
```

Each push to `main` publishes a release, `v1.0.<run number>`, with Linux
binaries for amd64 and arm64, once the amd64 binary passes
`scripts/smoke.sh`. The home server installs a release by its checksum,
so a release goes live only when that checksum is updated there.

To change the mail setup, edit `internal/posture/mail.json`, push it to
`main` so CI checks it, then run `make plan` and `make apply`. Until the
home server runs a release built from the new file, the page marks the
checks that changed. Move `mta_sts.mode` from `testing` to `enforce` only
once the TLS reports show no failures.

## Verify a build

The page's `build` row names the commit it runs, and each release binary
carries an attestation that this repository's workflow built it on `main`.
To check the binary the site runs:

```sh
commit=$(curl -s https://vinpatel.org/trace | jq -r .build.version)
tag=$(gh api --paginate repos/vinpate/vinpatel-org/releases \
  --jq ".[] | select(.target_commitish | startswith(\"$commit\")) | .tag_name")
gh release download "$tag" --repo vinpate/vinpatel-org --pattern vinpatel-org-linux-amd64
gh attestation verify vinpatel-org-linux-amd64 --repo vinpate/vinpatel-org \
  --signer-workflow vinpate/vinpatel-org/.github/workflows/ci.yml \
  --source-ref refs/heads/main
```

## Configuration

| Variable | Default |
|----------|---------|
| `LISTEN` | `127.0.0.1:8080` |
| `SITE_HOST` | `vinpatel.org` |
| `DKIM_SELECTOR` | the selector in `internal/posture/mail.json` |
| `DOH_URL` | `https://cloudflare-dns.com/dns-query`; empty turns lookups off |
| `LOG_LEVEL` | `info`; `debug` also logs request header names, never values |
