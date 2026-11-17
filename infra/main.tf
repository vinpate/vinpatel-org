data "cloudflare_zone" "site" {
  filter = {
    name = var.zone_name
  }
}

locals {
  zone_id = data.cloudflare_zone.site.id
  # cloudflared runs beside the server, which listens on loopback alone.
  origin = "http://127.0.0.1:8080"
  hosts = {
    apex = var.zone_name
    www  = "www.${var.zone_name}"
  }
}

resource "cloudflare_zone_setting" "min_tls_version" {
  zone_id    = local.zone_id
  setting_id = "min_tls_version"
  value      = "1.2"
}

resource "cloudflare_zone_setting" "always_use_https" {
  zone_id    = local.zone_id
  setting_id = "always_use_https"
  value      = "on"
}

# The page's CSP has no script-src, so anything Cloudflare injects only
# produces a console error, like the email obfuscation that would leave
# "[email protected]" on a 200 page. Network Error Logging asks browsers to
# report to Cloudflare, which the page's note does not admit to.
resource "cloudflare_zone_setting" "email_obfuscation" {
  zone_id    = local.zone_id
  setting_id = "email_obfuscation"
  value      = "off"
}

resource "cloudflare_zone_setting" "nel" {
  zone_id    = local.zone_id
  setting_id = "nel"
  value      = { enabled = false }
}

# Bot Fight Mode stays off. It covers every host in the zone and no rule
# can exempt one, so it answered every datacenter client with a challenge
# that only a browser can pass: mail servers fetching the MTA-STS policy,
# uptime checks, and `curl /trace` from the README's verify steps.
# JavaScript Detections go off with it; Cloudflare forces them on only
# while Bot Fight Mode runs. Cloudflare retired the single AI bot block on
# 2026-09-15 and writes to it no longer stick; these presets replace it,
# independently of Bot Fight Mode. AI agent and training bots are blocked;
# AI search crawlers may index the page.
resource "cloudflare_bot_management" "site" {
  zone_id     = local.zone_id
  enable_js   = false
  fight_mode  = false
  aisearch    = "disabled"
  ai_user     = "block"
  ai_training = "block"
}
