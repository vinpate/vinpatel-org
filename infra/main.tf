data "cloudflare_zone" "site" {
  filter = {
    name = var.zone_name
  }
}

locals {
  zone_id = data.cloudflare_zone.site.id
  origin  = "http://web:8080"
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
