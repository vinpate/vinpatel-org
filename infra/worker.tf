resource "cloudflare_workers_script" "fallback" {
  account_id         = var.account_id
  script_name        = "vinpatel-org-fallback"
  main_module        = "fallback.js"
  content_file       = "${path.module}/../edge/fallback.js"
  content_sha256     = filesha256("${path.module}/../edge/fallback.js")
  compatibility_date = "2026-10-01"
}

resource "cloudflare_workers_script_subdomain" "fallback" {
  account_id       = var.account_id
  script_name      = cloudflare_workers_script.fallback.script_name
  enabled          = false
  previews_enabled = false
}

resource "cloudflare_workers_route" "fallback" {
  zone_id = local.zone_id
  pattern = "${local.hosts.apex}/*"
  script  = cloudflare_workers_script.fallback.script_name
}
