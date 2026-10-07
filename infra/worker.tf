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

resource "cloudflare_workers_script" "mta_sts" {
  account_id         = var.account_id
  script_name        = "vinpatel-org-mta-sts"
  main_module        = "mta-sts.js"
  content_file       = "${path.module}/../edge/mta-sts.js"
  content_sha256     = filesha256("${path.module}/../edge/mta-sts.js")
  compatibility_date = "2026-10-01"

  bindings = [{
    name = "POLICY"
    type = "plain_text"
    text = local.mta_sts_policy
  }]
}

resource "cloudflare_workers_script_subdomain" "mta_sts" {
  account_id       = var.account_id
  script_name      = cloudflare_workers_script.mta_sts.script_name
  enabled          = false
  previews_enabled = false
}

resource "cloudflare_workers_route" "mta_sts" {
  zone_id = local.zone_id
  pattern = "mta-sts.${var.zone_name}/*"
  script  = cloudflare_workers_script.mta_sts.script_name
}
