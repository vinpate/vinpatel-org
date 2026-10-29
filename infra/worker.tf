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

  # Gate for the policy fields of internal/posture/mail.json: a precondition
  # fails the plan, where a check block would only warn.
  lifecycle {
    precondition {
      condition     = contains(["testing", "enforce", "none"], local.mail.mta_sts.mode)
      error_message = "mta_sts.mode in internal/posture/mail.json must be testing, enforce or none."
    }

    precondition {
      condition     = floor(local.mail.mta_sts.max_age) == local.mail.mta_sts.max_age && local.mail.mta_sts.max_age >= 1 && local.mail.mta_sts.max_age <= 31557600
      error_message = "mta_sts.max_age in internal/posture/mail.json must be a whole number of seconds from 1 to 31557600."
    }
  }
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
