# The iCloud mail records, brought under management with a one-time
# terraform import, and the MTA-STS policy whose hash the _mta-sts record
# announces. The mail works because of these and would stop if they drifted.
# Apart from the apple-domain record, their values come from
# internal/posture/mail.json, the one declaration of the mail posture, which
# the Go binary embeds as well; change them there.

locals {
  mail = jsondecode(file("${path.module}/../internal/posture/mail.json"))

  # RFC 8461 policy text: CRLF-terminated lines, in this order.
  mta_sts_policy = join("", [for line in concat(
    ["version: STSv1", "mode: ${local.mail.mta_sts.mode}"],
    [for mx in local.mail.mx : "mx: ${mx}"],
    ["max_age: ${local.mail.mta_sts.max_age}"]
  ) : "${line}\r\n"])

  # The record id must change whenever the policy does; a hash of the text
  # does that without anyone remembering to bump it.
  mta_sts_id = substr(sha256(local.mta_sts_policy), 0, 32)

  # The DMARC record's note in the dashboard. Cloudflare's report address
  # is an opaque mailbox, so it is named by its service.
  dmarc_comment = join(", ", [
    "DMARC: ${local.mail.dmarc.p}",
    "subdomains ${local.mail.dmarc.sp}",
    local.mail.dmarc.adkim == "s" && local.mail.dmarc.aspf == "s" ? "strict alignment" : "adkim=${local.mail.dmarc.adkim} aspf=${local.mail.dmarc.aspf}",
    endswith(local.mail.dmarc.rua, "@dmarc-reports.cloudflare.net") ? "reports to Cloudflare DMARC Management" : "reports to ${local.mail.dmarc.rua}",
  ])
}

resource "cloudflare_dns_record" "mx" {
  for_each = toset(local.mail.mx)

  zone_id  = local.zone_id
  name     = var.zone_name
  type     = "MX"
  content  = each.value
  priority = 10
  ttl      = 3600
}

resource "cloudflare_dns_record" "spf" {
  zone_id = local.zone_id
  name    = var.zone_name
  type    = "TXT"
  content = "\"${local.mail.spf}\""
  ttl     = 3600
}

resource "cloudflare_dns_record" "apple_domain" {
  zone_id = local.zone_id
  name    = var.zone_name
  type    = "TXT"
  content = "\"apple-domain=kMeMA2AbbnslLIHh\""
  ttl     = 3600
}

resource "cloudflare_dns_record" "dkim" {
  zone_id = local.zone_id
  name    = "${local.mail.dkim.selector}._domainkey.${var.zone_name}"
  type    = "CNAME"
  content = local.mail.dkim.target
  proxied = false
  ttl     = 3600
}

resource "cloudflare_dns_record" "dmarc" {
  zone_id = local.zone_id
  name    = "_dmarc.${var.zone_name}"
  type    = "TXT"
  content = "\"v=DMARC1; p=${local.mail.dmarc.p}; sp=${local.mail.dmarc.sp}; rua=${local.mail.dmarc.rua}; adkim=${local.mail.dmarc.adkim}; aspf=${local.mail.dmarc.aspf}\""
  ttl     = 1
  comment = local.dmarc_comment

  lifecycle {
    precondition {
      condition     = contains(["none", "quarantine", "reject"], local.mail.dmarc.p)
      error_message = "dmarc.p in internal/posture/mail.json must be none, quarantine or reject."
    }

    precondition {
      condition     = contains(["none", "quarantine", "reject"], local.mail.dmarc.sp)
      error_message = "dmarc.sp in internal/posture/mail.json must be none, quarantine or reject."
    }

    precondition {
      condition     = contains(["r", "s"], local.mail.dmarc.adkim) && contains(["r", "s"], local.mail.dmarc.aspf)
      error_message = "dmarc.adkim and dmarc.aspf in internal/posture/mail.json must each be r or s."
    }

    precondition {
      condition     = local.mail.domain == var.zone_name
      error_message = "domain in internal/posture/mail.json must be zone_name, the zone these records are published in."
    }
  }
}

resource "cloudflare_dns_record" "mta_sts_txt" {
  zone_id = local.zone_id
  name    = "_mta-sts.${var.zone_name}"
  type    = "TXT"
  content = "\"v=STSv1; id=${local.mta_sts_id}\""
  ttl     = 1
  comment = "MTA-STS pointer; the id is a hash of the policy the Worker serves"

  # The policy must be live before the id that announces it.
  depends_on = [cloudflare_workers_script.mta_sts]
}

resource "cloudflare_dns_record" "tls_rpt" {
  zone_id = local.zone_id
  name    = "_smtp._tls.${var.zone_name}"
  type    = "TXT"
  content = "\"v=TLSRPTv1; rua=${local.mail.tls_rpt.rua}\""
  ttl     = 1
  comment = "SMTP TLS reporting for MTA-STS"
}
