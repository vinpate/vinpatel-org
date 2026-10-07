# The iCloud mail records, brought under management with a one-time
# terraform import, and the MTA-STS policy whose hash the _mta-sts record
# announces. The mail works because of these and would stop if they drifted.

locals {
  # RFC 8461 policy text: CRLF-terminated lines, in this order.
  mta_sts_policy = join("", [for line in concat(
    ["version: STSv1", "mode: ${var.mta_sts_mode}"],
    [for mx in var.mail_mx : "mx: ${mx}"],
    ["max_age: ${var.mta_sts_max_age}"]
  ) : "${line}\r\n"])

  # The record id must change whenever the policy does; a hash of the text
  # does that without anyone remembering to bump it.
  mta_sts_id = substr(sha256(local.mta_sts_policy), 0, 32)
}

resource "cloudflare_dns_record" "mx" {
  for_each = toset(var.mail_mx)

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
  content = "\"v=spf1 include:icloud.com ~all\""
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
  name    = "sig1._domainkey.${var.zone_name}"
  type    = "CNAME"
  content = "sig1.dkim.${var.zone_name}.at.icloudmailadmin.com"
  proxied = false
  ttl     = 3600
}

resource "cloudflare_dns_record" "dmarc" {
  zone_id = local.zone_id
  name    = "_dmarc.${var.zone_name}"
  type    = "TXT"
  content = "\"v=DMARC1; p=reject; sp=reject; rua=mailto:f368687a37af4eaba058c173faa5bad4@dmarc-reports.cloudflare.net; adkim=s; aspf=s\""
  ttl     = 1
  comment = "DMARC: reject, subdomains reject, strict alignment, reports to Cloudflare DMARC Management"
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
  content = "\"v=TLSRPTv1; rua=mailto:mail@${var.zone_name}\""
  ttl     = 1
  comment = "SMTP TLS reporting for MTA-STS"
}
