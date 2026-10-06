resource "cloudflare_dns_record" "site" {
  for_each = local.hosts

  zone_id = local.zone_id
  name    = each.value
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.web.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
  comment = "vinpatel-org web tunnel, managed by Terraform"
}
