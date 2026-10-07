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

# The policy host is a Worker route, so the name only has to resolve and be
# proxied; 100:: is the discard prefix and never answers itself.
resource "cloudflare_dns_record" "mta_sts" {
  zone_id = local.zone_id
  name    = "mta-sts.${var.zone_name}"
  type    = "AAAA"
  content = "100::"
  proxied = true
  ttl     = 1
  comment = "vinpatel-org mail policy Worker, managed by Terraform"
}

# The name used to be a tunnel CNAME. Moving it keeps one record in state;
# the type change deletes the CNAME, then creates the AAAA, seconds apart.
moved {
  from = cloudflare_dns_record.site["mta_sts"]
  to   = cloudflare_dns_record.mta_sts
}
