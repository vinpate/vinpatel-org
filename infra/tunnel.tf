# Separate from the private home.vinpatel.org tunnel so public and private
# traffic never share a credential. There is no tunnel_secret: Cloudflare
# generates it, so neither the secret nor the connector token enters state.
# scripts/tunnel-token.sh reads the token from the API instead.
resource "cloudflare_zero_trust_tunnel_cloudflared" "web" {
  account_id = var.account_id
  name       = "vinpatel-org-web"
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "web" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.web.id
  config = {
    ingress = [
      { hostname = local.hosts.apex, service = local.origin },
      { hostname = local.hosts.www, service = local.origin },
      { hostname = local.hosts.mta_sts, service = local.origin },
      { service = "http_status:404" },
    ]
  }
}
