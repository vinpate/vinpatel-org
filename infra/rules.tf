resource "cloudflare_ruleset" "edge_headers" {
  zone_id     = local.zone_id
  name        = "vinpatel-org edge headers"
  description = "Expose TLS version, HTTP version and ASN to the origin."
  kind        = "zone"
  phase       = "http_request_late_transform"

  rules = [{
    ref         = "edge_headers"
    description = "Edge facts for the apex"
    expression  = "http.host eq \"${local.hosts.apex}\""
    action      = "rewrite"
    action_parameters = {
      headers = {
        "X-Edge-Tls"   = { operation = "set", expression = "cf.tls_version" }
        "X-Edge-Proto" = { operation = "set", expression = "http.request.version" }
        "X-Edge-Asn"   = { operation = "set", expression = "to_string(ip.src.asnum)" }
      }
    }
  }]
}

resource "cloudflare_ruleset" "redirects" {
  zone_id     = local.zone_id
  name        = "vinpatel-org redirects"
  description = "Send www to the apex."
  kind        = "zone"
  phase       = "http_request_dynamic_redirect"

  rules = [{
    ref         = "www_to_apex"
    description = "www to apex, path and query kept"
    expression  = "http.host eq \"${local.hosts.www}\""
    action      = "redirect"
    action_parameters = {
      from_value = {
        status_code           = 308
        preserve_query_string = true
        target_url = {
          expression = "concat(\"https://${local.hosts.apex}\", http.request.uri.path)"
        }
      }
    }
  }]
}

# Zone-wide: home.vinpatel.org also stops receiving visitor IP headers.
resource "cloudflare_managed_transforms" "site" {
  zone_id = local.zone_id
  managed_request_headers = [
    { id = "add_visitor_location_headers", enabled = true },
    { id = "remove_visitor_ip_headers", enabled = true },
  ]
  managed_response_headers = []
}
