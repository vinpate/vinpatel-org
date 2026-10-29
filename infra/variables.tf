variable "account_id" {
  description = "Cloudflare account that owns the tunnel and the Workers."
  type        = string
}

variable "zone_name" {
  description = "Apex domain the site is served from."
  type        = string
  default     = "vinpatel.org"
}

variable "google_site_verification" {
  description = "Search Console verification token for the apex TXT record, with or without the google-site-verification= prefix; empty for none."
  type        = string
  default     = ""
}
