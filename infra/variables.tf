variable "account_id" {
  description = "Cloudflare account that owns the tunnel and the Worker."
  type        = string
}

variable "zone_name" {
  description = "Apex domain the site is served from."
  type        = string
  default     = "vinpatel.org"
}
