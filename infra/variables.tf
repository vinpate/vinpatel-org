variable "account_id" {
  description = "Cloudflare account that owns the tunnel and the Worker."
  type        = string
}

variable "zone_name" {
  description = "Apex domain the site is served from."
  type        = string
  default     = "vinpatel.org"
}

variable "mail_mx" {
  description = "Mail exchangers, all published at priority 10; also the mx lines of the MTA-STS policy."
  type        = list(string)
  default     = ["mx01.mail.icloud.com", "mx02.mail.icloud.com"]
}

variable "mta_sts_mode" {
  description = "MTA-STS policy mode. Move to enforce only after clean TLS reports."
  type        = string
  default     = "testing"

  validation {
    condition     = contains(["testing", "enforce", "none"], var.mta_sts_mode)
    error_message = "mta_sts_mode must be testing, enforce or none."
  }
}

variable "mta_sts_max_age" {
  description = "Seconds a sending server may cache the policy (RFC 8461 allows up to 31557600)."
  type        = number
  default     = 604800

  validation {
    condition     = var.mta_sts_max_age >= 1 && var.mta_sts_max_age <= 31557600
    error_message = "mta_sts_max_age must be between 1 and 31557600 seconds."
  }
}

variable "google_site_verification" {
  description = "Search Console verification token for the apex TXT record, with or without the google-site-verification= prefix; empty for none."
  type        = string
  default     = ""
}
