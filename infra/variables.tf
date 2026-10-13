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

variable "tenancy_ocid" {
  description = "OCI tenancy; also the compartment that holds the budget."
  type        = string
}

variable "user_ocid" {
  description = "OCI user whose API key Terraform signs requests with."
  type        = string
}

variable "fingerprint" {
  description = "Fingerprint of that API key."
  type        = string
}

variable "private_key" {
  description = "PEM private key of that API key."
  type        = string
  sensitive   = true
}

variable "region" {
  description = "OCI home region; Always Free compute exists only there."
  type        = string
  default     = "us-ashburn-1"
}

variable "compartment_ocid" {
  description = "Compartment for the network and the host."
  type        = string
}

variable "ssh_public_key" {
  description = "OpenSSH public key for the ubuntu user and the serial console connection."
  type        = string
}

variable "ssh_cidr" {
  description = "Only source allowed to reach the host's SSH port."
  type        = string

  validation {
    condition     = can(cidrhost(var.ssh_cidr, 0)) && !endswith(var.ssh_cidr, "/0")
    error_message = "ssh_cidr must be a CIDR narrower than /0."
  }
}

variable "budget_email" {
  description = "Recipient of the budget alert."
  type        = string
  default     = "mail@vinpatel.org"
}
