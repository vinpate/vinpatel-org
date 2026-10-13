output "tunnel_id" {
  value = cloudflare_zero_trust_tunnel_cloudflared.web.id
}

output "host_ip" {
  value = oci_core_instance.host.public_ip
}

output "console_ssh_command" {
  description = "Serial console over SSH, for when the guest's own network or sshd is broken."
  value       = oci_core_instance_console_connection.host.connection_string
}
