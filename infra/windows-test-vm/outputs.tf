output "public_ip" {
  description = "Public IP of the VM."
  value       = azurerm_public_ip.this.ip_address
}

output "admin_username" {
  value = var.admin_username
}

output "ssh_config" {
  description = "Paste into ~/.ssh/config."
  value       = <<-EOT
    Host aigw-win
      HostName ${azurerm_public_ip.this.ip_address}
      User ${var.admin_username}
      IdentityFile ${var.ssh_private_key_path_hint}
      IdentitiesOnly yes
      ServerAliveInterval 30
  EOT
}

output "rdp_hint" {
  value = "RDP to ${azurerm_public_ip.this.ip_address}:3389 as ${var.admin_username}; password: terraform output -raw admin_password"
}

output "admin_password" {
  description = "Administrator password (RDP)."
  value       = local.admin_password
  sensitive   = true
}
