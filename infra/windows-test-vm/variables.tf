variable "subscription_id" {
  description = "Azure subscription ID. Null: use ARM_SUBSCRIPTION_ID or the az CLI default."
  type        = string
  default     = null
}

variable "resource_group_name" {
  description = "Resource group to create. Everything lives here; destroy removes it."
  type        = string
  default     = "aigw-win-test-rg"
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "westeurope"
}

variable "name_prefix" {
  description = "Prefix for resource names. Windows computer names are limited to 15 characters."
  type        = string
  default     = "aigwwin"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,8}$", var.name_prefix))
    error_message = "name_prefix must be 2-9 lowercase letters/digits, starting with a letter."
  }
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default = {
    purpose = "aigw-claude-auth-windows-test"
  }
}

variable "allowed_source_cidrs" {
  description = "Source CIDRs allowed to reach SSH (22) and RDP (3389), e.g. [\"203.0.113.7/32\"]. No default."
  type        = list(string)

  validation {
    condition     = length(var.allowed_source_cidrs) > 0
    error_message = "allowed_source_cidrs must contain at least one CIDR."
  }
  validation {
    condition = alltrue([
      for c in var.allowed_source_cidrs :
      !contains(["0.0.0.0/0", "*", "0.0.0.0/1", "128.0.0.0/1", "Internet", "Any"], c) && can(cidrhost(c, 0))
    ])
    error_message = "Each entry must be a valid CIDR and must not be 0.0.0.0/0, *, or another open-to-the-world range."
  }
}

variable "vm_size" {
  description = "VM size. Standard_B2ms (2 vCPU, 8 GiB) is cheap and enough for Python and Claude Code; burstable CPU is fine for a test box. Standard_D2s_v5 is steadier at about twice the price."
  type        = string
  default     = "Standard_B2ms"
}

variable "os_disk_size_gb" {
  description = "OS disk size in GiB (the Windows 11 image is 127 GiB by default)."
  type        = number
  default     = 128
}

variable "image_publisher" {
  description = "Image publisher. Windows Server: MicrosoftWindowsServer."
  type        = string
  default     = "MicrosoftWindowsDesktop"
}

variable "image_offer" {
  description = "Image offer. Windows Server: WindowsServer."
  type        = string
  default     = "windows-11"
}

variable "image_sku" {
  description = "Image SKU. Windows Server 2022: 2022-datacenter-azure-edition; 2025: 2025-datacenter-azure-edition."
  type        = string
  default     = "win11-24h2-pro"
}

variable "license_type" {
  description = "Windows_Client for Windows 10/11 images (needs multitenant hosting rights), Windows_Server for Hybrid Benefit on Server, or null to pay the standard price."
  type        = string
  default     = "Windows_Client"

  validation {
    condition     = var.license_type == null ? true : contains(["Windows_Client", "Windows_Server", "None"], var.license_type)
    error_message = "license_type must be null, Windows_Client, Windows_Server or None."
  }
}

variable "admin_username" {
  description = "Local administrator account."
  type        = string
  default     = "aigwtest"
}

variable "admin_password" {
  description = "Administrator password (used for RDP). Null: generate one, read it with `terraform output -raw admin_password`."
  type        = string
  default     = null
  sensitive   = true
}

variable "ssh_public_key" {
  description = "Contents of the SSH public key to authorize (e.g. $(cat ~/.ssh/id_ed25519.pub))."
  type        = string

  validation {
    condition     = can(regex("^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/=]+", trimspace(var.ssh_public_key)))
    error_message = "ssh_public_key must be the contents of a public key file (ssh-ed25519 AAAA...)."
  }
}

variable "ssh_private_key_path_hint" {
  description = "Only used to print the ~/.ssh/config block."
  type        = string
  default     = "~/.ssh/id_ed25519"
}

variable "ssh_default_shell" {
  description = "Shell for SSH logins: powershell (Windows PowerShell 5.1) or cmd."
  type        = string
  default     = "powershell"

  validation {
    condition     = contains(["powershell", "cmd"], var.ssh_default_shell)
    error_message = "ssh_default_shell must be powershell or cmd."
  }
}

variable "auto_shutdown_enabled" {
  description = "Daily auto-shutdown (deallocates the VM, which stops compute billing)."
  type        = bool
  default     = true
}

variable "auto_shutdown_time" {
  description = "Shutdown time, HHmm 24-hour."
  type        = string
  default     = "1900"

  validation {
    condition     = can(regex("^([01][0-9]|2[0-3])[0-5][0-9]$", var.auto_shutdown_time))
    error_message = "auto_shutdown_time must be HHmm, e.g. 1900."
  }
}

variable "auto_shutdown_timezone" {
  description = "Windows time zone name for the shutdown time, e.g. UTC or W. Europe Standard Time."
  type        = string
  default     = "UTC"
}
