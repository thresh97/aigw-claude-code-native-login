locals {
  admin_password = coalesce(var.admin_password, random_password.admin.result)
  computer_name  = "${var.name_prefix}-vm"

  # The script travels as plain text in custom_data (Azure writes it to C:\AzureData\CustomData.bin), and the
  # extension runs it with -File. Don't gzip/base64 it into -Command with Invoke-Expression: Defender kills that
  # pattern as Behavior:Win32/PShellCobStager.A, and the extension still reports success.
  bootstrap_script = join("\n", [
    "$PublicKeyB64 = '${base64encode(trimspace(var.ssh_public_key))}'",
    "$SshDefaultShell = '${var.ssh_default_shell}'",
    file("${path.module}/bootstrap.ps1"),
  ])
  bootstrap_cmd = join(" ", [
    "cmd /c \"copy /y C:\\AzureData\\CustomData.bin C:\\AzureData\\aigw-bootstrap.ps1 &&",
    "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\AzureData\\aigw-bootstrap.ps1\"",
  ])
}

resource "random_password" "admin" {
  length           = 24
  special          = true
  override_special = "!#%*-_=+"
  min_lower        = 2
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_virtual_network" "this" {
  name                = "${var.name_prefix}-vnet"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = ["10.60.0.0/24"]
  tags                = var.tags
}

resource "azurerm_subnet" "this" {
  name                 = "${var.name_prefix}-subnet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.60.0.0/26"]
}

resource "azurerm_public_ip" "this" {
  name                = "${var.name_prefix}-pip"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_security_group" "this" {
  name                = "${var.name_prefix}-nsg"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  security_rule {
    name                       = "allow-ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = var.allowed_source_cidrs
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-rdp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefixes    = var.allowed_source_cidrs
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "this" {
  name                = "${var.name_prefix}-nic"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.this.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.this.id
  }
}

resource "azurerm_network_interface_security_group_association" "this" {
  network_interface_id      = azurerm_network_interface.this.id
  network_security_group_id = azurerm_network_security_group.this.id
}

resource "azurerm_windows_virtual_machine" "this" {
  name                = local.computer_name
  computer_name       = substr(replace(local.computer_name, "-", ""), 0, 15)
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  size                = var.vm_size
  admin_username      = var.admin_username
  admin_password      = local.admin_password
  custom_data         = base64encode(local.bootstrap_script)
  license_type        = var.license_type
  network_interface_ids = [
    azurerm_network_interface.this.id,
  ]
  tags = var.tags

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.os_disk_size_gb
  }

  source_image_reference {
    publisher = var.image_publisher
    offer     = var.image_offer
    sku       = var.image_sku
    version   = "latest"
  }

  # Managed boot diagnostics (no storage account to manage).
  boot_diagnostics {}
}

resource "azurerm_virtual_machine_extension" "bootstrap" {
  name                       = "aigw-bootstrap"
  virtual_machine_id         = azurerm_windows_virtual_machine.this.id
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  auto_upgrade_minor_version = true
  tags                       = var.tags

  protected_settings = jsonencode({
    commandToExecute = local.bootstrap_cmd
  })
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "this" {
  virtual_machine_id    = azurerm_windows_virtual_machine.this.id
  location              = azurerm_resource_group.this.location
  enabled               = var.auto_shutdown_enabled
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone
  tags                  = var.tags

  notification_settings {
    enabled = false
  }
}
