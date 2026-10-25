# Windows test VM (Azure, Terraform)

A small, throwaway Windows VM for testing the Windows port (see `repro/WINDOWS.md`). An agent drives it over SSH
(`Host aigw-win`); you log in over RDP to see toasts and the interactive Claude Code UI. Everything is created in one new
resource group, so `terraform destroy` removes it and touches nothing else.

This creates billable resources in your subscription. Nothing here has been applied by the author; the notes marked
"(docs/knowledge)" are not from a run.

## What it builds

Resource group, VNet and subnet, Standard static public IP, NIC, NSG on the NIC, one Windows VM, a CustomScriptExtension
that sets up OpenSSH, and a daily auto-shutdown. All resources carry the tag `purpose = aigw-claude-auth-windows-test`.

- **Network.** Inbound TCP 22 and 3389 only from `allowed_source_cidrs`; an explicit deny for everything else inbound. The
  variable has no default and rejects an empty list, `0.0.0.0/0`, `*` and the two /1 halves of the internet.
- **Size.** Default `Standard_B2ms` (2 vCPU, 8 GiB): enough for Python, Claude Code and the Windows desktop at low cost.
  Burstable CPU is fine for a test box. `Standard_D2s_v5` is steadier and roughly twice the price.
- **Image.** Default is Windows 11 Pro 24H2 (`MicrosoftWindowsDesktop` / `windows-11` / `win11-24h2-pro`) because the
  target is a desktop OS.

### Windows 11 licensing (docs/knowledge)

Windows 10/11 images on Azure are only for subscriptions with eligible licensing (multitenant hosting rights, typically
via a Microsoft 365 E3/E5/F3 or Windows VDA per-user license). The VM sets `license_type = "Windows_Client"` to match.
Without eligibility, creation may fail or you would be out of licence terms. The image SKU may also not be offered in
every region or on every subscription type (check with `az vm image list-skus` yourself if apply fails).

To use Windows Server instead (still has a desktop for RDP, but it is not a client OS, so toast behavior can differ):

```
-var image_publisher=MicrosoftWindowsServer -var image_offer=WindowsServer \
-var image_sku=2022-datacenter-azure-edition -var license_type=null
```

(`2025-datacenter-azure-edition` also exists.) Use `license_type=Windows_Server` only if you hold Software Assurance.

## Prerequisites

- Terraform >= 1.5 (validated with 1.5.0), and the Azure CLI.
- `az login`, then pick the subscription: `az account set --subscription <subscription id>`, or export
  `ARM_SUBSCRIPTION_ID=<subscription id>` (azurerm 4.x requires one), or pass `-var subscription_id=<subscription id>`.
- An SSH key pair (`ssh-keygen -t ed25519` if you have none).
- Your public IP: `curl -s https://ifconfig.me`

## Apply

```
cd infra/windows-test-vm
terraform init
terraform apply \
  -var 'allowed_source_cidrs=["<your ip>/32"]' \
  -var "ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"
```

Or copy `terraform.tfvars.example` to `terraform.tfvars` (gitignored) and run `terraform apply`. Other variables
(location, size, image, shutdown time, `ssh_default_shell`) are in `variables.tf`. Apply takes several minutes; the
extension (OpenSSH install) runs after the VM is up.

If you do not set `admin_password`, one is generated. It is only in the (sensitive) state and output:

```
terraform output -raw admin_password
```

Treat the local `terraform.tfstate` as a secret: it holds the password.

## Connect

1. Add the block from `terraform output -raw ssh_config` to `~/.ssh/config` (it uses `ssh_private_key_path_hint`, default
   `~/.ssh/id_ed25519`). Then `ssh aigw-win`. SSH accepts the key only; password login over SSH is off.
2. RDP: Microsoft Remote Desktop, host = `terraform output -raw public_ip`, user = `terraform output -raw admin_username`,
   password from `terraform output -raw admin_password`.

If your IP changes, re-run apply with the new `allowed_source_cidrs`.

## What the bootstrap does

`bootstrap.ps1` runs once as SYSTEM through the CustomScriptExtension. It is gzipped and base64-encoded into the
extension's `protected_settings` (not shown in the portal or extension status), together with the public key. It:

- installs the `OpenSSH.Server` Windows capability, sets `sshd` to Automatic and starts it, ensures the firewall rule
  for TCP 22;
- writes the key to `C:\ProgramData\ssh\administrators_authorized_keys` (the admin user is in Administrators) with
  `icacls /inheritance:r` granting only Administrators and SYSTEM;
- sets `PasswordAuthentication no` and `PubkeyAuthentication yes` in `sshd_config` and restarts `sshd`;
- sets the SSH default shell (`ssh_default_shell`: `powershell` = Windows PowerShell 5.1, the default, or `cmd`).

It is idempotent and logs to `C:\ProgramData\aigw-bootstrap\bootstrap.log` (never the key or password). If SSH does not
work after apply, RDP in with the password and read that log, or check the extension status in the portal.

The script then needs your own steps from `repro/WINDOWS.md` (Python, Claude Code, Git for Windows).

## Cost

Compute for a B2ms in a Western Europe region is on the order of a few cents per hour (docs/knowledge; check the pricing
page), plus the OS disk and the static public IP, which bill even while the VM is stopped. Auto-shutdown is on by default
at 19:00 UTC (`auto_shutdown_time`, `auto_shutdown_timezone`, `auto_shutdown_enabled`) and deallocates the VM; start it
again from the portal or `az vm start`. Destroy when you are done.

## Teardown

```
terraform destroy
```

(same `-var` flags, or the tfvars file). This deletes the resource group's resources that Terraform created and nothing
outside it.
