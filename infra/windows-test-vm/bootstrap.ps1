# Runs as SYSTEM via CustomScriptExtension. Terraform prepends $PublicKeyB64 and $SshDefaultShell.
# Idempotent. Logs to C:\ProgramData\aigw-bootstrap\bootstrap.log; never logs the key.
$ErrorActionPreference = 'Stop'
$logDir = 'C:\ProgramData\aigw-bootstrap'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir 'bootstrap.log'
function Log($m) { Add-Content -Path $log -Value ("{0:u} {1}" -f (Get-Date), $m) }

try {
  Log 'start'
  $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
  if ($cap.State -ne 'Installed') {
    Log 'installing OpenSSH.Server'
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
  } else { Log 'OpenSSH.Server already installed' }

  # sshd generates host keys and its config on first start.
  Set-Service -Name sshd -StartupType Automatic
  Start-Service sshd
  Log 'sshd started'

  if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' `
      -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    Log 'firewall rule created'
  } else { Log 'firewall rule exists' }

  $key = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PublicKeyB64)).Trim()
  $akFile = 'C:\ProgramData\ssh\administrators_authorized_keys'
  $existing = if (Test-Path $akFile) { @(Get-Content -Path $akFile) } else { @() }
  if ($existing -notcontains $key) {
    Add-Content -Path $akFile -Value $key -Encoding ascii
    Log 'authorized key added'
  } else { Log 'authorized key already present' }
  & icacls.exe $akFile /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls failed: $LASTEXITCODE" }

  $cfg = 'C:\ProgramData\ssh\sshd_config'
  $lines = @(Get-Content -Path $cfg)
  $lines = @($lines | Where-Object { $_ -notmatch '^\s*#?\s*(PasswordAuthentication|PubkeyAuthentication)\s' })
  # Global options must come before any Match block, so put them at the top.
  $lines = @('PasswordAuthentication no', 'PubkeyAuthentication yes') + $lines
  Set-Content -Path $cfg -Value $lines -Encoding ascii
  Log 'sshd_config updated'

  $shellKey = 'HKLM:\SOFTWARE\OpenSSH'
  if (-not (Test-Path $shellKey)) { New-Item -Path $shellKey -Force | Out-Null }
  if ($SshDefaultShell -eq 'cmd') {
    $shell = 'C:\Windows\System32\cmd.exe'
  } else {
    $shell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
  }
  New-ItemProperty -Path $shellKey -Name DefaultShell -Value $shell -PropertyType String -Force | Out-Null
  Log "default shell set to $SshDefaultShell"

  Restart-Service sshd
  Log 'sshd restarted; done'
} catch {
  Log ('ERROR: ' + $_.Exception.Message)
  exit 1
}
