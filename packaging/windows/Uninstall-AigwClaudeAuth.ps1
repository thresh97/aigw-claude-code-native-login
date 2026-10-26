<#
.SYNOPSIS
  Removes what Install-AigwClaudeAuth.ps1 installed (run elevated, Windows PowerShell 5.1).
.DESCRIPTION
  Unregisters the scheduled task (stopping running daemons), removes the managed-settings drop-in, the install folder and
  the PATH entry. Per-user data stays unless -PurgeCurrentUser is given, which first runs the launcher's purge-user for the
  user running this script (forget the refresh token, remove our header lines, delete %APPDATA%\aigw-claude-auth). Other
  users keep an inert sentinel header line and their state folder: without the managed base URL and hooks nothing uses
  them; each user can delete %APPDATA%\aigw-claude-auth and the x-portkey-api-key / x-aigw-local lines.
.PARAMETER Name
  The fleet name used at build time (default aigw-claude-auth).
.PARAMETER Root
  Dry-run root, as for the installer.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Name = 'aigw-claude-auth',
    [string]$Root = '',
    [switch]$PurgeCurrentUser,
    [switch]$SkipTask
)
$ErrorActionPreference = 'Stop'
$TaskName = 'aigw-claude-auth-fleet'
function Resolve-Target([string]$path) {
    if ($Root -eq '') { return $path }
    return Join-Path $Root ($path -replace '^[A-Za-z]:', '')
}
$programFiles = 'C:\Program Files'
$installDir = Resolve-Target (Join-Path $programFiles 'aigw-claude-auth')
$managedDir = Resolve-Target (Join-Path $programFiles 'ClaudeCode\managed-settings.d')
$managedFile = Join-Path $managedDir ("50-$Name.json")

if ($PurgeCurrentUser -and (Test-Path -LiteralPath (Join-Path $installDir 'aigw_launch.py'))) {
    $python = (Get-Content (Join-Path $installDir 'aigw-claude-auth.cmd') -Raw) -replace '^@"([^"]+)".*$', '$1'
    if ($PSCmdlet.ShouldProcess($env:USERNAME, 'purge per-user data')) {
        & $python.Trim() (Join-Path $installDir 'aigw_launch.py') purge-user
    }
}

if (-not $SkipTask -and $Root -eq '') {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess("scheduled task $TaskName", 'stop and unregister')) {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
    }
}

if (Test-Path -LiteralPath $managedFile) { Remove-Item -LiteralPath $managedFile -Force }
if (Test-Path -LiteralPath "$managedFile.bak") { Write-Host "left $managedFile.bak (the drop-in this one replaced); restore or delete it by hand" }
if (Test-Path -LiteralPath $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force }
# remove the Claude Code folders only if we leave them empty (they may hold other managed settings)
foreach ($d in $managedDir, (Split-Path $managedDir -Parent)) {
    if ((Test-Path -LiteralPath $d) -and -not (Get-ChildItem -LiteralPath $d -Force)) { Remove-Item -LiteralPath $d -Force }
}

if ($Root -eq '') {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $real = Join-Path $programFiles 'aigw-claude-auth'
    if (($machine -split ';') -contains $real) {
        if ($PSCmdlet.ShouldProcess('machine PATH', "remove $real")) {
            [Environment]::SetEnvironmentVariable('Path', (($machine -split ';' | Where-Object { $_ -ne $real }) -join ';'), 'Machine')
        }
    }
}
if ($WhatIfPreference) { Write-Host "(WhatIf: nothing was removed)" } else { Write-Host "removed $Name" }
