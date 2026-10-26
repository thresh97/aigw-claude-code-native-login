<#
.SYNOPSIS
  Installs aigw-claude-auth for all users of this PC (run elevated, Windows PowerShell 5.1).
.DESCRIPTION
  Writes, from the payload folder next to this script (built by packaging/build.py windows):
    <ProgramFiles>\aigw-claude-auth\   aigw_claude_auth.py, aigw_launch.py, config.json, task.xml, aigw-claude-auth.cmd
    <ProgramFiles>\ClaudeCode\managed-settings.d\50-<name>.json   Claude Code managed settings (drop-in)
  and registers the scheduled task "aigw-claude-auth-fleet": at log on of any member of the local Users group it
  runs the launcher, which does the per-user first run (install --no-hooks) and then the daemon, as that user.
  Nothing per user is touched here. An existing managed-settings.json is never modified.

  Why the drop-in file and not HKLM\SOFTWARE\Policies\ClaudeCode: Claude Code merges managed-settings.d\*.json on
  Windows like on the other platforms (docs), a file needs no registry write and is removed by deleting it, and it
  does not collide with an existing managed-settings.json. The registry value outranks files: if your
  organization already sets HKLM policy, the file is ignored (the first source with a policy key wins unless
  managedSourcesBehavior is "merge"); in that case deliver payload\50-<name>.json as the "Settings" value by GPO or
  Intune instead. `aigw-claude-auth doctor` shows which source wins.

  The Python interpreter named in fleet.txt (python\windows in the fleet file) must exist: Windows has no Python of
  its own. Ship one (python.org installer, or an embeddable build), or build a single binary. See packaging/README.md.
.PARAMETER Root
  Install under this folder instead of the real system folders (dry run on a test box). Implies -SkipTask unless
  -ForceTaskWithRoot is given. The managed settings still name the real Program Files paths.
.PARAMETER AddToPath
  Also add the install folder to the machine PATH, so `aigw-claude-auth login` works in any terminal.
.EXAMPLE
  .\Install-AigwClaudeAuth.ps1 -WhatIf
  .\Install-AigwClaudeAuth.ps1 -Root C:\aigw-h\root -SkipTask
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Root = '',
    [string]$PayloadDir = '',
    [switch]$SkipTask,
    [switch]$ForceTaskWithRoot,
    [switch]$AddToPath
)
$ErrorActionPreference = 'Stop'
$TaskName = 'aigw-claude-auth-fleet'
# not a param default: with powershell -File (Intune, ssh) $PSScriptRoot is still empty while defaults are evaluated (PS 5.1)
if (-not $PayloadDir) { $PayloadDir = Join-Path $PSScriptRoot 'payload' }

function Resolve-Target([string]$path) {
    if ($Root -eq '') { return $path }
    return Join-Path $Root ($path -replace '^[A-Za-z]:', '')
}

$info = @{}
Get-Content (Join-Path $PayloadDir 'fleet.txt') | ForEach-Object { $k, $v = $_ -split '=', 2; $info[$k] = $v }
$name = $info['name']
$python = $info['python']
$programFiles = 'C:\Program Files'
if ($env:ProgramFiles -ne $programFiles) {
    Write-Warning "ProgramFiles is $env:ProgramFiles; the rendered managed settings and task name $programFiles. Rebuild with the right paths."
}
$installDir = Resolve-Target (Join-Path $programFiles 'aigw-claude-auth')
$managedDir = Resolve-Target (Join-Path $programFiles 'ClaudeCode\managed-settings.d')
$managedFile = Join-Path $managedDir ("50-$name.json")

if ($Root -eq '' -and -not $WhatIfPreference) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { throw 'Run this script from an elevated PowerShell (or use -WhatIf / -Root for a dry run).' }
    if (-not (Test-Path -LiteralPath $python)) { throw "The Python interpreter $python does not exist; install it first or change python.windows in the fleet file and rebuild." }
}
elseif (-not (Test-Path -LiteralPath $python)) {
    Write-Warning "Python interpreter $python does not exist on this machine (not an error in a dry run)."
}

Write-Host "install dir:  $installDir"
Write-Host "managed file: $managedFile"

New-Item -ItemType Directory -Force -Path $installDir, $managedDir | Out-Null
foreach ($f in 'aigw_claude_auth.py', 'aigw_launch.py', 'config.json', 'task.xml') {
    Copy-Item -LiteralPath (Join-Path $PayloadDir $f) -Destination (Join-Path $installDir $f) -Force
}

# Managed settings drop-in; keep a copy of a different file that was there before (outside the folder's *.json glob)
$src = Join-Path $PayloadDir "50-$name.json"
if ((Test-Path -LiteralPath $managedFile) -and ((Get-FileHash $managedFile).Hash -ne (Get-FileHash $src).Hash)) {
    Copy-Item -LiteralPath $managedFile -Destination "$managedFile.bak" -Force
    Write-Host "kept the previous drop-in as $managedFile.bak"
}
Copy-Item -LiteralPath $src -Destination $managedFile -Force

# Command-line wrapper: the same interpreter, script and fleet config the hooks use
$cmd = "@`"$python`" `"$programFiles\aigw-claude-auth\aigw_claude_auth.py`" --config `"$programFiles\aigw-claude-auth\config.json`" %*`r`n"
if ($PSCmdlet.ShouldProcess((Join-Path $installDir 'aigw-claude-auth.cmd'), 'write wrapper')) {
    [IO.File]::WriteAllText((Join-Path $installDir 'aigw-claude-auth.cmd'), $cmd, [Text.Encoding]::ASCII)
}

if ($AddToPath) {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $real = Join-Path $programFiles 'aigw-claude-auth'
    if (($machine -split ';') -notcontains $real -and $Root -eq '') {
        if ($PSCmdlet.ShouldProcess('machine PATH', "add $real")) {
            [Environment]::SetEnvironmentVariable('Path', "$machine;$real", 'Machine')
        }
    }
}

if ($SkipTask -or ($Root -ne '' -and -not $ForceTaskWithRoot)) {
    Write-Host 'scheduled task: skipped'
}
elseif ($PSCmdlet.ShouldProcess("scheduled task $TaskName", 'register (at log on of any local Users member, run as that user)')) {
    $xml = Get-Content -LiteralPath (Join-Path $installDir 'task.xml') -Raw
    Register-ScheduledTask -TaskName $TaskName -Xml $xml -Force | Out-Null
    Write-Host "registered scheduled task $TaskName (it starts at each user's next log on)"
}

Write-Host 'Per user, at first log on: the task runs the launcher (install --no-hooks, then the daemon). The user signs in once:'
Write-Host '  aigw-claude-auth login      (or just starts Claude Code: with hook_login set, the first prompt shows the sign-in)'
