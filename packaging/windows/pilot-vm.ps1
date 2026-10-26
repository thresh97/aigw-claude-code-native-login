<#
.SYNOPSIS
  Emulated pilot of the Windows fleet package on a disposable test VM (run elevated, Windows PowerShell 5.1).
  Driven phase by phase from packaging/windows/pilot-ssh.sh; each phase is one call and prints CHECK lines.
.DESCRIPTION
  DISPOSABLE VM ONLY. It installs into the real C:\Program Files, creates two local users (pilot1, pilot2) with random
  passwords that exist only in memory and, briefly, in the Winlogon autologon values, and reboots the machine to get a
  real interactive logon for each. It never signs in to the IdP and never starts Claude Code.

  Phases:
    install     checks (no HKLM\SOFTWARE\Policies\ClaudeCode key), runs Install-AigwClaudeAuth.ps1, checks files, the drop-in
                and the scheduled task principal
    logon-prep  creates the user if needed, sets a fresh random password, sets Winlogon autologon (one logon) and reboots
    check       removes the autologon values first, waits for the logon and the task, then reads the user's files,
                runs doctor --json in that user's own session, and in proxy mode looks at the listening port
    concurrent  with a user already logged on: starts the launcher daemon as another user (CreateProcessWithLogonW, not a
                task-triggered logon) and reports what the fixed loopback port does
    uninstall   per-user leftovers, per-user purge, Uninstall-AigwClaudeAuth.ps1, nothing-left checks
    cleanup     removes pilot1/pilot2 with their profiles, restores/removes the Winlogon values, removes $Work
  State (users created, the Winlogon values found) is kept in $Work\state.json. Output also goes to $Work\out\.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('install', 'logon-prep', 'check', 'concurrent', 'uninstall', 'cleanup')][string]$Phase,
    [ValidateSet('file', 'proxy')][string]$Mode = 'file',
    [string]$User = '',
    [string]$Work = 'C:\aigw-pilot',
    [string]$Dist = (Join-Path $Work 'dist'),
    [string]$Python = 'C:\Program Files\Python313\python.exe',
    [int]$ProxyPort = 18787,
    [int]$WaitSeconds = 420
)
$ErrorActionPreference = 'Stop'
$TaskName = 'aigw-claude-auth-fleet'
$FleetName = 'aigw-claude-auth'
$InstallDir = 'C:\Program Files\aigw-claude-auth'
$ManagedDir = 'C:\Program Files\ClaudeCode\managed-settings.d'
$DropIn = Join-Path $ManagedDir "50-$FleetName.json"
$Winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$Out = Join-Path $Work 'out'
$StateFile = Join-Path $Work 'state.json'
New-Item -ItemType Directory -Force -Path $Work, $Out | Out-Null

function Say([string]$m) {
    Write-Host $m
    Add-Content -LiteralPath (Join-Path $Out "log-$Mode.txt") -Value $m -ErrorAction SilentlyContinue
}
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    Say ("CHECK {0}={1}{2}" -f $name, $(if ($ok) { 'ok' } else { 'FAIL' }), $(if ($detail) { " ($detail)" } else { '' }))
}
function Fp([string]$s) {          # length and a short hash, never the value
    $h = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($s))
    return ('len{0}/{1}' -f $s.Length, (($h[0..3] | ForEach-Object { $_.ToString('x2') }) -join ''))
}
function Load-State {
    if (Test-Path -LiteralPath $StateFile) { return Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json }
    return [pscustomobject]@{ createdUsers = @(); winlogon = $null }
}
function Save-State($s) { $s | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StateFile -Encoding UTF8 }
function New-RandomPassword {
    $b = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return ([Convert]::ToBase64String($b) -replace '[^A-Za-z0-9]', 'x') + 'aZ9!'
}
function UserProfilePath([string]$u) {
    $sid = (Get-LocalUser -Name $u).SID.Value
    $p = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }
    if ($p) { return $p.LocalPath }
    return $null
}
function Get-Sessions {            # quser exits 1 and writes to stderr when nobody is logged on
    $ErrorActionPreference = 'Continue'
    return @((& quser.exe 2>&1 | Out-String) -split "`r?`n")
}
function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Winlogon-Read {
    $key = Get-Item $Winlogon
    $o = @{}
    foreach ($n in 'AutoAdminLogon', 'DefaultUserName', 'DefaultDomainName', 'DefaultPassword', 'AutoLogonCount', 'ForceAutoLogon') {
        $v = $key.GetValue($n, $null)
        if ($null -ne $v) { $o[$n] = @{ value = "$v"; kind = "$($key.GetValueKind($n))" } }
    }
    return $o
}
function Winlogon-Restore {          # puts back what logon-prep found; DefaultPassword is never written back
    $st = Load-State
    $orig = $st.winlogon
    foreach ($n in 'AutoAdminLogon', 'DefaultUserName', 'DefaultDomainName', 'DefaultPassword', 'AutoLogonCount', 'ForceAutoLogon') {
        $had = $null -ne $orig -and $null -ne $orig.PSObject.Properties[$n] -and $n -ne 'DefaultPassword'
        if ($had) {
            $e = $orig.$n
            if ($e.kind -eq 'DWord') { Set-ItemProperty -Path $Winlogon -Name $n -Value ([int]$e.value) -Type DWord }
            else { Set-ItemProperty -Path $Winlogon -Name $n -Value $e.value -Type String }
        }
        else { Remove-ItemProperty -Path $Winlogon -Name $n -ErrorAction SilentlyContinue }
    }
}
function Winlogon-Clean {
    $now = Winlogon-Read
    return (-not $now.ContainsKey('DefaultPassword'))
}

# Run a script in the user's own interactive session through a one-shot task (needs that user logged on).
function Invoke-AsUser([string]$u, [string]$tag, [string]$scriptText) {
    $ps1 = Join-Path $Work "run-$u-$tag.ps1"
    $outFile = Join-Path $Out "as-$u-$tag.txt"
    Remove-Item -LiteralPath $outFile -ErrorAction SilentlyContinue
    Set-Content -LiteralPath $ps1 -Value ('$ErrorActionPreference = "Continue"' + "`r`n" + $scriptText + "`r`n") -Encoding UTF8
    $tn = "aigw-pilot-run-$u"
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& '$ps1' *> '$outFile'`""
    $pr = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$u" -LogonType Interactive
    Register-ScheduledTask -TaskName $tn -Action $act -Principal $pr -Force | Out-Null
    try {
        Start-ScheduledTask -TaskName $tn
        $end = (Get-Date).AddSeconds(150)
        do { Start-Sleep -Seconds 2 } while ((Get-ScheduledTask -TaskName $tn).State -eq 'Running' -and (Get-Date) -lt $end)
        $info = Get-ScheduledTaskInfo -TaskName $tn
        Say ("as-user {0}/{1}: task result {2}" -f $u, $tag, $info.LastTaskResult)
    }
    finally { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $outFile) { return (Get-Content -LiteralPath $outFile -Raw) }
    return ''
}

function Describe-UserFiles([string]$u) {
    $prof = UserProfilePath $u
    $r = @{ profile = $prof; settings = $null; header = @(); env = @() }
    if (-not $prof) { return $r }
    $sf = Join-Path $prof '.claude\settings.json'
    $r.settings = $sf
    if (Test-Path -LiteralPath $sf) {
        $j = Get-Content -LiteralPath $sf -Raw | ConvertFrom-Json
        $r.exists = $true
        if ($j.PSObject.Properties['env']) {
            $r.env = @($j.env.PSObject.Properties.Name)
            $h = $j.env.PSObject.Properties['ANTHROPIC_CUSTOM_HEADERS']
            if ($h) { $r.header = @(($h.Value -split "`n") | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }) }
        }
        $r.hooks = [bool]$j.PSObject.Properties['hooks']
    }
    else { $r.exists = $false }
    return $r
}
function Header-Summary($lines) {      # name and a fingerprint of the value; a JWT is recognised and never shown
    $o = @()
    foreach ($l in $lines) {
        $n, $v = $l -split ':\s*', 2
        $o += ('{0}[{1}{2}]' -f $n, (Fp $v), $(if ($v -like 'eyJ*') { ',JWT' } else { '' }))
    }
    return ($o -join '; ')
}

# ---------------------------------------------------------------------------------------------------------
function Phase-Install {
    Check 'elevated' (Test-Admin)
    if (-not (Test-Admin)) { throw 'not elevated' }
    if (Test-Path 'HKLM:\SOFTWARE\Policies\ClaudeCode') {
        Say 'STOP: HKLM\SOFTWARE\Policies\ClaudeCode exists; not touching it. Report this.'
        exit 3
    }
    Check 'no-hklm-claudecode-policy' $true
    Check 'no-existing-install' (-not (Test-Path -LiteralPath $InstallDir) -and -not (Test-Path -LiteralPath $DropIn) -and -not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) 'refusing to overwrite an earlier install'
    $installer = Join-Path $Dist 'Install-AigwClaudeAuth.ps1'
    Check 'dist-present' (Test-Path -LiteralPath $installer)
    Check 'python-present' (Test-Path -LiteralPath $Python)
    $before = @{}
    $userSettings = 'C:\Users\' + $env:USERNAME + '\.claude\settings.json'
    if (Test-Path -LiteralPath $userSettings) { $before.admin = (Get-FileHash -LiteralPath $userSettings).Hash }
    Set-Content -LiteralPath (Join-Path $Work 'admin-settings-hash.txt') -Value ($before.admin)
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer 2>&1 | ForEach-Object { Say "  installer: $_" }
    Check 'installer-exit' ($LASTEXITCODE -eq 0) "exit $LASTEXITCODE"
    foreach ($f in 'aigw_claude_auth.py', 'aigw_launch.py', 'config.json', 'task.xml', 'aigw-claude-auth.cmd') {
        Check "file:$f" (Test-Path -LiteralPath (Join-Path $InstallDir $f))
    }
    Check 'file:dropin' (Test-Path -LiteralPath $DropIn)
    $raw = Get-Content -LiteralPath $DropIn -Raw
    $j = $null
    try { $j = $raw | ConvertFrom-Json; Check 'dropin-valid-json' $true } catch { Check 'dropin-valid-json' $false $_.Exception.Message }
    if ($j) {
        Check 'dropin-no-custom-headers' (-not ($raw -match 'ANTHROPIC_CUSTOM_HEADERS'))
        Check 'dropin-mode' ($j.env.AIGW_MODE -eq $Mode -or ($Mode -eq 'file' -and -not $j.env.AIGW_MODE)) "AIGW_MODE=$($j.env.AIGW_MODE)"
        Check 'dropin-hooks' ($j.hooks.PSObject.Properties.Name -contains 'UserPromptSubmit' -and $j.hooks.PSObject.Properties.Name -contains 'StopFailure')
        if ($Mode -eq 'proxy') { Check 'dropin-base-url-is-loopback' ($j.env.ANTHROPIC_BASE_URL -eq "http://127.0.0.1:$ProxyPort") }
    }
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Check 'task-registered' ($null -ne $t)
    if ($t) {
        $p = $t.Principal
        Say ("  task principal: GroupId={0} UserId={1} LogonType={2} RunLevel={3}" -f $p.GroupId, $p.UserId, $p.LogonType, $p.RunLevel)
        Check 'task-principal-users-group' ($p.GroupId -eq 'S-1-5-32-545' -or $p.GroupId -eq 'BUILTIN\Users' -or $p.GroupId -eq 'Users') "GroupId=$($p.GroupId)"
        Say ("  task trigger: {0}; state {1}; multiple-instances {2}" -f ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }), $t.State, $t.Settings.MultipleInstances)
    }
    $acl = (Get-Acl -LiteralPath $InstallDir).Access | Where-Object { $_.FileSystemRights -match 'Write|Modify|FullControl' -and $_.IdentityReference -match 'Users|Everyone' -and $_.IdentityReference -notmatch 'Administrators|SYSTEM|TrustedInstaller' }
    Check 'install-dir-not-user-writable' (-not $acl) 'the install dir runs code for every user'
    $acl2 = (Get-Acl -LiteralPath $DropIn).Access | Where-Object { $_.FileSystemRights -match 'Write|Modify|FullControl' -and $_.IdentityReference -match 'Users|Everyone' -and $_.IdentityReference -notmatch 'Administrators|SYSTEM|TrustedInstaller' }
    Check 'dropin-not-user-writable' (-not $acl2)
    icacls $Work /grant 'Users:(OI)(CI)M' | Out-Null     # lets the pilot users' one-shot tasks write their output
}

function Phase-LogonPrep {
    if (-not $User) { throw '-User required' }
    $st = Load-State
    if ($null -eq $st.winlogon) { $st.winlogon = Winlogon-Read }
    $pw = New-RandomPassword
    $sec = ConvertTo-SecureString $pw -AsPlainText -Force
    $existing = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-LocalUser -Name $User -Password $sec -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword -Description 'aigw pilot' | Out-Null
        Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545') -Member $User -ErrorAction SilentlyContinue
        $st.createdUsers = @($st.createdUsers) + $User
        Say "created local user $User (standard user, Users group)"
    }
    else {
        if (@($st.createdUsers) -notcontains $User) { throw "$User exists and was not created by this pilot; not touching it" }
        Set-LocalUser -Name $User -Password $sec
    }
    Check "member-of-Users:$User" ((Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object { $_.Name -like "*\$User" }) -ne $null)
    Check "not-admin:$User" (-not (Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.Name -like "*\$User" }))
    Save-State $st
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $lastBefore = if ($t) { (Get-ScheduledTaskInfo -TaskName $TaskName).LastRunTime } else { $null }
    Set-Content -LiteralPath (Join-Path $Work "lastrun-before-$User.txt") -Value $lastBefore
    Set-ItemProperty -Path $Winlogon -Name AutoAdminLogon -Value '1' -Type String
    Set-ItemProperty -Path $Winlogon -Name DefaultUserName -Value $User -Type String
    Set-ItemProperty -Path $Winlogon -Name DefaultDomainName -Value $env:COMPUTERNAME -Type String
    Set-ItemProperty -Path $Winlogon -Name DefaultPassword -Value $pw -Type String
    Set-ItemProperty -Path $Winlogon -Name AutoLogonCount -Value 1 -Type DWord
    $pw = $null
    Say "autologon set for $User (one logon); rebooting in 5 s"
    & shutdown.exe /r /t 5 /f /c 'aigw pilot: autologon' | Out-Null
}

function Phase-Check {
    if (-not $User) { throw '-User required' }
    # 1. the autologon values go first
    Winlogon-Restore
    Check 'autologon-DefaultPassword-removed' (Winlogon-Clean)
    $w = Winlogon-Read
    Say ("  winlogon now: AutoAdminLogon={0} DefaultUserName={1} DefaultPassword={2}" -f ($w['AutoAdminLogon'].value), ($w['DefaultUserName'].value), $(if ($w.ContainsKey('DefaultPassword')) { 'PRESENT' } else { 'absent' }))
    # 2. the interactive logon
    $end = (Get-Date).AddSeconds($WaitSeconds)
    $logged = $false
    do {
        $q = (Get-Sessions) -join "`n"
        if ($q -match "(?m)^\s*>?$User\s") { $logged = $true } else { Start-Sleep -Seconds 5 }
    } while (-not $logged -and (Get-Date) -lt $end)
    Say ("  quser: " + (($q -split "`r?`n" | Where-Object { $_ -match $User }) -join ' | '))
    Check "interactive-logon:$User" $logged
    if (-not $logged) { return }
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    # 3. the task fired
    $info = $null
    do {
        Start-Sleep -Seconds 5
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
    } while (($info.LastRunTime -lt $boot) -and (Get-Date) -lt $end)
    $t = Get-ScheduledTask -TaskName $TaskName
    Say ("  task: State={0} LastRunTime={1:u} LastTaskResult={2} (boot {3:u})" -f $t.State, $info.LastRunTime, $info.LastTaskResult, $boot)
    Check "task-fired-after-logon:$User" ($info.LastRunTime -ge $boot)
    Check "task-last-result:$User" ($info.LastTaskResult -eq 267009 -or $info.LastTaskResult -eq 0) ('0x{0:x} (0x41301 = still running = the daemon)' -f $info.LastTaskResult)
    # who runs the daemon
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*aigw_launch.py*' }
    $owners = @($procs | ForEach-Object { $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner; "{0}\{1}:{2}" -f $o.Domain, $o.User, $_.Name })
    Say ("  launcher processes: " + ($owners -join ', '))
    Check "daemon-runs-as-user:$User" (@($owners | Where-Object { $_ -like "*\${User}:*" }).Count -ge 1)
    # 4. the files the launcher's first run wrote
    $f = Describe-UserFiles $User
    Say ("  profile: {0}" -f $f.profile)
    Check "user-settings-written:$User" ([bool]$f.exists) $f.settings
    if ($f.exists) {
        Say ("  user settings env keys: " + ($f.env -join ','))
        Say ("  user settings header lines: " + (Header-Summary $f.header))
        Check "user-settings-no-hooks:$User" (-not $f.hooks) 'hooks come from managed settings'
        if ($Mode -eq 'file') { Check "user-settings-no-base-url:$User" ($f.env -notcontains 'ANTHROPIC_BASE_URL') 'the base URL comes from managed settings' }
        else {
            $bu = (Get-Content -LiteralPath $f.settings -Raw | ConvertFrom-Json).env.ANTHROPIC_BASE_URL
            Check "user-settings-base-url-is-the-proxy:$User" ($bu -eq "http://127.0.0.1:$ProxyPort") 'proxy mode also writes the loopback address'
        }
        $names = @($f.header | ForEach-Object { ($_ -split ':', 2)[0].Trim().ToLower() })
        if ($Mode -eq 'file') {
            Check "file-mode-only-portkey-sentinel:$User" ($names.Count -eq 1 -and $names[0] -eq 'x-portkey-api-key' -and -not ($f.header[0] -like '*eyJ*'))
        }
        else {
            Check "proxy-mode-x-aigw-local-no-jwt:$User" ($names -contains 'x-aigw-local' -and -not ($f.header -join ' ' -like '*eyJ*') -and $names -notcontains 'x-portkey-api-key')
            $sec = ($f.header | Where-Object { $_ -like 'x-aigw-local*' } | Select-Object -First 1)
            if ($sec) {
                $v = ($sec -split ':\s*', 2)[1]
                Set-Content -LiteralPath (Join-Path $Out "secret-fp-$User-$(Get-Date -Format HHmmss).txt") -Value (Fp $v)
            }
        }
        $cd = Join-Path $f.profile 'AppData\Roaming\aigw-claude-auth'
        Say ("  state dir {0}: {1}" -f $cd, ((Get-ChildItem -LiteralPath $cd -Force -ErrorAction SilentlyContinue | ForEach-Object Name) -join ','))
        $ld = Join-Path $f.profile 'AppData\Local\aigw-claude-auth\logs'
        foreach ($lf in Get-ChildItem -LiteralPath $ld -Force -ErrorAction SilentlyContinue) {
            Say ("  log {0} ({1} bytes), last lines:" -f $lf.Name, $lf.Length)
            Get-Content -LiteralPath $lf.FullName -Tail 6 | ForEach-Object { Say "    | $_" }
        }
    }
    # 5. the proxy port
    if ($Mode -eq 'proxy') {
        $c = Get-NetTCPConnection -LocalPort $ProxyPort -State Listen -ErrorAction SilentlyContinue
        Check "proxy-listening:$User" ($null -ne $c) "127.0.0.1:$ProxyPort"
        foreach ($x in $c) {
            $pp = Get-CimInstance Win32_Process -Filter "ProcessId=$($x.OwningProcess)"
            $o = Invoke-CimMethod -InputObject $pp -MethodName GetOwner
            Say ("  port {0} listener: {1} bind {2} owner {3}\{4}" -f $ProxyPort, $pp.Name, $x.LocalAddress, $o.Domain, $o.User)
        }
    }
    # 6. doctor in the user's own session
    $py = $Python
    $doc = Invoke-AsUser $User 'doctor' ("& '$py' '$InstallDir\aigw_claude_auth.py' --config '$InstallDir\config.json' doctor --json")
    $rep = $null
    try { $rep = $doc | ConvertFrom-Json } catch { Say "  doctor output did not parse; first 300 chars: $($doc.Substring(0, [Math]::Min(300, $doc.Length)))" }
    Check "doctor-ran-as-user:$User" ($null -ne $rep)
    if ($rep) {
        Say ("  doctor: version {0}, {1} error(s), {2} warning(s), jwt={3}" -f $rep.version, $rep.errors, $rep.warnings, $rep.sources.jwt)
        Say ("  doctor sources: mode={0} managed={1} user_settings_exists={2}" -f $rep.sources.mode, $rep.sources.managed.winning_source, $rep.sources.user_settings.exists)
        Check "doctor-no-errors:$User" ($rep.errors -eq 0)
        foreach ($fi in $rep.findings) { Say ("    [{0}] {1}: {2}" -f $fi.severity, $fi.id, $fi.message) }
    }
    $who = Invoke-AsUser $User 'whoami' 'whoami; $env:USERPROFILE; $env:APPDATA'
    Say ("  whoami in the user's session: " + (($who -split "`r?`n" | Where-Object { $_ }) -join ' | '))
    # the admin's own settings must be untouched by the group-principal task
    $adminSettings = 'C:\Users\' + $env:USERNAME + '\.claude\settings.json'
    $h0 = (Get-Content -LiteralPath (Join-Path $Work 'admin-settings-hash.txt') -ErrorAction SilentlyContinue)
    $h1 = if (Test-Path -LiteralPath $adminSettings) { (Get-FileHash -LiteralPath $adminSettings).Hash } else { $null }
    Check 'admin-settings-untouched' ("$h0" -eq "$h1")
}

function Phase-Concurrent {
    # A second interactive user cannot be had here (one autologon; Start-Process -Credential from ssh dies with 0xC0000142 and
    # a password task fails with "logon type not granted" for a standard user). So this starts the same launcher a second time
    # as the admin, with its settings and state redirected to a throwaway folder, while the logged-on user's daemon holds the
    # fixed port: the bind does not depend on who owns the process. It also starts the fleet task by hand while its
    # instance is running, which tests MultipleInstancesPolicy IgnoreNew.
    function Listeners {
        foreach ($x in @(Get-NetTCPConnection -LocalPort $ProxyPort -State Listen -ErrorAction SilentlyContinue)) {
            $pp = Get-CimInstance Win32_Process -Filter "ProcessId=$($x.OwningProcess)"
            $o = Invoke-CimMethod -InputObject $pp -MethodName GetOwner
            Say ("    listener {0}:{1} pid {2} owner {3}" -f $x.LocalAddress, $ProxyPort, $x.OwningProcess, $o.User)
        }
    }
    function Launchers {
        $procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*aigw_launch.py*' }
        Say ("    launcher processes: " + (($procs | ForEach-Object { $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner; "$($o.User):pid$($_.ProcessId)" }) -join ', '))
    }
    Say '  before:'; Listeners; Launchers
    $scratch = Join-Path $Work 'second-launcher'
    New-Item -ItemType Directory -Force -Path $scratch | Out-Null
    $env:AIGW_CLAUDE_AUTH_DIR = Join-Path $scratch 'state'
    $env:AIGW_CLAUDE_SETTINGS = Join-Path $scratch 'settings.json'
    $env:CLAUDE_CONFIG_DIR = $scratch
    try {
        $p = Start-Process -FilePath $Python -ArgumentList "`"$InstallDir\aigw_launch.py`"", 'daemon' -PassThru -WindowStyle Hidden -RedirectStandardError "$Out\second.err" -RedirectStandardOutput "$Out\second.out"
    }
    finally { Remove-Item Env:AIGW_CLAUDE_AUTH_DIR, Env:AIGW_CLAUDE_SETTINGS, Env:CLAUDE_CONFIG_DIR -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 12
    Say ("  second launcher (pid {0}): {1}" -f $p.Id, $(if ($p.HasExited) { "exited with $($p.ExitCode)" } else { 'still running' }))
    foreach ($fn in 'second.err', 'second.out') {
        Say "  --- $fn"
        Get-Content -LiteralPath (Join-Path $Out $fn) -ErrorAction SilentlyContinue | Select-Object -First 12 | ForEach-Object { Say "    | $_" }
    }
    Say '  after the second launcher:'; Listeners
    if ($Mode -eq 'proxy') { Check 'port-still-held-by-first' (@(Get-NetTCPConnection -LocalPort $ProxyPort -State Listen -ErrorAction SilentlyContinue).Count -ge 1) }
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    # the fleet task started by hand while a user's instance runs
    $before = @(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*aigw_launch.py*' }).Count
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Continue
    Start-Sleep -Seconds 8
    $after = @(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*aigw_launch.py*' }).Count
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    Say ("  Start-ScheduledTask while an instance runs: launcher processes {0} -> {1}; task State={2} LastRunTime={3:u} LastTaskResult=0x{4:x}" -f $before, $after, (Get-ScheduledTask -TaskName $TaskName).State, $info.LastRunTime, $info.LastTaskResult)
    Launchers
}

function Phase-Uninstall {
    $users = @((Load-State).createdUsers)
    $leftBefore = @{}
    foreach ($u in $users) {
        $prof = UserProfilePath $u
        if (-not $prof) { continue }
        $items = @()
        if (Test-Path -LiteralPath "$prof\AppData\Roaming\aigw-claude-auth") { $items += 'state-dir' }
        if (Test-Path -LiteralPath "$prof\AppData\Local\aigw-claude-auth") { $items += 'log-dir' }
        $f = Describe-UserFiles $u
        if ($f.exists -and $f.header.Count) { $items += ('header-lines:' + (($f.header | ForEach-Object { ($_ -split ':', 2)[0] }) -join '+')) }
        $leftBefore[$u] = $items
        Say ("  per-user before uninstall, {0}: {1}" -f $u, ($items -join ', '))
    }
    # the daemons keep files open: the uninstaller unregisters the task, which stops the running instances
    $un = Join-Path $Dist 'Uninstall-AigwClaudeAuth.ps1'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $un 2>&1 | ForEach-Object { Say "  uninstaller: $_" }
    Check 'uninstaller-exit' ($LASTEXITCODE -eq 0) "exit $LASTEXITCODE"
    Check 'gone:task' (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue))
    Check 'gone:dropin' (-not (Test-Path -LiteralPath $DropIn))
    Check 'gone:install-dir' (-not (Test-Path -LiteralPath $InstallDir))
    Check 'gone:claudecode-dir' (-not (Test-Path -LiteralPath 'C:\Program Files\ClaudeCode')) 'removed only if the uninstaller left it empty'
    Start-Sleep -Seconds 3
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*aigw_launch.py*' }
    Check 'gone:daemon-processes' (-not $procs) $(if ($procs) { "still running: $(@($procs).Count) (task unregistered but instance not stopped)" } else { '' })
    Say ('  per-user after the machine-wide uninstall (the documented default: untouched): ' + (($users | ForEach-Object { "$_=" + ((Describe-UserFiles $_).header.Count) + ' header line(s)' }) -join ', '))
}

function Phase-Purge {              # per-user purge as a user would run it, using the packaged launcher (before uninstall)
    if (-not $User) { throw '-User required' }
    $f0 = Describe-UserFiles $User
    Say ("  per-user before purge, {0}: state-dir={1} header-lines={2}" -f $User, (Test-Path -LiteralPath "$($f0.profile)\AppData\Roaming\aigw-claude-auth"), $f0.header.Count)
    $purgeOut = Invoke-AsUser $User 'purge' ("& '$Python' '$InstallDir\aigw_launch.py' purge-user 2>&1")
    Say ("  purge-user as {0}: {1}" -f $User, (($purgeOut -split "`r?`n" | Where-Object { $_ }) -join ' | '))
    $f = Describe-UserFiles $User
    $left = @()
    if (Test-Path -LiteralPath "$($f.profile)\AppData\Roaming\aigw-claude-auth") { $left += 'state-dir' }
    if ($f.exists) { $left += ('header-lines:' + $f.header.Count) }
    Say ("  per-user after purge, {0}: {1}" -f $User, $(if ($left) { $left -join ', ' } else { 'nothing of ours' }))
    Check "purged:$User" ($left.Count -eq 0 -or ($left.Count -eq 1 -and $left[0] -eq 'header-lines:0'))
}

function Phase-Cleanup {
    $st = Load-State
    Winlogon-Restore
    Check 'winlogon-DefaultPassword-absent' (Winlogon-Clean)
    Check 'winlogon-restored' ((Winlogon-Read).ContainsKey('AutoAdminLogon') -eq ($null -ne $st.winlogon -and $null -ne $st.winlogon.PSObject.Properties['AutoAdminLogon']))
    foreach ($u in @($st.createdUsers)) {
        $lu = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
        $sid = if ($lu) { $lu.SID.Value } else { '' }
        # a profile that is loaded cannot be removed: log the user off first
        foreach ($l in (Get-Sessions)) {
            if ($l -match "^\s*>?$u\s+(\S+\s+)?(\d+)\s") { Say "  logging off $u (session $($Matches[2]))"; & logoff.exe $Matches[2] }
        }
        for ($i = 0; $i -lt 30 -and ((Get-Sessions) -match "^\s*>?$u\s"); $i++) { Start-Sleep -Seconds 2 }
        Get-CimInstance Win32_UserProfile | Where-Object { ($sid -and $_.SID -eq $sid) -or $_.LocalPath -eq "C:\Users\$u" } | Remove-CimInstance -ErrorAction Continue
        if ($lu) { Remove-LocalUser -Name $u }
        Check "removed-user:$u" (-not (Get-LocalUser -Name $u -ErrorAction SilentlyContinue))
        Check "removed-profile:$u" (-not (Test-Path -LiteralPath "C:\Users\$u"))
    }
    Get-ScheduledTask -TaskName 'aigw-pilot-run-*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
}

switch ($Phase) {
    'install' { Phase-Install }
    'logon-prep' { Phase-LogonPrep }
    'check' { Phase-Check }
    'concurrent' { Phase-Concurrent }
    'uninstall' { if ($User) { Phase-Purge } else { Phase-Uninstall } }
    'cleanup' { Phase-Cleanup }
}
