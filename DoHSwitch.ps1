#Requires -Version 5.1
<#
.SYNOPSIS
    DoHSwitch - network-aware Secure DNS (DNS-over-HTTPS) switcher for Google Chrome.

.DESCRIPTION
    Copy config.example.json to config.json and fill office.match before first use.

    Office network  -> DnsOverHttpsMode = automatic, DnsOverHttpsTemplates removed
                       (Chrome UI: "With your current service provider" / OS default when available)
    Outside office  -> DnsOverHttpsMode = secure, DnsOverHttpsTemplates = Google Public DNS
                       (Chrome UI: "With Google (Public DNS)")

    Policies are written to the Chrome policy registry key (HKCU by default, HKLM with -Scope Machine).
    Both locations live under ...\SOFTWARE\Policies, which a normal user can only read, so
    -Apply, -Reset, -InstallTask and -UninstallTask must run from an elevated PowerShell.
    -Status and -DryRun work without elevation.
    Chrome reloads registry policies automatically; no restart required.
    Uses only built-in Windows PowerShell 5.1 cmdlets. No external modules.

.PARAMETER Apply
    Detect the network and write the matching policy. Default action.
.PARAMETER Force
    Skip detection: Office or Outside. Default Auto.
.PARAMETER Status
    Show network facts, detection result, current policies and last state.
.PARAMETER Reset
    Remove the DoH policy values so Chrome returns to user control.
.PARAMETER InstallTask
    Register a Scheduled Task that runs -Apply at logon (30 s delay).
.PARAMETER OnNetworkChange
    With -InstallTask: also register an event-triggered task on network profile connect (Event ID 10000).
.PARAMETER UninstallTask
    Remove the scheduled tasks.
.PARAMETER ConfigPath
    Path to config.json. Default: config.json next to this script.
.PARAMETER Scope
    User (HKCU, default) or Machine (HKLM, needs admin). Overrides config.
.PARAMETER DryRun
    Print what would change without writing the registry.

.EXAMPLE
    .\DoHSwitch.ps1 -Apply
.EXAMPLE
    .\DoHSwitch.ps1 -Status
.EXAMPLE
    .\DoHSwitch.ps1 -Apply -Force Outside -DryRun
.EXAMPLE
    .\DoHSwitch.ps1 -InstallTask -OnNetworkChange
#>
[CmdletBinding(DefaultParameterSetName = 'Apply')]
param(
    [Parameter(ParameterSetName = 'Apply')]
    [switch]$Apply,

    [Parameter(ParameterSetName = 'Apply')]
    [ValidateSet('Auto', 'Office', 'Outside')]
    [string]$Force = 'Auto',

    [Parameter(ParameterSetName = 'Status')]
    [switch]$Status,

    [Parameter(ParameterSetName = 'Reset')]
    [switch]$Reset,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$InstallTask,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$OnNetworkChange,

    [Parameter(ParameterSetName = 'Uninstall')]
    [switch]$UninstallTask,

    [string]$ConfigPath,

    [ValidateSet('User', 'Machine')]
    [string]$Scope,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$script:ScriptRoot    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:ScriptPath    = Join-Path $script:ScriptRoot 'DoHSwitch.ps1'
$script:LogDir        = Join-Path $script:ScriptRoot 'logs'
$script:LogPath       = Join-Path $script:LogDir 'dohswitch.log'
$script:StatePath     = Join-Path $script:ScriptRoot 'state.json'
$script:LogMaxBytes   = 1048576
$script:TaskLogon     = 'DoHSwitch-AtLogon'
$script:TaskNetChange = 'DoHSwitch-NetworkChange'
$script:PolicyModeName      = 'DnsOverHttpsMode'
$script:PolicyTemplatesName = 'DnsOverHttpsTemplates'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Get-Prop {
    <# Safe property read under StrictMode: returns $Default when the property is missing or null. #>
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
    param(
        [ValidateSet('INFO', 'WARN', 'ERROR')] [string]$Level = 'INFO',
        [Parameter(Mandatory)] [string]$Message
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try {
        if (-not (Test-Path $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null }
        if ((Test-Path $script:LogPath) -and (Get-Item $script:LogPath).Length -gt $script:LogMaxBytes) {
            Move-Item -Path $script:LogPath -Destination ($script:LogPath + '.1') -Force
        }
        Add-Content -Path $script:LogPath -Value $line -Encoding UTF8
    } catch { }
    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
function Get-DefaultConfig {
    [pscustomobject]@{
        scope  = 'User'
        office = [pscustomobject]@{
            mode      = 'automatic'
            templates = ''
            match     = [pscustomobject]@{
                domainJoined = $false
                dnsServers   = @()
                dnsSuffixes  = @()
                gateways     = @()
                ssids        = @()
                profileNames = @()
            }
        }
        outside = [pscustomobject]@{
            mode      = 'secure'
            templates = 'https://dns.google/dns-query{?dns}'
        }
        logMaxBytes = 1048576
    }
}

function Get-Config {
    param([string]$Path)
    $default = Get-DefaultConfig
    if (-not $Path) { $Path = Join-Path $script:ScriptRoot 'config.json' }
    $raw = $null
    if (Test-Path $Path) {
        try {
            $raw = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            throw "Invalid config ($Path): $($_.Exception.Message)"
        }
    }

    $office  = Get-Prop $raw 'office'  $null
    $outside = Get-Prop $raw 'outside' $null
    $match   = Get-Prop $office 'match' $null
    $dm      = $default.office.match

    $cfg = [pscustomobject]@{
        path   = $Path
        exists = [bool](Test-Path $Path)
        scope  = Get-Prop $raw 'scope' $default.scope
        office = [pscustomobject]@{
            mode      = Get-Prop $office 'mode'      $default.office.mode
            templates = [string](Get-Prop $office 'templates' $default.office.templates)
            match     = [pscustomobject]@{
                domainJoined = [bool](Get-Prop $match 'domainJoined' $dm.domainJoined)
                dnsServers   = @(Get-Prop $match 'dnsServers'   $dm.dnsServers)
                dnsSuffixes  = @(Get-Prop $match 'dnsSuffixes'  $dm.dnsSuffixes)
                gateways     = @(Get-Prop $match 'gateways'     $dm.gateways)
                ssids        = @(Get-Prop $match 'ssids'        $dm.ssids)
                profileNames = @(Get-Prop $match 'profileNames' $dm.profileNames)
            }
        }
        outside = [pscustomobject]@{
            mode      = Get-Prop $outside 'mode'      $default.outside.mode
            templates = [string](Get-Prop $outside 'templates' $default.outside.templates)
        }
        logMaxBytes = [int](Get-Prop $raw 'logMaxBytes' $default.logMaxBytes)
    }

    foreach ($profile in 'office', 'outside') {
        $m = $cfg.$profile.mode
        if ($m -notin 'off', 'automatic', 'secure') { throw "config: $profile.mode must be off/automatic/secure, got '$m'" }
        $t = $cfg.$profile.templates
        if ($t -and ($t -split '\s+' | Where-Object { $_ -notmatch '^https://' })) {
            throw "config: $profile.templates must start with https://, got '$t'"
        }
    }
    if ($cfg.scope -notin 'User', 'Machine') { throw "config: scope must be User or Machine, got '$($cfg.scope)'" }
    return $cfg
}

function Test-HasOfficeRules {
    <# True when at least one office.match rule is set. Without rules every network is "outside". #>
    param([Parameter(Mandatory)] $Match)
    if (Get-Prop $Match 'domainJoined' $false) { return $true }
    foreach ($n in 'dnsServers', 'dnsSuffixes', 'gateways', 'ssids', 'profileNames') {
        if (@(Get-Prop $Match $n @()) | Where-Object { $_ }) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Network detection
# ---------------------------------------------------------------------------
function Get-NetworkFacts {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $upIndexes = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.ifIndex })

    $dnsSuffixes = @(Get-DnsClient -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -in $upIndexes -and $_.ConnectionSpecificSuffix } |
        ForEach-Object { $_.ConnectionSpecificSuffix.ToLower() } | Select-Object -Unique)

    $dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -in $upIndexes } |
        ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)

    $gateways = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -in $upIndexes } |
        ForEach-Object { $_.NextHop } | Select-Object -Unique)

    $profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Select-Object -Unique)

    $ssid = $null
    try {
        $out = & netsh.exe wlan show interfaces 2>$null
        $m = $out | Select-String -Pattern '^\s*SSID\s*:\s*(.+)$' | Select-Object -First 1
        if ($m) { $ssid = $m.Matches[0].Groups[1].Value.Trim() }
    } catch { }

    [pscustomobject]@{
        DomainJoined = [bool]$cs.PartOfDomain
        Domain       = [string]$cs.Domain
        DnsSuffixes  = $dnsSuffixes
        DnsServers   = $dnsServers
        Gateways     = $gateways
        Ssid         = $ssid
        ProfileNames = $profiles
    }
}

function Test-OfficeNetwork {
    <# Any matching rule marks the network as office. Returns IsOffice + Reasons. #>
    param(
        [Parameter(Mandatory)] $Facts,
        [Parameter(Mandatory)] $Match
    )
    $reasons = New-Object System.Collections.Generic.List[string]

    if ((Get-Prop $Match 'domainJoined' $false) -and $Facts.DomainJoined) {
        $reasons.Add("domainJoined=$($Facts.Domain)")
    }
    foreach ($s in @(Get-Prop $Match 'dnsServers' @())) {
        if ($s -and ($Facts.DnsServers -contains $s)) { $reasons.Add("dnsServer=$s") }
    }
    foreach ($s in @(Get-Prop $Match 'dnsSuffixes' @())) {
        if ($s -and ($Facts.DnsSuffixes -contains $s.ToLower())) { $reasons.Add("dnsSuffix=$s") }
    }
    foreach ($g in @(Get-Prop $Match 'gateways' @())) {
        if ($g -and ($Facts.Gateways -contains $g)) { $reasons.Add("gateway=$g") }
    }
    foreach ($w in @(Get-Prop $Match 'ssids' @())) {
        if ($w -and $Facts.Ssid -and ($Facts.Ssid -ieq $w)) { $reasons.Add("ssid=$w") }
    }
    foreach ($p in @(Get-Prop $Match 'profileNames' @())) {
        if ($p -and ($Facts.ProfileNames -contains $p)) { $reasons.Add("profile=$p") }
    }

    [pscustomobject]@{
        IsOffice = ($reasons.Count -gt 0)
        Reasons  = @($reasons)
    }
}

# ---------------------------------------------------------------------------
# Policy (registry)
# ---------------------------------------------------------------------------
function Get-PolicyPath {
    param([ValidateSet('User', 'Machine')] [string]$Scope = 'User')
    if ($Scope -eq 'Machine') { 'HKLM:\SOFTWARE\Policies\Google\Chrome' } else { 'HKCU:\SOFTWARE\Policies\Google\Chrome' }
}

function Get-DoHPolicy {
    param([Parameter(Mandatory)] [string]$Path)
    if (-not (Test-Path $Path)) {
        return [pscustomobject]@{ Path = $Path; Exists = $false; Mode = $null; Templates = $null }
    }
    $item = Get-ItemProperty -Path $Path
    [pscustomobject]@{
        Path      = $Path
        Exists    = $true
        Mode      = Get-Prop $item $script:PolicyModeName $null
        Templates = Get-Prop $item $script:PolicyTemplatesName $null
    }
}

function Set-DoHPolicy {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [ValidateSet('off', 'automatic', 'secure')] [string]$Mode,
        [string]$Templates = ''
    )
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $script:PolicyModeName -Value $Mode -PropertyType String -Force | Out-Null
    if ([string]::IsNullOrWhiteSpace($Templates)) {
        Remove-ItemProperty -Path $Path -Name $script:PolicyTemplatesName -ErrorAction SilentlyContinue
    } else {
        New-ItemProperty -Path $Path -Name $script:PolicyTemplatesName -Value $Templates.Trim() -PropertyType String -Force | Out-Null
    }
}

function Remove-DoHPolicy {
    param([Parameter(Mandatory)] [string]$Path)
    if (-not (Test-Path $Path)) { return }
    Remove-ItemProperty -Path $Path -Name $script:PolicyModeName      -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $Path -Name $script:PolicyTemplatesName -ErrorAction SilentlyContinue
    $key = Get-Item -Path $Path
    if ($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) {
        Remove-Item -Path $Path -Force
    }
}

function Get-DesiredPolicy {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] [bool]$IsOffice)
    $p = if ($IsOffice) { $Config.office } else { $Config.outside }
    [pscustomobject]@{
        Profile   = $(if ($IsOffice) { 'office' } else { 'outside' })
        Mode      = $p.mode
        Templates = [string]$p.templates
    }
}

function Test-PolicyMatches {
    param([Parameter(Mandatory)] $Current, [Parameter(Mandatory)] $Desired)
    $curMode = [string](Get-Prop $Current 'Mode' '')
    $curTpl  = ([string](Get-Prop $Current 'Templates' '')).Trim()
    $desTpl  = ([string]$Desired.Templates).Trim()
    return ($curMode -eq [string]$Desired.Mode) -and ($curTpl -eq $desTpl)
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
function Save-State {
    param([Parameter(Mandatory)] $State)
    try {
        $State | ConvertTo-Json -Depth 6 | Set-Content -Path $script:StatePath -Encoding UTF8
    } catch {
        Write-Log -Level WARN -Message "Failed to write state.json: $($_.Exception.Message)"
    }
}

function Get-State {
    if (-not (Test-Path $script:StatePath)) { return $null }
    try { Get-Content -Path $script:StatePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
}

# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------
function Get-WindowsPowerShellPath {
    Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
}

function Install-DoHTask {
    param([switch]$NetworkChange, [ValidateSet('User', 'Machine')] [string]$Scope = 'User')
    $psExe = Get-WindowsPowerShellPath
    $args  = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($script:ScriptPath)`" -Apply -Scope $Scope"
    $user  = "$env:USERDOMAIN\$env:USERNAME"
    # Both HKCU\SOFTWARE\Policies and HKLM need elevation (user only has ReadKey on HKCU\SOFTWARE\Policies).
    # RunLevel Highest on a logon task runs elevated without a UAC prompt for members of Administrators.
    $runLevel = 'Highest'

    $action   = New-ScheduledTaskAction -Execute $psExe -Argument $args -WorkingDirectory $script:ScriptRoot
    $trigger  = New-ScheduledTaskTrigger -AtLogOn -User $user
    $trigger.Delay = 'PT30S'
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel $runLevel

    Register-ScheduledTask -TaskName $script:TaskLogon -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal -Force | Out-Null
    Write-Log -Message "Task '$($script:TaskLogon)' registered (AtLogOn, 30 s delay, user $user, scope $Scope)"

    if ($NetworkChange) {
        # Event-triggered task via schtasks.exe (built-in). Event ID 10000 = network profile connected.
        $query = "*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=10000]]"
        $tr = "`"$psExe`" $args"
        $out = & schtasks.exe /Create /F /TN $script:TaskNetChange /SC ONEVENT `
            /EC 'Microsoft-Windows-NetworkProfile/Operational' /MO $query /TR $tr /RL HIGHEST 2>&1
        if ($LASTEXITCODE -ne 0) { throw "schtasks failed: $out" }
        Write-Log -Message "Task '$($script:TaskNetChange)' registered (NetworkProfile event 10000)"
    }
}

function Uninstall-DoHTask {
    foreach ($name in $script:TaskLogon, $script:TaskNetChange) {
        $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($t) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
            Write-Log -Message "Task '$name' removed"
        } else {
            Write-Log -Message "Task '$name' not installed, skipping"
        }
    }
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
function Invoke-Apply {
    param($Config, [string]$Scope, [string]$Force, [bool]$DryRun)

    $path = Get-PolicyPath -Scope $Scope
    if ($Scope -eq 'User') {
        $hklm = Get-DoHPolicy -Path (Get-PolicyPath -Scope 'Machine')
        if ($hklm.Exists -and $hklm.Mode) {
            Write-Log -Level WARN -Message "HKLM already has $($script:PolicyModeName)=$($hklm.Mode). HKLM overrides HKCU. Use -Scope Machine or remove the HKLM policy."
        }
    }

    if ($Force -eq 'Auto' -and -not (Test-HasOfficeRules -Match $Config.office.match)) {
        Write-Log -Level ERROR -Message "office.match in $($Config.path) is empty: every network would be treated as 'outside'. Copy config.example.json to config.json and fill office.match (see -Status), or use -Force Office/Outside."
        return 1
    }

    $facts = Get-NetworkFacts
    $detect = Test-OfficeNetwork -Facts $facts -Match $Config.office.match
    $isOffice = switch ($Force) {
        'Office'  { $true }
        'Outside' { $false }
        default   { $detect.IsOffice }
    }
    $why = if ($Force -ne 'Auto') { "forced=$Force" }
           elseif ($detect.IsOffice) { 'match: ' + ($detect.Reasons -join ', ') }
           else { 'no office rule matched' }

    $desired = Get-DesiredPolicy -Config $Config -IsOffice $isOffice
    $current = Get-DoHPolicy -Path $path
    $tplText = if ($desired.Templates) { $desired.Templates } else { '(none)' }

    Write-Log -Message ("Network: dns=[{0}] suffix=[{1}] gw=[{2}] ssid={3}" -f ($facts.DnsServers -join ','), ($facts.DnsSuffixes -join ','), ($facts.Gateways -join ','), $facts.Ssid)
    Write-Log -Message "Decision: profile=$($desired.Profile) ($why) -> mode=$($desired.Mode) templates=$tplText scope=$Scope"

    $changed = $false
    if (Test-PolicyMatches -Current $current -Desired $desired) {
        Write-Log -Message 'No change: policy already matches'
    } elseif ($DryRun) {
        Write-Log -Message "DRY RUN: would write $path -> $($script:PolicyModeName)=$($desired.Mode), $($script:PolicyTemplatesName)=$tplText"
    } else {
        Set-DoHPolicy -Path $path -Mode $desired.Mode -Templates $desired.Templates
        $after = Get-DoHPolicy -Path $path
        if (-not (Test-PolicyMatches -Current $after -Desired $desired)) {
            Write-Log -Level ERROR -Message "Verification failed: registry has mode=$($after.Mode) templates=$($after.Templates)"
            return 3
        }
        $changed = $true
        Write-Log -Message "Applied: $path -> $($script:PolicyModeName)=$($desired.Mode), $($script:PolicyTemplatesName)=$tplText"
    }

    Save-State ([pscustomobject]@{
        lastRunAt     = (Get-Date).ToString('o')
        profile       = $desired.Profile
        reason        = $why
        mode          = $desired.Mode
        templates     = $desired.Templates
        scope         = $Scope
        changed       = $changed
        dryRun        = $DryRun
        network       = $facts
    })
    return 0
}

function Invoke-Status {
    param($Config, [string]$Scope)
    $facts  = Get-NetworkFacts
    $detect = Test-OfficeNetwork -Facts $facts -Match $Config.office.match
    $desired = Get-DesiredPolicy -Config $Config -IsOffice $detect.IsOffice

    Write-Host ''
    Write-Host '== Config ==' -ForegroundColor Cyan
    Write-Host "  path   : $($Config.path) (exists=$($Config.exists))"
    Write-Host "  scope  : $Scope"
    Write-Host "  office : mode=$($Config.office.mode) templates='$($Config.office.templates)'"
    Write-Host "  outside: mode=$($Config.outside.mode) templates='$($Config.outside.templates)'"
    Write-Host "  rules  : dnsServers=[$($Config.office.match.dnsServers -join ',')] dnsSuffixes=[$($Config.office.match.dnsSuffixes -join ',')] gateways=[$($Config.office.match.gateways -join ',')] ssids=[$($Config.office.match.ssids -join ',')] profileNames=[$($Config.office.match.profileNames -join ',')] domainJoined=$($Config.office.match.domainJoined)"

    Write-Host '== Network ==' -ForegroundColor Cyan
    Write-Host "  domainJoined: $($facts.DomainJoined) ($($facts.Domain))"
    Write-Host "  dnsServers  : $($facts.DnsServers -join ', ')"
    Write-Host "  dnsSuffixes : $($facts.DnsSuffixes -join ', ')"
    Write-Host "  gateways    : $($facts.Gateways -join ', ')"
    Write-Host "  ssid        : $($facts.Ssid)"
    Write-Host "  profiles    : $($facts.ProfileNames -join ', ')"

    Write-Host '== Detection ==' -ForegroundColor Cyan
    Write-Host "  isOffice : $($detect.IsOffice)  reasons: $(if ($detect.Reasons) { $detect.Reasons -join ', ' } else { '(none)' })"
    Write-Host "  desired  : profile=$($desired.Profile) mode=$($desired.Mode) templates='$($desired.Templates)'"

    Write-Host '== Chrome policy (registry) ==' -ForegroundColor Cyan
    foreach ($s in 'User', 'Machine') {
        $p = Get-DoHPolicy -Path (Get-PolicyPath -Scope $s)
        Write-Host ("  {0,-7}: {1}  mode={2} templates='{3}'" -f $s, $p.Path, $p.Mode, $p.Templates)
    }

    Write-Host '== Tasks ==' -ForegroundColor Cyan
    foreach ($name in $script:TaskLogon, $script:TaskNetChange) {
        $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Write-Host ("  {0,-24}: {1}" -f $name, $(if ($t) { $t.State } else { 'not installed' }))
    }

    $state = Get-State
    Write-Host '== Last run (state.json) ==' -ForegroundColor Cyan
    if ($state) {
        Write-Host "  at=$(Get-Prop $state 'lastRunAt') profile=$(Get-Prop $state 'profile') reason='$(Get-Prop $state 'reason')' changed=$(Get-Prop $state 'changed') dryRun=$(Get-Prop $state 'dryRun')"
    } else {
        Write-Host '  (none)'
    }
    Write-Host ''
    return 0
}

function Invoke-Reset {
    param([string]$Scope, [bool]$DryRun)
    $path = Get-PolicyPath -Scope $Scope
    $cur = Get-DoHPolicy -Path $path
    if (-not $cur.Exists -or (-not $cur.Mode -and -not $cur.Templates)) {
        Write-Log -Message "Reset: no DoH policy at $path"
        return 0
    }
    if ($DryRun) {
        Write-Log -Message "DRY RUN: would remove $($script:PolicyModeName) and $($script:PolicyTemplatesName) from $path"
        return 0
    }
    Remove-DoHPolicy -Path $path
    Write-Log -Message "Reset: DoH policy removed from $path. Chrome is back under user control."
    Save-State ([pscustomobject]@{ lastRunAt = (Get-Date).ToString('o'); profile = 'reset'; reason = 'manual -Reset'; mode = $null; templates = $null; scope = $Scope; changed = $true; dryRun = $false })
    return 0
}

function Invoke-Main {
    try {
        $cfg = Get-Config -Path $ConfigPath
    } catch {
        Write-Log -Level ERROR -Message $_.Exception.Message
        return 1
    }
    $script:LogMaxBytes = $cfg.logMaxBytes
    $effScope = if ($Scope) { $Scope } else { $cfg.scope }

    # Writing under HKCU\SOFTWARE\Policies or HKLM\SOFTWARE\Policies needs an elevated process.
    $needsElevation = switch ($PSCmdlet.ParameterSetName) {
        'Status'    { $false }
        'Reset'     { -not $DryRun }
        'Install'   { -not $DryRun }
        'Uninstall' { $true }
        default     { -not $DryRun }
    }
    if ($needsElevation -and -not (Test-IsElevated)) {
        Write-Log -Level ERROR -Message "Administrator PowerShell required (standard users only have ReadKey on HKCU\SOFTWARE\Policies). Re-run elevated, or use -DryRun / -Status."
        return 4
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Status'    { return (Invoke-Status -Config $cfg -Scope $effScope) }
        'Reset'     { return (Invoke-Reset -Scope $effScope -DryRun $DryRun.IsPresent) }
        'Install'   {
            if ($DryRun) { Write-Log -Message "DRY RUN: would register task(s) for scope $effScope"; return 0 }
            Install-DoHTask -NetworkChange:$OnNetworkChange -Scope $effScope
            return 0
        }
        'Uninstall' { Uninstall-DoHTask; return 0 }
        default     { return (Invoke-Apply -Config $cfg -Scope $effScope -Force $Force -DryRun $DryRun.IsPresent) }
    }
}

# Run main unless dot-sourced (tests dot-source this file to load the functions).
if ($MyInvocation.InvocationName -ne '.') {
    $code = Invoke-Main
    exit $code
}
