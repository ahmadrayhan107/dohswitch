# Pester 3.4 tests (built into Windows PowerShell 5.1). Run: Invoke-Pester -Path .\tests
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Join-Path (Split-Path -Parent $here) 'DoHSwitch.ps1'
. $script   # dot-source: loads functions only (main is guarded)

function New-Facts {
    param($DnsServers = @(), $DnsSuffixes = @(), $Gateways = @(), $Ssid = $null, $ProfileNames = @(), $DomainJoined = $false, $Domain = 'WORKGROUP')
    [pscustomobject]@{
        DomainJoined = $DomainJoined; Domain = $Domain; DnsSuffixes = @($DnsSuffixes); DnsServers = @($DnsServers)
        Gateways = @($Gateways); Ssid = $Ssid; ProfileNames = @($ProfileNames)
    }
}
function New-Match {
    param($DnsServers = @(), $DnsSuffixes = @(), $Gateways = @(), $Ssids = @(), $ProfileNames = @(), $DomainJoined = $false)
    [pscustomobject]@{
        domainJoined = $DomainJoined; dnsServers = @($DnsServers); dnsSuffixes = @($DnsSuffixes)
        gateways = @($Gateways); ssids = @($Ssids); profileNames = @($ProfileNames)
    }
}

Describe 'Test-OfficeNetwork' {
    It 'matches on DNS server' {
        $r = Test-OfficeNetwork -Facts (New-Facts -DnsServers '192.168.20.3', '8.8.8.8') -Match (New-Match -DnsServers '192.168.20.3')
        $r.IsOffice | Should Be $true
        ($r.Reasons -join ',') | Should Match 'dnsServer=192.168.20.3'
    }
    It 'matches on DNS suffix case-insensitively' {
        $r = Test-OfficeNetwork -Facts (New-Facts -DnsSuffixes 'lan') -Match (New-Match -DnsSuffixes 'LAN')
        $r.IsOffice | Should Be $true
    }
    It 'matches on SSID' {
        $r = Test-OfficeNetwork -Facts (New-Facts -Ssid 'Office-WiFi') -Match (New-Match -Ssids 'office-wifi')
        $r.IsOffice | Should Be $true
    }
    It 'matches on gateway' {
        $r = Test-OfficeNetwork -Facts (New-Facts -Gateways '10.0.0.1') -Match (New-Match -Gateways '10.0.0.1')
        $r.IsOffice | Should Be $true
    }
    It 'matches on profile name' {
        $r = Test-OfficeNetwork -Facts (New-Facts -ProfileNames 'CorpNet') -Match (New-Match -ProfileNames 'CorpNet')
        $r.IsOffice | Should Be $true
    }
    It 'matches on domain join when rule enabled' {
        $r = Test-OfficeNetwork -Facts (New-Facts -DomainJoined $true -Domain 'corp.local') -Match (New-Match -DomainJoined $true)
        $r.IsOffice | Should Be $true
    }
    It 'does not match domain rule on a workgroup machine' {
        $r = Test-OfficeNetwork -Facts (New-Facts -DomainJoined $false) -Match (New-Match -DomainJoined $true)
        $r.IsOffice | Should Be $false
    }
    It 'returns outside when no rule matches' {
        $r = Test-OfficeNetwork -Facts (New-Facts -DnsServers '1.1.1.1' -DnsSuffixes 'home' -Gateways '192.168.1.1') -Match (New-Match -DnsServers '192.168.20.3' -DnsSuffixes 'lan')
        $r.IsOffice | Should Be $false
        $r.Reasons.Count | Should Be 0
    }
    It 'returns outside when rules are empty' {
        $r = Test-OfficeNetwork -Facts (New-Facts -DnsServers '192.168.20.3') -Match (New-Match)
        $r.IsOffice | Should Be $false
    }
    It 'collects multiple reasons' {
        $r = Test-OfficeNetwork -Facts (New-Facts -DnsServers '192.168.20.3' -DnsSuffixes 'lan') -Match (New-Match -DnsServers '192.168.20.3' -DnsSuffixes 'lan')
        $r.Reasons.Count | Should Be 2
    }
}

Describe 'Test-HasOfficeRules' {
    It 'false when all rules empty' {
        Test-HasOfficeRules -Match (New-Match) | Should Be $false
    }
    It 'false for the shipped config.example.json' {
        $c = Get-Config -Path (Join-Path (Split-Path -Parent $here) 'config.example.json')
        Test-HasOfficeRules -Match $c.office.match | Should Be $false
    }
    It 'true when a dnsServers rule exists' {
        Test-HasOfficeRules -Match (New-Match -DnsServers '10.0.0.53') | Should Be $true
    }
    It 'true when only domainJoined is enabled' {
        Test-HasOfficeRules -Match (New-Match -DomainJoined $true) | Should Be $true
    }
    It 'ignores empty strings' {
        Test-HasOfficeRules -Match (New-Match -Ssids '') | Should Be $false
    }
}

Describe 'Get-DesiredPolicy' {
    $cfg = Get-DefaultConfig
    It 'office -> automatic with no templates' {
        $d = Get-DesiredPolicy -Config $cfg -IsOffice $true
        $d.Profile | Should Be 'office'
        $d.Mode | Should Be 'automatic'
        $d.Templates | Should Be ''
    }
    It 'outside -> secure with Google template' {
        $d = Get-DesiredPolicy -Config $cfg -IsOffice $false
        $d.Profile | Should Be 'outside'
        $d.Mode | Should Be 'secure'
        $d.Templates | Should Be 'https://dns.google/dns-query{?dns}'
    }
}

Describe 'Test-PolicyMatches' {
    $desired = [pscustomobject]@{ Mode = 'secure'; Templates = 'https://dns.google/dns-query{?dns}' }
    It 'true when equal' {
        Test-PolicyMatches -Current ([pscustomobject]@{ Mode = 'secure'; Templates = 'https://dns.google/dns-query{?dns}' }) -Desired $desired | Should Be $true
    }
    It 'false when mode differs' {
        Test-PolicyMatches -Current ([pscustomobject]@{ Mode = 'automatic'; Templates = 'https://dns.google/dns-query{?dns}' }) -Desired $desired | Should Be $false
    }
    It 'false when templates differ' {
        Test-PolicyMatches -Current ([pscustomobject]@{ Mode = 'secure'; Templates = 'https://cloudflare-dns.com/dns-query{?dns}' }) -Desired $desired | Should Be $false
    }
    It 'false when policy absent' {
        Test-PolicyMatches -Current ([pscustomobject]@{ Mode = $null; Templates = $null; Exists = $false }) -Desired $desired | Should Be $false
    }
    It 'treats missing templates as empty for office profile' {
        $office = [pscustomobject]@{ Mode = 'automatic'; Templates = '' }
        Test-PolicyMatches -Current ([pscustomobject]@{ Mode = 'automatic'; Templates = $null }) -Desired $office | Should Be $true
    }
}

Describe 'Registry round-trip (temp key under HKCU)' {
    $testPath = "HKCU:\Software\DoHSwitchTest\$([guid]::NewGuid())"

    It 'Get-DoHPolicy reports missing key' {
        $p = Get-DoHPolicy -Path $testPath
        $p.Exists | Should Be $false
        $p.Mode | Should Be $null
    }
    It 'Set then Get returns secure + templates' {
        Set-DoHPolicy -Path $testPath -Mode 'secure' -Templates 'https://dns.google/dns-query{?dns}'
        $p = Get-DoHPolicy -Path $testPath
        $p.Exists | Should Be $true
        $p.Mode | Should Be 'secure'
        $p.Templates | Should Be 'https://dns.google/dns-query{?dns}'
        (Get-ItemProperty -Path $testPath).DnsOverHttpsMode | Should Be 'secure'
    }
    It 'Set office removes the templates value' {
        Set-DoHPolicy -Path $testPath -Mode 'automatic' -Templates ''
        $p = Get-DoHPolicy -Path $testPath
        $p.Mode | Should Be 'automatic'
        $p.Templates | Should Be $null
        (Get-Item -Path $testPath).GetValueNames() -contains 'DnsOverHttpsTemplates' | Should Be $false
    }
    It 'Remove-DoHPolicy deletes values and empty key' {
        Remove-DoHPolicy -Path $testPath
        Test-Path $testPath | Should Be $false
    }
    It 'Remove-DoHPolicy keeps key when other values exist' {
        New-Item -Path $testPath -Force | Out-Null
        New-ItemProperty -Path $testPath -Name 'OtherPolicy' -Value 1 -PropertyType DWord -Force | Out-Null
        Set-DoHPolicy -Path $testPath -Mode 'secure' -Templates 'https://dns.google/dns-query{?dns}'
        Remove-DoHPolicy -Path $testPath
        Test-Path $testPath | Should Be $true
        (Get-Item -Path $testPath).GetValueNames() -contains 'DnsOverHttpsMode' | Should Be $false
        Remove-Item -Path 'HKCU:\Software\DoHSwitchTest' -Recurse -Force
    }
}

Describe 'Get-Config' {
    It 'uses defaults when file is missing' {
        $c = Get-Config -Path (Join-Path $env:TEMP "nope-$([guid]::NewGuid()).json")
        $c.exists | Should Be $false
        $c.scope | Should Be 'User'
        $c.outside.templates | Should Be 'https://dns.google/dns-query{?dns}'
        $c.office.match.dnsServers.Count | Should Be 0
    }
    It 'fills missing fields with defaults' {
        $f = Join-Path $env:TEMP "cfg-$([guid]::NewGuid()).json"
        '{ "office": { "match": { "dnsServers": ["10.1.1.1"] } } }' | Set-Content -Path $f -Encoding UTF8
        $c = Get-Config -Path $f
        $c.office.mode | Should Be 'automatic'
        $c.office.match.dnsServers[0] | Should Be '10.1.1.1'
        $c.outside.mode | Should Be 'secure'
        Remove-Item $f
    }
    It 'rejects invalid mode' {
        $f = Join-Path $env:TEMP "cfg-$([guid]::NewGuid()).json"
        '{ "outside": { "mode": "fast" } }' | Set-Content -Path $f -Encoding UTF8
        { Get-Config -Path $f } | Should Throw
        Remove-Item $f
    }
    It 'rejects non-https template' {
        $f = Join-Path $env:TEMP "cfg-$([guid]::NewGuid()).json"
        '{ "outside": { "templates": "http://dns.google/dns-query{?dns}" } }' | Set-Content -Path $f -Encoding UTF8
        { Get-Config -Path $f } | Should Throw
        Remove-Item $f
    }
    It 'loads the repo config.json' {
        $c = Get-Config -Path (Join-Path (Split-Path -Parent $here) 'config.json')
        $c.exists | Should Be $true
        $c.office.mode | Should Be 'automatic'
        $c.outside.mode | Should Be 'secure'
    }
}
