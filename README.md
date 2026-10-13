# DoHSwitch

Network-aware Secure DNS switcher for Google Chrome. Pure PowerShell, zero dependencies.

DoHSwitch looks at the network your Windows machine is on and sets Chrome's Secure DNS (DNS-over-HTTPS) policy accordingly:

| Network | Chrome `chrome://settings/security` | Registry policy written |
|---|---|---|
| Office | *With your current service provider* (OS default when available) | `DnsOverHttpsMode=automatic`, no `DnsOverHttpsTemplates` |
| Anywhere else | *With Google (Public DNS)* | `DnsOverHttpsMode=secure`, `DnsOverHttpsTemplates=https://dns.google/dns-query{?dns}` |

Why: on the office network internal hostnames must resolve through the office resolver. Outside, the ISP's DNS is not trusted, so Chrome goes straight to Google DoH.

- Windows PowerShell 5.1 (built into Windows 10/11), also works on PowerShell 7
- No modules, no binaries, no Chrome extension. Only built-in cmdlets
- Runs on logon (and optionally on every network change) through Task Scheduler
- Chrome picks the policy up live. No restart needed

## Requirements

- Windows 10/11, Google Chrome
- An account in the local Administrators group. `HKCU\SOFTWARE\Policies` is read-only for standard users, so writing the policy needs an elevated PowerShell. `-Status` and `-DryRun` work without elevation

## Quick start

```powershell
git clone https://github.com/ahmadrayhan107/dohswitch.git
cd dohswitch
Copy-Item config.example.json config.json
```

1. Connect to your office network and run `.\DoHSwitch.ps1 -Status`. Copy the values under `== Network ==` into `office.match` in `config.json` (see [Configuration](#configuration)).
2. Open PowerShell **as Administrator** and run:

```powershell
.\DoHSwitch.ps1 -Apply -DryRun            # preview the decision, writes nothing
.\DoHSwitch.ps1 -Apply                    # write the policy now
.\DoHSwitch.ps1 -InstallTask -OnNetworkChange   # run automatically at logon and on network change
```

3. Verify in Chrome: `chrome://policy` lists `DnsOverHttpsMode` (and `DnsOverHttpsTemplates` when outside). `chrome://settings/security` shows Secure DNS as managed.

## Usage

| Command | Needs admin | What it does |
|---|---|---|
| `.\DoHSwitch.ps1 -Status` | no | Show network facts, detection result, current policies, tasks, last run |
| `.\DoHSwitch.ps1 -Apply -DryRun` | no | Show what `-Apply` would write |
| `.\DoHSwitch.ps1 -Apply` | yes | Detect network and write the matching policy (idempotent) |
| `.\DoHSwitch.ps1 -Apply -Force Office` / `-Force Outside` | yes | Skip detection |
| `.\DoHSwitch.ps1 -Reset` | yes | Remove the policy, Chrome returns to user control |
| `.\DoHSwitch.ps1 -InstallTask` | yes | Register task `DoHSwitch-AtLogon` (logon + 30 s) |
| `.\DoHSwitch.ps1 -InstallTask -OnNetworkChange` | yes | Also register `DoHSwitch-NetworkChange` (Event ID 10000, NetworkProfile) |
| `.\DoHSwitch.ps1 -UninstallTask` | yes | Remove both tasks |

Common options: `-ConfigPath <file>`, `-Scope User|Machine` (HKCU or HKLM), `-Verbose`.

Exit codes: `0` ok, `1` config error or empty office rules, `3` registry verification failed, `4` elevation required.

The tasks run elevated without a UAC prompt (`RunLevel Highest`) and persist across reboots until `-UninstallTask`.

## Configuration

`config.json` is private to your machine and git-ignored. `config.example.json` is the template.

```json
{
  "scope": "User",
  "office": {
    "mode": "automatic",
    "templates": "",
    "match": {
      "domainJoined": false,
      "dnsServers": ["192.168.20.3"],
      "dnsSuffixes": ["corp.example"],
      "gateways": [],
      "ssids": ["Office-WiFi"],
      "profileNames": []
    }
  },
  "outside": {
    "mode": "secure",
    "templates": "https://dns.google/dns-query{?dns}"
  },
  "logMaxBytes": 1048576
}
```

A network is **office** when **any** rule in `office.match` matches. Leave a list empty to ignore it.

| Rule | Source | Tip |
|---|---|---|
| `dnsServers` | DNS servers of adapters that are Up | Most reliable: your office's internal DNS IP |
| `dnsSuffixes` | Connection-specific DNS suffix from DHCP | Case-insensitive |
| `gateways` | Default gateway IP | `192.168.1.1` is common at home too, don't rely on it alone |
| `ssids` | Current Wi-Fi name | Only when on Wi-Fi |
| `profileNames` | Windows network profile name | Windows renames these ("Network 3"), least stable |
| `domainJoined` | Machine joined to an AD domain | Set `true` on corporate laptops |

`-Apply` refuses to run (exit `1`) when `office.match` has no rules at all, because every network would be treated as outside and Google DoH would break internal names at the office. Use `-Force` to override.

Other provider for outside? Replace `outside.templates` with any RFC 8484 template, for example `https://cloudflare-dns.com/dns-query{?dns}` or `https://dns.quad9.net/dns-query{?dns}`. Set `outside.mode` to `automatic` if you want Chrome to fall back to plain DNS when DoH fails.

## How it works

Chrome reads enterprise policies from `HKCU:\SOFTWARE\Policies\Google\Chrome` (or HKLM) and watches the key for changes. DoHSwitch collects network facts with `Get-NetAdapter`, `Get-DnsClientServerAddress`, `Get-DnsClient`, `Get-NetRoute`, `Get-NetConnectionProfile`, `netsh wlan` and `Win32_ComputerSystem`, matches them against `office.match`, writes the two policy values with `New-ItemProperty`, reads them back to verify, and logs to `logs\dohswitch.log`. State of the last run lives in `state.json`.

## Tests

```powershell
Invoke-Pester -Path .\tests     # Pester 3.4, ships with Windows PowerShell 5.1
```

Covers network detection rules, policy mapping, config loading and validation, and a registry round-trip in a temporary key under `HKCU:\Software\DoHSwitchTest`.

## Limitations

- Chrome only. Edge and Brave use the same policies under different keys; not wired yet.
- Does not touch Windows system DNS.
- HKLM policies (for example corporate GPO) override HKCU. `-Apply` warns when it sees one.

## License

MIT
