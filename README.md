# windows-hardening

[![Status](https://img.shields.io/badge/status-active%20development-brightgreen)](https://github.com/briangeis/windows-hardening)
[![Platform](https://img.shields.io/badge/platform-windows-blue)](https://github.com/briangeis/windows-hardening)
[![PowerShell](https://img.shields.io/badge/powershell-5.1%2B-blue)](https://github.com/briangeis/windows-hardening)
[![License](https://img.shields.io/github/license/briangeis/windows-hardening)](LICENSE)

A PowerShell toolkit for hardening Windows on standalone devices. Scripts run in four modes of operation, using curated definitions files and reusable configuration profiles.

The toolkit is intended for standalone Windows 11 devices. Scripts are broadly compatible with Windows 10. Domain-joined devices are not supported, as Group Policy applied by Active Directory takes precedence over local policy changes.

## Requirements

- PowerShell 5.1 or later
- Administrator privileges
- `LGPO.exe` from the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)  
  (required on Pro, Enterprise, Education, and LTSC editions)

## Component Scripts

Each component script supports four modes of operation, consistent across the toolkit:

- **Interactive**: Configure settings through a menu, for initial setup and targeted adjustment.
- **Profile**: Apply a pre-built profile to the device without prompting, for scripted hardening and automation.
- **Build**: Construct a configuration profile on Windows or Linux, for later application to a Windows device.
- **Snapshot**: Capture the current system state as a profile, for backup or replication.

A snapshot of the current system state is saved automatically before any changes are applied in Interactive or Profile Mode. `Get-Help` is available on every script for full parameter and usage documentation.

| Script                     | Component                  | Description                              | Status      |
|----------------------------|----------------------------|------------------------------------------|-------------|
| `Invoke-WinHardenPolicy`   | [Policy](policy/README.md) | Registry and Local Group Policy settings | In progress |
| `Invoke-WinHardenServices` | Services                   | Windows service startup configuration    | Planned     |
| `Invoke-WinHardenPackages` | Packages                   | Preinstalled appx package removal        | Planned     |
| `Invoke-WinHardenSuite`    | Orchestrator               | Coordinates execution of all components  | Planned     |

## Definitions Files

Each definitions file describes the settings each component script can configure, curated from authoritative sources and independent research rather than exhaustive configuration checklists. Each definitions file is specific to one component, and each component may have multiple definitions files.

`Policy-MicrosoftPrivacyConnections.psd1` covers 116 registry settings governing connections and data sharing between Windows and Microsoft services, drawn from the Microsoft article "Manage connections from Windows 10 and Windows 11 operating system components to Microsoft services." The [Policy-MicrosoftPrivacyConnections reference](definitions/reference/Policy-MicrosoftPrivacyConnections.md) maps every setting to its corresponding section in the source article, documenting where the article's registry guidance is incorrect, identifying inconsistencies, and flagging settings with significant side effects.

`Policy-WindowsPrivacyDefaults.psd1` covers 46 registry settings addressing Windows 11 privacy and security defaults not covered by Policy-MicrosoftPrivacyConnections, drawn from independent research and direct system analysis. Together the two files form a complete privacy and hardening baseline. The [Policy-WindowsPrivacyDefaults reference](definitions/reference/Policy-WindowsPrivacyDefaults.md) records the research and editorial decisions behind each setting, covering notable side effects, applicability conditions, and settings requiring special handling.

The full list of available definitions files is maintained in [definitions/](definitions/).

## Setup

Run PowerShell as Administrator, then enter the following commands in order.

**Navigate to the directory where the toolkit will be stored:**

```powershell
cd C:\Tools
```

**Clone the repository from GitHub:**

```powershell
git clone https://github.com/briangeis/windows-hardening
```

**Enable local script execution, which Windows restricts by default:**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

**Remove the download restriction Windows applies to the toolkit files:**

```powershell
Get-ChildItem -Path .\windows-hardening -Recurse -Filter *.ps1 | Unblock-File
```

**Download LGPO.exe, required on Pro, Enterprise, Education, and LTSC editions:**

Extract `LGPO.exe` from the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319) and place it in the `policy` directory.

## License

This toolkit is licensed under the [GNU General Public License v3.0](LICENSE).
