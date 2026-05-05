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
- `LGPO.exe` from the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319) (required except on Windows Home)

## Setup

Run PowerShell as Administrator, then enter the following commands in order.

**Navigate to the directory where you want the toolkit stored:**

```powershell
cd <directory>
```

**Clone the repository:**

```powershell
git clone https://github.com/briangeis/windows-hardening
```

**Allow your device to run PowerShell scripts:**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

**Unblock the toolkit scripts:**

```powershell
Get-ChildItem -Path .\windows-hardening -Recurse -Filter *.ps1 | Unblock-File
```

**Download LGPO.exe:**

Windows Pro, Enterprise, Education, and LTSC editions require `LGPO.exe`. Download it from the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319) and place it in the `policy` directory. Windows Home editions do not require `LGPO.exe`.

## Components

Each component script supports four modes of operation, consistent across the toolkit:

- **Interactive**: Configure settings through a menu, reviewing the current state of each setting against its hardened value.
- **Silent**: Apply a pre-built profile to the device without prompting, for scripted hardening and automation.
- **Build**: Construct a configuration profile on Windows or Linux, for later application to a Windows device.
- **Snapshot**: Capture the current system state as a profile, for backup or replication.

A snapshot of the current system state is saved automatically before any changes are applied in Interactive or Silent mode. `Get-Help` is available on every script for full parameter and usage documentation.

| Script | Component | Description | Status |
|---|---|---|---|
| `Invoke-WinHardenPolicy` | [Policy](policy/README.md) | Registry and Local Group Policy settings | In progress |
| `Invoke-WinHardenServices` | Services | Windows service startup configuration | Planned |
| `Invoke-WinHardenPackages` | Packages | Preinstalled appx package removal | Planned |
| `Invoke-WinHardenSuite` | Orchestrator | Coordinates silent execution of all components | Planned |

## Definitions

Definitions files describe the settings each component script can configure, curated from authoritative sources rather than exhaustive configuration checklists. Each definitions file is specific to one component, and each component may have multiple definitions files.

The Policy component's definitions file, `Policy-MicrosoftPrivacyConnections.psd1`, covers Microsoft privacy and connection settings across 120 registry values. The [Policy-MicrosoftPrivacyConnections reference](definitions/reference/Policy-MicrosoftPrivacyConnections.md) maps every setting to its corresponding section in the Microsoft source article, documenting where the article's own registry guidance is incorrect, identifying inconsistencies in the article's documentation, and flagging settings with significant side effects.

The full list of available definitions files is maintained in [definitions/](definitions/).

## License

This toolkit is licensed under the [GNU General Public License v3.0](LICENSE).
