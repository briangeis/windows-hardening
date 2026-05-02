# Policy

Applies registry and Local Group Policy hardening settings to a standalone Windows device.

## Prerequisites

- PowerShell 5.1 or later
- Administrator privileges (all modes except Build Mode)
- `LGPO.exe` from the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
  is required on Pro, Enterprise, Education, and LTSC editions in Interactive and Silent modes

Place `LGPO.exe` in the `policy` directory alongside the script, or ensure it is available on the system `PATH`. Windows Home editions do not require `LGPO.exe`.

## Modes of Operation

The script supports four modes, determined by which parameters are provided.

### Interactive Mode

Opens a menu of settings from a definitions file. Each setting shows its current state on the device alongside the hardened and default values from the definitions file. Settings can be applied or restored individually, or all at once within a section. A snapshot of the current system state is saved automatically on startup.

Use Interactive Mode for initial configuration of a device, reviewing the current state of settings, or making targeted adjustments to settings already in place.

```powershell
.\policy\Invoke-WinHardenPolicy.ps1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1
```

### Silent Mode

Reads a profile file and applies all settings without prompting. A snapshot of the current system state is saved automatically before any changes are applied.

Use Silent Mode to apply a pre-built profile to a device, or as part of an automated hardening workflow.

```powershell
.\policy\Invoke-WinHardenPolicy.ps1 -ProfilePath .\Policy-Snapshot_WIN11-HOME_20260426_042606.psd1
```

### Build Mode

Opens the same settings menu as Interactive Mode, but saves selections to a profile file instead of applying them to the device. Does not read or write system state, so administrator privileges are not required. Can be run on Windows or Linux.

Use Build Mode to prepare a configuration profile for later application to a Windows device. Build Mode can be run multiple times, each time with a different definitions file and the same profile file path, to accumulate settings from each source into a single profile.

```powershell
.\policy\Invoke-WinHardenPolicy.ps1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1 -Build .\my-profile.psd1
```

### Snapshot Mode

Reads the current registry state for every setting in a definitions file and writes a profile capturing it, without prompting or making any changes.

Use Snapshot Mode to capture the state of a configured device for replication on other devices, or as a backup before reimaging.

```powershell
.\policy\Invoke-WinHardenPolicy.ps1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1 -Snapshot
```

## Output Files

### Log

Every session appends to a log file in the current working directory. The file is named `Policy-Log_ComputerName.log`, where `ComputerName` is the name of the device. Specify a different path with `-LogPath`, which accepts either a full file path or a directory. When a directory is provided, the file is written there with the generated filename.

### Snapshots

Interactive Mode and Silent Mode each save a snapshot of the current registry state before any changes are made. Snapshots are written to the current working directory using a generated filename: `Policy-Snapshot_ComputerName_yyyyMMdd_HHmmss.psd1`. Specify a different path with `-SnapshotPath`, which accepts either a full file path or a directory. When a directory is provided, the file is written there with the generated filename.

### Build Profiles

Build Mode writes selections to the profile file path provided with `-Build`. If the file does not exist, it is created on the first save. If the file already exists, its contents are loaded as the starting state for the session and updated in place. Settings already in the profile file that do not correspond to any setting in the current definitions file are preserved and never modified.

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-DefinitionsPath` | String | Path to a definitions file. Required for Interactive, Build, and Snapshot modes. |
| `-ProfilePath` | String | Path to a profile file to apply. Triggers Silent Mode. |
| `-Build` | String | Path to the profile file to build. Triggers Build Mode. |
| `-Snapshot` | Switch | Triggers Snapshot Mode. |
| `-SnapshotPath` | String | Output path for the snapshot profile. Accepts a full file path or a directory. Only valid with `-Snapshot`. |
| `-LogPath` | String | Output path for the log file. Accepts a full file path or a directory. |
| `-LGPOPath` | String | Explicit path to `LGPO.exe`. If not provided, the script searches the `policy` directory and then the system `PATH`. |

Run `Get-Help .\policy\Invoke-WinHardenPolicy.ps1 -Detailed` for the full parameter reference.
