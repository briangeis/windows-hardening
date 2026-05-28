# Policy Definition Reference: Windows Privacy Defaults

[Policy-WindowsPrivacyDefaults.psd1](../Policy-WindowsPrivacyDefaults.psd1) pairs with [Policy-MicrosoftPrivacyConnections](Policy-MicrosoftPrivacyConnections.md) to form a complete privacy and hardening baseline for standalone Windows devices. Settings target Windows 11 default behaviors that create privacy and security exposure, completing the baseline that [Policy-MicrosoftPrivacyConnections](Policy-MicrosoftPrivacyConnections.md) establishes. This file is the product of independent research, with each setting identified and verified through direct system analysis. This document records the editorial decisions behind each setting and also covers the distribution of settings across registry hives, notable side effects and applicability conditions, settings requiring additional steps, interdependencies, counterintuitive Group Policy behavior, and settings without a Group Policy equivalent.

The categories are organized navigation-first: each category answers a specific question a sysadmin asks when hardening a standalone device. Telemetry & Reporting and Security Defaults cover the highest-priority decisions, addressing data collection pipelines and security behaviors that are active by default. Activity & History and Content Delivery cover on-device tracking and unsolicited content delivery. Windows Update addresses automatic installation of system and driver updates. Windows Applications groups privacy and network behaviors specific to individual native applications.

## Contents

**Categories**
- [Telemetry & Reporting](#telemetry--reporting)
- [Security Defaults](#security-defaults)
- [Activity & History](#activity--history)
- [Content Delivery](#content-delivery)
- [Windows Update](#windows-update)
- [Windows Applications](#windows-applications)

**Reference**
- [Settings Distribution by Category](#settings-distribution-by-category)
- [Settings with Notable Side Effects](#settings-with-notable-side-effects)
- [Settings Requiring Additional Steps](#settings-requiring-additional-steps)
- [Interdependent Settings](#interdependent-settings)
- [Counterintuitive GPO Behavior](#counterintuitive-gpo-behavior)
- [Settings Without a Group Policy Equivalent](#settings-without-a-group-policy-equivalent)
- [Settings Tree](#settings-tree)

## Telemetry & Reporting

*What additional data does Windows collect and report to Microsoft?*

Contains data reporting and collection settings for channels that operate outside the diagnostic data pipeline governed by `AllowTelemetry` in [Policy-MicrosoftPrivacyConnections](Policy-MicrosoftPrivacyConnections.md). Windows Error Reporting, Application Impact Telemetry, and the inventory collector each route data to Microsoft through separate mechanisms unaffected by that setting. The Diagnostic Data section is complementary: its settings limit what Windows retains and reports even after `AllowTelemetry` is at minimum.

| PSD1 Section              | HKLM | HKCU | Total |
|---------------------------|:----:|:----:|:-----:|
| Diagnostic Data           | 3    | 0    | 3     |
| Error Reporting           | 1    | 0    | 1     |
| Application Compatibility | 2    | 0    | 2     |
| Input Data                | 1    | 0    | 1     |

## Security Defaults

*What default behaviors introduce security risk on this device?*

Contains security behaviors that ship enabled by default on standalone devices and are not addressed by [Policy-MicrosoftPrivacyConnections](Policy-MicrosoftPrivacyConnections.md). Removable Media requires all three of its settings applied together to fully close the AutoPlay and AutoRun attack surface. The remaining sections address network name resolution exposure, authentication and lock screen defaults, data written to disk by power management features, and MDM enrollment.

| PSD1 Section                 | HKLM | HKCU | Total |
|------------------------------|:----:|:----:|:-----:|
| Removable Media              | 3    | 0    | 3     |
| Network                      | 2    | 0    | 2     |
| Authentication & Lock Screen | 3    | 0    | 3     |
| Data at Rest                 | 3    | 0    | 3     |
| Device Management            | 1    | 0    | 1     |

## Activity & History

*What records does Windows keep locally about activity on this device?*

Contains on-device tracking behaviors that accumulate without explicit user action. Sections address recently opened document and app history in the Start menu, search history in File Explorer and the Search panel, account-driven cloud content in File Explorer, and the local clipboard history store. These settings are distinct from the activity synchronization settings in [Policy-MicrosoftPrivacyConnections](Policy-MicrosoftPrivacyConnections.md), which control cloud-side behavior rather than local records.

| PSD1 Section           | HKLM | HKCU | Total |
|------------------------|:----:|:----:|:-----:|
| Document & App History | 2    | 0    | 2     |
| Search & Explorer      | 1    | 2    | 3     |
| Clipboard              | 1    | 0    | 1     |

## Content Delivery

*What content or applications does Windows deliver to this device without explicit user action?*

Contains content and applications Windows delivers without explicit user action. Cloud Content and Spotlight both address areas not covered by [Policy-MicrosoftPrivacyConnections](Policy-MicrosoftPrivacyConnections.md): Cloud Content covers tips and account-tailored notifications, and Spotlight covers the Windows 11-specific surfaces confirmed by testing to fall outside its global Spotlight disable. The remaining sections cover Search behaviors that connect to Microsoft services, the Push To Install remote app delivery channel, and Microsoft account prompts in the Start menu.

| PSD1 Section          | HKLM | HKCU | Total |
|-----------------------|:----:|:----:|:-----:|
| Cloud Content         | 2    | 0    | 2     |
| Spotlight             | 0    | 4    | 4     |
| Search                | 2    | 0    | 2     |
| App Delivery          | 1    | 0    | 1     |
| Account Notifications | 0    | 1    | 1     |

## Windows Update

*What does Windows Update do by default on this device?*

Contains Windows Update settings for devices that receive updates from Microsoft directly. Unlike the update-blocking approach in [Policy-MicrosoftPrivacyConnections](Policy-MicrosoftPrivacyConnections.md), these settings keep updates available while disabling automatic installation and excluding driver updates. Exclude Driver Updates addresses the persistent issue of Windows Update overriding manually managed drivers with incorrect packages or packages that remove companion software.

| PSD1 Section    | HKLM | HKCU | Total |
|-----------------|:----:|:----:|:-----:|
| Update Behavior | 2    | 0    | 2     |

## Windows Applications

*What do native Windows applications collect or transmit by default?*

Contains privacy and network access settings for native Windows applications with default behaviors warranting configuration. Windows Media Player is included despite its reduced role in Windows 11 because its DRM subsystem contacts Microsoft independently of other controls in this file. The Windows AI section covers features introduced in Windows 11 23H2 and later, some of which require Copilot+ PC hardware and are inert on standard devices.

| PSD1 Section         | HKLM | HKCU | Total |
|----------------------|:----:|:----:|:-----:|
| Windows AI           | 3    | 1    | 4     |
| Phone Link           | 1    | 0    | 1     |
| Game Recording       | 1    | 0    | 1     |
| Windows Media Player | 1    | 2    | 3     |

---

## Settings Distribution by Category

| Category              | HKLM   | HKCU   | Total  |
|-----------------------|:------:|:------:|:------:|
| Telemetry & Reporting | 7      | 0      | 7      |
| Security Defaults     | 12     | 0      | 12     |
| Activity & History    | 4      | 2      | 6      |
| Content Delivery      | 5      | 5      | 10     |
| Windows Update        | 2      | 0      | 2      |
| Windows Applications  | 6      | 3      | 9      |
| **Totals**            | **36** | **10** | **46** |

## Settings with Notable Side Effects

The following settings have effects or applicability conditions that are not apparent from the setting name alone.

### Disable Windows Error Reporting (Error Reporting)

WER provides crash analysis information useful for diagnosing application and system failures. Disabling it removes this capability. Crash dumps written to disk before the setting is applied are not removed.

### Disable Multicast and Smart Multi-Homed Name Resolution (Network)

Both settings are primarily relevant on devices that use a VPN or connect to untrusted networks. LLMNR broadcasts name resolution queries on the local network segment, where they can be intercepted on an untrusted network. Smart Multi-Homed Name Resolution sends DNS queries across all active interfaces simultaneously, which can cause queries to leak across a VPN tunnel to the local interface. On devices with a single interface and no VPN, neither setting has an observable effect.

### Disable Automatic Windows Update (Update Behavior)

Disabling automatic updates requires manual checks to receive security patches. Users who do not check regularly will miss patches, leaving the device exposed to known vulnerabilities.

### Disable Windows Copilot (Windows AI)

The policy controlling the Copilot panel (`TurnOffWindowsCopilot`) is deprecated as of Windows 11 24H2. In 24H2 and later, Copilot is delivered as a standalone Windows Store app that this policy does not control. On devices running 24H2 or later, no policy-based equivalent exists. The setting is included because it remains effective on Windows 11 23H2 and earlier, where the Copilot panel is a shell component.

### Disable Recall (Windows AI)

Recall requires Copilot+ PC hardware with a dedicated NPU and is not present on standard Windows 11 devices. On supported devices, the policy prevents Recall from being enabled in Settings entirely.

### Disable Windows Media DRM Internet Access (Windows Media Player)

Blocking DRM internet access prevents Windows Media DRM clients from acquiring or renewing licenses for protected content. Any media file or stream that requires a new or refreshed license will fail to play. Content already licensed on this device is unaffected.

## Settings Requiring Additional Steps

### Disable Hibernation and Disable Fast Startup (Data at Rest)

Setting `HibernateEnabled` to `0` prevents new hibernation writes but does not remove the existing `hiberfile.sys`. The file may contain a RAM snapshot from the most recent shutdown, including browser sessions and application data. Run `powercfg /H off` separately to disable hibernation and remove the file. Fast Startup depends on the same hibernation infrastructure and should be disabled alongside it. Applying Disable Fast Startup without first disabling hibernation may allow Fast Startup to re-activate.

## Interdependent Settings

### Disable AutoPlay and AutoRun (Removable Media)

All three settings are required to fully close the AutoPlay and AutoRun attack surface. Disable AutoPlay prevents the AutoPlay dialog from launching for drive-type devices. Disallow AutoPlay for Nonvolume Devices extends AutoPlay control to cameras, phones, and other non-drive devices. Disable AutoRun Command Execution prevents `AutoRun.inf` command execution independently of whether AutoPlay is active. Any subset of the three leaves a gap.

## Counterintuitive GPO Behavior

### Disable File Explorer Account Insights (Search & Explorer)

The GPO governing this setting is named `Show files based on your account and cloud provider activity`. To prevent File Explorer from showing account-based content, the policy must be set to Enabled, which writes `DisableGraphRecentItems` to `1`. Setting the policy to Disabled writes `DisableGraphRecentItems` to `0`, which enables the feature. The registry value name is self-consistent: `1` disables the feature and `0` does not. The GPO name is counterintuitive because enabling a policy named `Show files based on your account and cloud provider activity` is what prevents the files from being shown.

## Settings Without a Group Policy Equivalent

The following settings have `GPOPath` and `GPOState` set to `$null` in the definitions file. On Windows Pro, Enterprise, Education, and LTSC editions, these must still be configured via registry even when Group Policy is used for all other settings.

| Setting Name         | PSD1 Section | Reason            |
|----------------------|--------------|-------------------|
| Disable Hibernation  | Data at Rest | No GPO equivalent |
| Disable Fast Startup | Data at Rest | No GPO equivalent |

## Settings Tree

```
Policy-WindowsPrivacyDefaults.psd1
+-- Telemetry & Reporting
|   +-- Diagnostic Data
|   |   +-- Exclude Device Name from Diagnostic Data
|   |   +-- Limit Diagnostic Log Collection
|   |   \-- Limit Dump Collection
|   +-- Error Reporting
|   |   \-- Disable Windows Error Reporting
|   +-- Application Compatibility
|   |   +-- Disable Application Telemetry
|   |   \-- Disable Inventory Collector
|   \-- Input Data
|       \-- Disable Inking and Typing Data Collection
|
+-- Security Defaults
|   +-- Removable Media
|   |   +-- Disallow AutoPlay for Nonvolume Devices
|   |   +-- Disable AutoRun Command Execution
|   |   \-- Disable AutoPlay
|   +-- Network
|   |   +-- Disable Multicast Name Resolution
|   |   \-- Disable Smart Multi-Homed Name Resolution
|   +-- Authentication & Lock Screen
|   |   +-- Turn Off Lock Screen App Notifications
|   |   +-- Disable Automatic Sign-In After Restart
|   |   \-- Disable Local Account Security Questions
|   +-- Data at Rest
|   |   +-- Disable Hibernation
|   |   +-- Disable Fast Startup
|   |   \-- Disable Indexing of Encrypted Files
|   \-- Device Management
|       \-- Disable MDM Enrollment
|
+-- Activity & History
|   +-- Document & App History
|   |   +-- Disable Recently Opened Document History
|   |   \-- Remove Recently Added List from Start Menu
|   +-- Search & Explorer
|   |   +-- Disable File Explorer Search History
|   |   +-- Disable Search History
|   |   \-- Disable File Explorer Account Insights
|   \-- Clipboard
|       \-- Disable Clipboard History
|
+-- Content Delivery
|   +-- Cloud Content
|   |   +-- Disable Windows Tips
|   |   \-- Disable Consumer Account State Content
|   +-- Spotlight
|   |   +-- Disable Spotlight Collection on Desktop
|   |   +-- Disable Windows Welcome Experience
|   |   +-- Disable Spotlight on Action Center
|   |   \-- Disable Spotlight on Settings
|   +-- Search
|   |   +-- Disable Search Highlights
|   |   \-- Disable Cloud Search
|   +-- App Delivery
|   |   \-- Disable Push To Install Service
|   \-- Account Notifications
|       \-- Disable Account Notifications in Start
|
+-- Windows Update
|   \-- Update Behavior
|       +-- Disable Automatic Windows Update
|       \-- Exclude Driver Updates from Windows Update
|
\-- Windows Applications
    +-- Windows AI
    |   +-- Disable Windows Copilot
    |   +-- Disable Recall
    |   +-- Disable Click to Do
    |   \-- Disable Settings Agentic Search
    +-- Phone Link
    |   \-- Disable Phone-PC Linking
    +-- Game Recording
    |   \-- Disable Game Recording and Broadcasting
    \-- Windows Media Player
        +-- Disable Windows Media DRM Internet Access
        +-- Disable CD and DVD Media Information Retrieval
        \-- Disable Music File Media Information Retrieval
```
