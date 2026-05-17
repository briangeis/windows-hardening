# Policy Definition Reference: Windows Privacy Defaults

[Policy-WindowsPrivacyDefaults.psd1](../Policy-WindowsPrivacyDefaults.psd1) pairs with Policy-MicrosoftPrivacyConnections to form a complete privacy and hardening baseline for standalone Windows devices. While Policy-MicrosoftPrivacyConnections derives its settings from a single Microsoft article, this definitions file is the product of independent research, with each setting identified and verified through direct system analysis. Settings target Windows 11 default behaviors that, when configured, strengthen privacy and security on a standalone device. This document records the editorial decisions behind each setting.

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
- [Settings Requiring Additional Steps](#settings-requiring-additional-steps)
- [Interdependent Settings](#interdependent-settings)
- [Counterintuitive GPO Behavior](#counterintuitive-gpo-behavior)
- [Settings with Notable Side Effects](#settings-with-notable-side-effects)
- [Settings Without a Group Policy Equivalent](#settings-without-a-group-policy-equivalent)
- [Settings Tree](#settings-tree)

## Telemetry & Reporting

*What data collection pipelines are active beyond the Microsoft-connection controls in Policy-MicrosoftPrivacyConnections?*

Covers data collection pipelines that operate independently of the AllowTelemetry control in Policy-MicrosoftPrivacyConnections. Application Impact Telemetry and the inventory collector profile software outside the diagnostic data pipeline. Diagnostic log and dump limits cap what Windows collects locally, and Windows Error Reporting is a separate crash data channel not blocked by AllowTelemetry.

| PSD1 Section              | HKLM | HKCU | Total |
|---------------------------|:----:|:----:|:-----:|
| Diagnostic Data           | 3    | 0    | 3     |
| Error Reporting           | 1    | 0    | 1     |
| Application Compatibility | 2    | 0    | 2     |
| Input Data                | 1    | 0    | 1     |

## Security Defaults

*Which security-affecting behaviors ship enabled by default on Home and Pro?*

Covers security-affecting behaviors that are enabled by default on Home and Pro but managed centrally in enterprise environments. Removable Media requires all three of its settings applied together to fully close the AutoPlay and AutoRun attack surface. The remaining sections address DNS name resolution exposure, authentication and lock screen defaults, data written to disk, and MDM enrollment.

| PSD1 Section               | HKLM | HKCU | Total |
|----------------------------|:----:|:----:|:-----:|
| Removable Media            | 3    | 0    | 3     |
| Network                    | 2    | 0    | 2     |
| Authentication & Lock Screen | 3  | 0    | 3     |
| Data at Rest               | 3    | 0    | 3     |
| Device Management          | 1    | 0    | 1     |

## Activity & History

*What records does Windows keep locally about activity on this device?*

Covers on-device tracking behaviors that accumulate without explicit user action. Sections address document and app history in the Start menu and taskbar, File Explorer and Windows Search pane search history and account-driven cloud content, and the local clipboard history store. These are distinct from the activity synchronization settings in Policy-MicrosoftPrivacyConnections, which address cloud-side behavior.

| PSD1 Section           | HKLM | HKCU | Total |
|------------------------|:----:|:----:|:-----:|
| Document & App History | 2    | 0    | 2     |
| Search & Explorer      | 1    | 2    | 3     |
| Clipboard              | 1    | 0    | 1     |

## Content Delivery

*What content or applications does Windows deliver to this device without explicit user action?*

Covers content and applications Windows delivers without explicit user action. The Cloud Content section extends the coverage in Policy-MicrosoftPrivacyConnections with tips and account-tailored notifications not addressed by that file. Spotlight covers the Windows 11-specific Spotlight surfaces confirmed by testing to fall outside the master switch in Policy-MicrosoftPrivacyConnections. Search covers behaviors that connect Windows Search to Microsoft services. App Delivery covers the Push To Install service, which allows apps to be installed remotely from a browser or another device. Account Notifications covers Microsoft account prompts that Windows delivers to the Start menu.

| PSD1 Section          | HKLM | HKCU | Total |
|-----------------------|:----:|:----:|:-----:|
| Cloud Content         | 2    | 0    | 2     |
| Spotlight             | 0    | 4    | 4     |
| Search                | 2    | 0    | 2     |
| App Delivery          | 1    | 0    | 1     |
| Account Notifications | 0    | 1    | 1     |

## Windows Update

*What Windows Update behavior needs to be configured on a device without IT management?*

Covers Windows Update behavior on devices without centralized IT policy. Windows Update runs automatically and includes driver updates by default on Home and Pro. Exclude Driver Updates addresses the persistent issue of Windows Update overriding manually managed drivers with incorrect packages or packages that remove companion software.

Policy-MicrosoftPrivacyConnections contains settings that block Windows Update access entirely through WSUS redirection. A user applying those settings has no need for these. A user who wants security updates to continue while controlling timing and content would apply these settings without the blocking ones.

| PSD1 Section    | HKLM | HKCU | Total |
|-----------------|:----:|:----:|:-----:|
| Update Behavior | 2    | 0    | 2     |

## Windows Applications

*What network or data collection behavior do built-in Windows applications have by default?*

Covers privacy and network access settings for built-in Windows applications that have default behaviors warranting configuration. Windows Media Player is included despite its reduced role in Windows 11 because its DRM subsystem contacts Microsoft independently of other controls in this file. Game Recording covers the Windows game capture feature bundled with Windows Game Bar. Windows AI covers the AI-powered features introduced in Windows 11 23H2 and later. Phone Link covers the background connectivity maintained by the Phone Link app.

| PSD1 Section         | HKLM | HKCU | Total |
|----------------------|:----:|:----:|:-----:|
| Windows AI           | 3    | 1    | 4     |
| Phone Link           | 1    | 0    | 1     |
| Game Recording       | 1    | 0    | 1     |
| Windows Media Player | 1    | 2    | 3     |

---

## Settings Distribution by Category

| Category              | HKLM   | HKCU  | Total  |
|-----------------------|:------:|:-----:|:------:|
| Telemetry & Reporting | 7      | 0     | 7      |
| Security Defaults     | 12     | 0     | 12     |
| Activity & History    | 4      | 2     | 6      |
| Content Delivery      | 5      | 5     | 10     |
| Windows Update        | 2      | 0     | 2      |
| Windows Applications  | 6      | 3     | 9      |
| **Totals**            | **36** | **10** | **46** |

## Settings Requiring Additional Steps

### Disable Hibernation and Disable Fast Startup (Data at Rest)

Setting HibernateEnabled=0 prevents new hibernation writes but does not delete the existing hiberfile.sys, which is present on all Windows 11 installations by default. The file may contain a RAM snapshot from the most recent shutdown, including browser sessions and application data. Run `powercfg /H off` separately to both disable hibernation and remove the file. The registry setting alone achieves policy correctness going forward but leaves the existing snapshot on disk.

Fast Startup depends on hibernation infrastructure and should be disabled alongside it. Disabling Fast Startup without first disabling hibernation may allow Fast Startup to re-activate.

## Interdependent Settings

### Disallow AutoPlay for Nonvolume Devices, Disable AutoRun Command Execution, Disable AutoPlay (Removable Media)

All three settings are required to fully close the AutoPlay and AutoRun attack surface. Turn off Autoplay disables the AutoPlay dialog for drive-type devices. Disallow Autoplay for non-volume devices extends this to cameras, phones, and other non-drive devices. Set the default behavior for AutoRun prevents AutoRun.inf command execution independently of whether AutoPlay is active. Any subset of the three leaves a gap.

## Counterintuitive GPO Behavior

### Disable File Explorer Account Insights (Search & Explorer)

The GPO governing this setting is named "Show files based on your account and cloud provider activity." To prevent File Explorer from showing account-based content, the policy must be set to Enabled, which writes DisableGraphRecentItems=1. Setting the policy to Disabled writes DisableGraphRecentItems=0, which enables the feature. The registry value name is self-consistent: 1 disables the feature and 0 does not. The GPO name is counterintuitive because enabling a policy named "Show files" is what prevents the files from being shown.

## Settings with Notable Side Effects

### Disable Windows Error Reporting (Error Reporting)

WER provides crash analysis information useful for diagnosing application and system failures. Disabling it removes this capability. Crash dumps written to disk before the setting is applied are not removed.

### Disable Automatic Windows Update (Update Behavior)

This setting requires manual user action to check for and install updates. Users who do not check regularly will miss security patches, leaving the device exposed to known vulnerabilities. This setting is best suited to users who actively manage their own update schedule.

### Disable Windows Copilot (Windows AI)

The policy controlling the Copilot panel (TurnOffWindowsCopilot) is deprecated as of Windows 11 24H2. In 24H2 and later, Copilot is delivered as a standalone Windows Store app that this policy does not control. On devices running 24H2 or later, no policy-based equivalent exists for this file's scope. The setting is included because it remains effective on Windows 11 23H2 and earlier, where the Copilot panel is a shell component.

### Disable Recall (Windows AI)

Recall requires Copilot+ PC hardware with a dedicated NPU and is not available on standard Windows 11 devices. It is also not documented as applicable to Home edition. The setting has no effect on devices where Recall is unavailable. On supported devices, the policy prevents Recall from being enabled in Settings entirely.

### Disable Click to Do and Disable Settings Agentic Search (Windows AI)

Both features were introduced in Windows 11 24H2. On devices running earlier versions, both settings are inert but safe to apply. On Copilot+ PCs, Click to Do analyzes screen content to provide contextual suggestions; Settings agentic search uses an AI model for natural language queries within the Settings app.

### Disable Smart Multi-Homed Name Resolution (Network)

This setting prevents Windows from sending DNS queries simultaneously to multiple interfaces. It is primarily relevant on devices with multiple active network interfaces, including VPN connections. On devices with a single active interface, the setting has no observable effect.

## Settings Without a Group Policy Equivalent

The following settings have `GPOPath` and `GPOState` set to `$null` in the definitions file. They must be applied via registry on all editions.

| Setting Name         | PSD1 Section | Reason               |
|----------------------|---|----------------------|
| Disable Hibernation  | Data at Rest | No GPO equivalent    |
| Disable Fast Startup | Data at Rest | No GPO equivalent    |

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
