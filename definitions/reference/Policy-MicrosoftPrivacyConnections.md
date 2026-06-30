# Policy Definition Reference: Microsoft Privacy Connections

**Source Article:** [Manage connections from Windows 10 and Windows 11 operating system components to Microsoft services](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)

This document maps each setting in [Policy-MicrosoftPrivacyConnections.psd1](Policy-MicrosoftPrivacyConnections.psd1) to its corresponding section in the Microsoft article. It also covers the distribution of settings across registry hives, settings with notable side effects, settings that have no Group Policy equivalent, intentional deviations from the article's registry recommendations, and known inconsistencies in the article's guidance.

The categories are organized navigation-first: each category answers a specific question a sysadmin asks when hardening a standalone device. Telemetry & Diagnostics, Microsoft Cloud Services, and App Permissions cover the highest-priority privacy and compliance decisions. Windows Features and Windows Update cover feature hardening and update policy. Browsers groups all browser-specific configuration. Background Services is a technical catch-all for background infrastructure that does not fit naturally elsewhere and is the least likely to be browsed by most users.

The source article covers both Windows 10 and Windows 11, and some Group Policy display names were renamed between versions. Where names differ, this document uses the Windows 11 names as they appear in the Local Group Policy Editor on Windows 11.

## Contents

**Categories**
- [Telemetry & Diagnostics](#telemetry--diagnostics)
- [Microsoft Cloud Services](#microsoft-cloud-services)
- [App Permissions](#app-permissions)
  - [Device Access](#device-access)
  - [Communication](#communication)
  - [App Behavior](#app-behavior)
- [Windows Features](#windows-features)
- [Windows Update](#windows-update)
- [Browsers](#browsers)
- [Background Services](#background-services)

**Reference**
- [Settings Distribution by Category](#settings-distribution-by-category)
- [Settings with Notable Side Effects](#settings-with-notable-side-effects)
- [Settings Without a Group Policy Equivalent](#settings-without-a-group-policy-equivalent)
- [Settings Sharing a Group Policy](#settings-sharing-a-group-policy)
- [Intentional Deviations from Source Article](#intentional-deviations-from-source-article)
- [Counterintuitive GPO Behavior](#counterintuitive-gpo-behavior)
- [Article Content Not Included](#article-content-not-included)
- [Settings Tree](#settings-tree)  

## Telemetry & Diagnostics

*What is this device reporting to Microsoft?*

The highest-priority privacy decisions. Defender cloud reporting is grouped here because MAPS, sample submission, and MSRT telemetry are data sent to Microsoft regardless of which product generates them.

| PSD1 Section             | Article Section | HKLM | HKCU | Total |
|--------------------------|:---------------:|:----:|:----:|:-----:|
| Feedback & Diagnostics   | 18.16           | 3    | 3    | 6     |
| Advertising & Tracking   | 18.1            | 2    | 1    | 3     |
| Defender Cloud Reporting | 24              | 4    | 0    | 4     |
| Inking & Typing          | 18.21           | 2    | 0    | 2     |

## Microsoft Cloud Services

*Which Microsoft cloud services are connected?*

Settings controlling which Microsoft cloud services this device is permitted to connect to, typically decided when establishing a baseline configuration. Find My Device is included here as a Microsoft cloud location service, not a security tool.

| PSD1 Section             | Article Section | HKLM | HKCU | Total |
|--------------------------|:---------------:|:----:|:----:|:-----:|
| OneDrive                 | 16              | 2    | 0    | 2     |
| Microsoft Account        | 12              | 1    | 0    | 1     |
| Windows Search           | 2               | 4    | 0    | 4     |
| Cross-Device Experiences | 18.1, 21, 30    | 4    | 0    | 4     |
| Find My Device           | 5               | 1    | 0    | 1     |

## App Permissions

*What can apps access on this device?*

Controls app access to device capabilities and personal data. Settings in this category are UWP app capability policies, organized by the type of access they govern. The Location section additionally contains a system-wide location platform setting alongside a setting that applies only to UWP apps.

### Device Access

| PSD1 Section  | Article Section | HKLM | HKCU | Total |
|---------------|:---------------:|:----:|:----:|:-----:|
| Location      | 18.2            | 2    | 0    | 2     |
| Camera        | 18.3            | 1    | 0    | 1     |
| Microphone    | 18.4            | 1    | 0    | 1     |
| Radios        | 18.14           | 1    | 0    | 1     |
| Motion        | 18.18           | 1    | 0    | 1     |
| Other Devices | 18.15           | 2    | 0    | 2     |

### Communication

| PSD1 Section | Article Section | HKLM | HKCU | Total |
|--------------|:---------------:|:----:|:----:|:-----:|
| Account Info | 18.7            | 1    | 0    | 1     |
| Contacts     | 18.8            | 1    | 0    | 1     |
| Calendar     | 18.9            | 1    | 0    | 1     |
| Email        | 18.11           | 1    | 0    | 1     |
| Messaging    | 18.12           | 1    | 0    | 1     |
| Phone Calls  | 18.13           | 1    | 0    | 1     |
| Call History | 18.10           | 1    | 0    | 1     |

### App Behavior

| PSD1 Section       | Article Section | HKLM | HKCU | Total |
|--------------------|:---------------:|:----:|:----:|:-----:|
| Background Apps    | 18.17           | 1    | 0    | 1     |
| Notifications      | 18.5            | 1    | 0    | 1     |
| Voice Activation   | 18.23           | 2    | 0    | 2     |
| Tasks              | 18.19           | 1    | 0    | 1     |
| App Diagnostics    | 18.20           | 1    | 0    | 1     |

## Windows Features

*Which Windows features call home or use cloud content?*

Contains Windows features with network or cloud behavior. Sections are ordered by decision priority: Microsoft Store leads as the most consequential configuration decision, Windows-specific features follow, and legacy sections trail. Browser-specific SmartScreen settings remain in Browsers.

| PSD1 Section               | Article Section | HKLM | HKCU | Total |
|----------------------------|:---------------:|:----:|:----:|:-----:|
| Microsoft Store            | 18.1, 24.1, 26  | 4    | 1    | 5     |
| Windows Spotlight          | 25              | 1    | 1    | 2     |
| Widgets                    | 18.24, 32       | 2    | 0    | 2     |
| Start Menu Personalization | 18.1, 33        | 1    | 1    | 2     |
| Speech Recognition         | 18.6            | 2    | 0    | 2     |
| Push Notifications         | 10              | 1    | 0    | 1     |
| Online Tips                | 8               | 1    | 0    | 1     |
| Apps for Websites          | 27              | 1    | 0    | 1     |
| Offline Maps               | 15              | 2    | 0    | 2     |
| Activity History           | 18.22           | 3    | 0    | 3     |

## Windows Update

*What does Windows automatically download or update from Microsoft?*

Groups Windows Update alongside settings that share the same core behavior: Windows pulling software, data, or configuration from Microsoft automatically. Insider Preview Builds is grouped here as an update channel rather than a Windows feature.

| PSD1 Section            | Article Section | HKLM | HKCU | Total |
|-------------------------|:---------------:|:----:|:----:|:-----:|
| Windows Update Settings | 29              | 6    | 0    | 6     |
| Insider Preview Builds  | 7               | 1    | 0    | 1     |
| Delivery Optimization   | 28              | 1    | 0    | 1     |
| Storage Health          | 20              | 1    | 0    | 1     |
| Services Configuration  | 31              | 1    | 0    | 1     |

## Browsers

*How are Microsoft browsers configured?*

Each section orders settings by browser-focused decision priority: data-to-Microsoft settings lead, followed by credential storage, security features, and UI and startup defaults. Microsoft Edge Update is a standalone section for update control, separated from Microsoft Edge because disabling updates is a security concern rather than a privacy decision.

| PSD1 Section              | Article Section | HKLM | HKCU | Total |
|---------------------------|:---------------:|:----:|:----:|:-----:|
| Microsoft Edge            | 13.2            | 12   | 0    | 12    |
| Microsoft Edge Update     | 13.2            | 2    | 0    | 2     |
| Internet Explorer         | 8, 8.1          | 10   | 3    | 13    |

## Background Services

*Which background Windows services connect to external networks or Microsoft?*

The technical catch-all for background infrastructure settings. Sections are ordered by inverse decision priority, with the least consequential settings first and those with significant side effects last.

| PSD1 Section                        | Article Section | HKLM | HKCU | Total |
|-------------------------------------|:---------------:|:----:|:----:|:-----:|
| Device Metadata Retrieval           | 4               | 1    | 0    | 1     |
| Font Streaming                      | 6               | 1    | 0    | 1     |
| Software Protection Platform        | 19              | 1    | 0    | 1     |
| Teredo                              | 22              | 1    | 0    | 1     |
| License Manager                     | 9               | 1    | 0    | 1     |
| Network Connection Status Indicator | 14              | 1    | 0    | 1     |
| Date & Time                         | 3               | 2    | 0    | 2     |
| Windows SmartScreen                 | 24.1            | 1    | 0    | 1     |
| Root Certificates                   | 1               | 1    | 0    | 1     |

---

## Settings Distribution by Category

| Category                 |  HKLM   |  HKCU  |  Total  |
|--------------------------|:-------:|:------:|:-------:|
| Telemetry & Diagnostics  | 11      | 4      | 15      |
| Microsoft Cloud Services | 12      | 0      | 12      |
| App Permissions          | 21      | 0      | 21      |
| Windows Features         | 18      | 3      | 21      |
| Windows Update           | 10      | 0      | 10      |
| Browsers                 | 24      | 3      | 27      |
| Background Services      | 10      | 0      | 10      |
| **Totals**               | **106** | **10** | **116** |

## Settings with Notable Side Effects

The following settings carry consequences that are not obvious from the setting name alone. Applying any of these without understanding their effects can introduce failures that are difficult to trace back to the registry change.

### Disable Microsoft Account Sign-In Assistant (Microsoft Cloud Services)

Disabling the Microsoft Account Sign-In Assistant service removes the foundation for all Microsoft Account functionality on the device. Sign-in will fail for the Microsoft Store, OneDrive, Office, Xbox, and Windows Update when those services require Microsoft Account authentication.

### Disable Cross-Device Experiences (Microsoft Cloud Services)

Disabling the Connected Devices Platform removes the infrastructure underlying cross-device features. Phone Link features such as SMS mirroring and call handling through the Windows app will not function.

### Disable Windows Update Access (Windows Update)

Blocks all Windows Update features at the system level. The device will not check for, download, or install security patches, cumulative updates, or driver updates while this setting is applied.

### Disable Edge SmartScreen (Browsers)

Removes SmartScreen protection within Microsoft Edge. Malicious URLs, phishing pages, and downloads encountered through Edge will not be checked or blocked.

### Disable Edge Auto Update (Browsers)

Prevents EdgeUpdate from automatically installing security patches to Edge. Vulnerabilities in Edge will not be remediated without manually downloading and running a new Edge installer.

### Disable IE SmartScreen (Browsers)

Removes SmartScreen protection within Internet Explorer. Malicious URLs and phishing pages encountered through IE will not be checked or blocked.

### License Manager (Background Services)

Disabling the LicenseManager service can prevent Store-purchased apps from launching and may cause Microsoft 365 subscription validation failures.

### Teredo (Background Services)

Disabling Teredo may affect Xbox gaming features and Delivery Optimization in certain network configurations.

### Network Connection Status Indicator (Background Services)

Disabling NCSI active tests removes the taskbar network connectivity indicator. Applications that query Windows for network connectivity status may also behave unexpectedly.

### Date & Time (Background Services)

The two settings together prevent Windows from synchronizing time automatically. The resulting time drift can cause TLS certificate validation failures and break TOTP-based two-factor authentication.

### Windows SmartScreen (Background Services)

Disabling Windows SmartScreen removes system-wide malware and phishing protection in Explorer and for file downloads. Unlike the browser-specific SmartScreen settings in Browsers, this setting affects the entire operating system.

### Root Certificates (Background Services)

The most consequential setting in the file. Disabling automatic root certificate updates can break the TLS trust chain in ways that are difficult to diagnose: certificate validation failures, software refusing to run, and websites becoming inaccessible without an obvious error pointing to the root cause.

## Settings Without a Group Policy Equivalent

The following 23 settings have `GPOPath` and `GPOState` set to `$null` in the definitions file. In each case, either the article provides no GPO, or the GPO requires ADMX templates not present in a standard Windows 11 installation. On Windows Pro, Enterprise, Education, and LTSC editions, these must still be configured via registry even when Group Policy is used for all other settings.

| Setting Name                                | Article Section | PSD1 Section               | Reason                                    |
|---------------------------------------------|:---------------:|----------------------------|-------------------------------------------|
| Set Time Sync to NoSync                     | 3               | Date & Time                | Registry-only, NTP Client GPO is separate |
| Disable License Manager Service             | 9               | License Manager            | Article provides no GPO                   |
| Disable Microsoft Account Sign-In Assistant | 12              | Microsoft Account          | Article provides no GPO                   |
| Disable Search Suggestions                  | 13.2            | Microsoft Edge             | Requires Edge ADMX                        |
| Enable Do Not Track                         | 13.2            | Microsoft Edge             | Requires Edge ADMX                        |
| Disable Password Manager                    | 13.2            | Microsoft Edge             | Requires Edge ADMX                        |
| Disable Address Autofill                    | 13.2            | Microsoft Edge             | Requires Edge ADMX                        |
| Disable Credit Card Autofill                | 13.2            | Microsoft Edge             | Requires Edge ADMX                        |
| Disable Default Search Provider             | 13.2            | Microsoft Edge             | Requires Edge ADMX                        |
| Set New Tab to Blank                        | 13.2            | Microsoft Edge             | Requires Edge ADMX                        |
| Disable Startup Restore                     | 13.2            | Microsoft Edge             | Requires Edge ADMX                        |
| Set Startup URL to Blank                    | 13.2            | Microsoft Edge             | Requires Edge ADMX                        |
| Disable First Run Experience                | 13.2            | Microsoft Edge             | Requires Edge ADMX                        |
| Disable Edge Auto Update                    | 13.2            | Microsoft Edge Update      | Requires Edge Update ADMX                 |
| Disable Auto Update Check                   | 13.2            | Microsoft Edge Update      | Requires Edge Update ADMX                 |
| Disable Edge Update Experimentation Service | 13.2            | Microsoft Edge             | Requires Edge Update ADMX                 |
| Disable Language List Access                | 18.1            | Advertising & Tracking     | HKCU only, no GPO available               |
| Disable App Launch Tracking                 | 18.1            | Start Menu Personalization | HKCU only, no GPO available               |
| Disable SmartScreen for Store Apps          | 18.1            | Microsoft Store            | HKCU only, no GPO available               |
| Set Feedback Period to Zero                 | 18.16           | Feedback & Diagnostics     | HKCU only, no GPO available               |
| Set Feedback Count to Zero                  | 18.16           | Feedback & Diagnostics     | HKCU only, no GPO available               |
| Disable News and Interests                  | 18.24           | Widgets                    | Article provides no GPO                   |
| Disable MSRT Diagnostic Data                | 24              | Defender Cloud Reporting   | Article explicitly notes no GPO           |

## Settings Sharing a Group Policy

The following GPOs are each controlled by more than one setting in the definitions file. A single entry appears in `gpedit.msc` for each GPO regardless of how many registry values it controls, so the total number of `gpedit.msc` entries is lower than the total number of settings in the file.

| Group Policy                                         | Setting Names                                                                                                                     | Count |
|------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|:-----:|
| `Turn off automatic learning`                        | Restrict Implicit Text Collection, Restrict Implicit Ink Collection                                                               | 2     |
| `Do not sync`                                        | Disable Settings Sync, Disable Settings Sync User Override                                                                        | 2     |
| `Turn off the advertising ID`                        | Disable Advertising ID (Feature), Disable Advertising ID (Policy)                                                                 | 2     |
| `Configure app install control`                      | Suppress Store App Recommendations (Policy), Suppress Store App Recommendations (Source)                                          | 2     |
| `Specify intranet Microsoft update service location` | Set WSUS Server to Blank, Set WSUS Status Server to Blank, Set Alternate Download Server to Blank, Enforce Intranet Update Server | 4     |
| `Disable changing home page settings`                | Set IE Home Page to Blank, Lock IE Home Page Setting                                                                              | 2     |

## Intentional Deviations from Source Article

The following settings use a different registry approach than the article specifies. These are deliberate choices where the definitions file favors the registry path that aligns with how the policy actually functions in Windows, rather than the path the article literally provides. Each deviation is documented here for traceability.

### IE First Run Wizard and New Tab Behavior (Section 8)

Two settings are affected: **Disable IE First Run Wizard** (`DisableFirstRunCustomize`) and **Set IE New Tab to Blank** (`NewTabPageShow`). The article specifies both under User Configuration, writing to `HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\*`. The definitions file uses the Computer Configuration equivalents, writing to `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\*`. Computer Configuration applies machine-wide to all users on the device, consistent with the toolkit's preference for HKLM settings and more appropriate for standalone device hardening.

### Edge Update Settings (Section 13.2)

Three settings are affected: **Disable Edge Auto Update**, **Disable Auto Update Check**, and **Disable Edge Update Experimentation Service**. The article specifies all three at `HKLM\...\Policies\Microsoft\Edge\EdgeUpdate`. The definitions file corrects the path to `HKLM\...\Policies\Microsoft\EdgeUpdate` and the experimentation setting's value name from `ExperimentationAndConfigurationServiceControl` to `UpdaterExperimentationAndConfigurationServiceControl`.

### Disable Online Speech Recognition (Section 18.6)

The article specifies the registry path at `HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy\HasAccepted`. The definitions file uses `HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization`, which is the registry path written by the Computer Configuration Group Policy `Allow users to enable online speech recognition services`. The HKLM Policies path applies machine-wide, consistent with the toolkit's preference for HKLM settings.

### Inking & Typing Settings (Section 18.21)

Two settings are affected: **Restrict Implicit Text Collection** (`RestrictImplicitTextCollection`) and **Restrict Implicit Ink Collection** (`RestrictImplicitInkCollection`). The article specifies both registry values at `HKCU\Software\Microsoft\InputPersonalization`. The Computer Configuration GPO that controls both values (`Control Panel > Regional and Language Options > Handwriting personalization > Turn off automatic learning`) writes to `HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization` when set to Enabled, confirmed by applying the policy on a Windows 11 Pro device. The definitions file uses the HKLM Policies path consistent with Computer Configuration policy behavior.

The article assigns `RestrictImplicitTextCollection` to `Windows Components > Text Input > Improve inking and typing recognition` and `RestrictImplicitInkCollection` to a User Configuration variant of `Handwriting personalization > Turn off automatic learning`. Both attributions are incorrect. Both values are written by the Computer Configuration `Turn off automatic learning` GPO. The Text Input GPO controls a different registry value unrelated to these settings. The definitions file assigns both values to the Computer Configuration `Turn off automatic learning` GPO.

### Disable Cloud Optimized Content (Section 25)

The article specifies the registry path at `HKCU\...\Policies\Microsoft\Windows\CloudContent`, but the definitions file uses `HKLM\...\Policies\Microsoft\Windows\CloudContent`. The article's own GPO for this setting is under Computer Configuration, which writes to HKLM, not HKCU. The article's registry instruction contradicts its own GPO guidance. The definitions file follows the HKLM path consistent with Computer Configuration policy behavior.

### Disable Recommendations (Section 33)

The article specifies `HKCU\...\Explorer\Advanced\Start_TrackDocs` set to `0`, which disables document tracking that feeds the Recommendations section. The definitions file instead uses `HKLM\...\Policies\Microsoft\Windows\Explorer\HideRecommendedSection` set to `1`, which is the registry key corresponding to the article's own GPO recommendation (`Remove Recommended from Start Menu`). This approach is machine-wide (HKLM, consistent with the majority of settings in the file), directly hides the Recommendations UI element rather than indirectly reducing its content, and aligns with the article's GPO guidance rather than its registry guidance.

## Counterintuitive GPO Behavior

### Disable All Store Apps (Microsoft Store)

The GPO governing this setting is named `Disable all apps from Microsoft Store`. To disable all apps from the Store, the policy must be set to Disabled, which writes `DisableStoreApps` to `1`. Setting the policy to Enabled writes `DisableStoreApps` to `0`, enabling Store apps. The registry value name is self-consistent: `1` disables Store apps and `0` does not. The GPO name is counterintuitive because disabling a policy named `Disable all apps from Microsoft Store` is what disables Store apps.

## Article Content Not Included

### Excluded Sections

| Article Section | Title             | Reason                                                                                                                                               |
|:---------------:|-------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| 11              | Windows Mail      | The Windows Mail application was removed in Windows 8 and is not present on any Windows 10 or Windows 11 installation.                               |
| 13.1            | Legacy Edge       | Legacy Edge does not exist on Windows 11. Chromium Edge does not read these registry paths.                                                          |
| 17              | Preinstalled apps | Handled via PowerShell `Remove-AppxPackage` commands, not registry settings.                                                                         |
| 23              | Wi-Fi Sense       | The Wi-Fi Sense feature was removed in Windows 10 version 1703 (April 2017) and is not present on any current Windows 10 or Windows 11 installation. |

### Excluded Settings

| Article Section | Registry Value            | Reason                                                                                                       |
|:---------------:|---------------------------|--------------------------------------------------------------------------------------------------------------|
| 21              | `CloudServiceSyncEnabled` | The Windows Messaging app that used this registry value was removed in Windows 10 version 1703 (April 2017). |
| 18.12           | `AllowMessageSync`        | Targets the same Windows Messaging platform cloud sync infrastructure as `CloudServiceSyncEnabled`.          |

## Settings Tree

```
Policy-MicrosoftPrivacyConnections.psd1
+-- Telemetry & Diagnostics
|   +-- Feedback & Diagnostics
|   |   +-- Set Diagnostic Data to Minimum
|   |   +-- Disable Tailored Experiences
|   |   +-- Disable Consumer Experiences
|   |   +-- Disable Feedback Notifications
|   |   +-- Set Feedback Period to Zero
|   |   \-- Set Feedback Count to Zero
|   +-- Advertising & Tracking
|   |   +-- Disable Advertising ID (Feature)
|   |   +-- Disable Advertising ID (Policy)
|   |   \-- Disable Language List Access
|   +-- Defender Cloud Reporting
|   |   +-- Disable MAPS Reporting
|   |   +-- Disable Sample Submission
|   |   +-- Disable MSRT Diagnostic Data
|   |   \-- Disable Enhanced Notifications
|   \-- Inking & Typing
|       +-- Restrict Implicit Text Collection
|       \-- Restrict Implicit Ink Collection
|
+-- Microsoft Cloud Services
|   +-- OneDrive
|   |   +-- Disable OneDrive File Storage
|   |   \-- Disable OneDrive Network Traffic Before Sign-In
|   +-- Microsoft Account
|   |   \-- Disable Microsoft Account Sign-In Assistant
|   +-- Windows Search
|   |   +-- Disable Web Results in Search
|   |   +-- Disable Web Search
|   |   +-- Disable Search Location
|   |   \-- Disable Cortana
|   +-- Cross-Device Experiences
|   |   +-- Disable Cross-Device Experiences
|   |   +-- Disable Settings Sync
|   |   +-- Disable Settings Sync User Override
|   |   \-- Disable Cloud Clipboard
|   \-- Find My Device
|       \-- Disable Find My Device
|
+-- App Permissions
|   +-- Device Access
|   |   +-- Location
|   |   |   +-- Disable Location Services
|   |   |   \-- Deny App Access to Location
|   |   +-- Camera
|   |   |   \-- Deny App Access to Camera
|   |   +-- Microphone
|   |   |   \-- Deny App Access to Microphone
|   |   +-- Radios
|   |   |   \-- Deny App Access to Radios
|   |   +-- Motion
|   |   |   \-- Deny App Access to Motion
|   |   \-- Other Devices
|   |       +-- Deny Sync with Unpaired Devices
|   |       \-- Deny App Access to Trusted Devices
|   +-- Communication
|   |   +-- Account Info
|   |   |   \-- Deny App Access to Account Info
|   |   +-- Contacts
|   |   |   \-- Deny App Access to Contacts
|   |   +-- Calendar
|   |   |   \-- Deny App Access to Calendar
|   |   +-- Email
|   |   |   \-- Deny App Access to Email
|   |   +-- Messaging
|   |   |   \-- Deny App Access to Messaging
|   |   +-- Phone Calls
|   |   |   \-- Deny App Access to Phone Calls
|   |   \-- Call History
|   |       \-- Deny App Access to Call History
|   \-- App Behavior
|       +-- Background Apps
|       |   \-- Deny Background App Execution
|       +-- Notifications
|       |   \-- Deny App Access to Notifications
|       +-- Voice Activation
|       |   +-- Deny Voice Activation
|       |   \-- Deny Voice Activation Above Lock
|       +-- Tasks
|       |   \-- Deny App Access to Tasks
|       \-- App Diagnostics
|           \-- Deny App Access to Diagnostics
|
+-- Windows Features
|   +-- Microsoft Store
|   |   +-- Disable All Store Apps
|   |   +-- Disable Auto Download and Install of Updates
|   |   +-- Suppress Store App Recommendations (Policy)
|   |   +-- Suppress Store App Recommendations (Source)
|   |   \-- Disable SmartScreen for Store Apps
|   +-- Windows Spotlight
|   |   +-- Disable All Spotlight Features
|   |   \-- Disable Cloud Optimized Content
|   +-- Widgets
|   |   +-- Disable Widgets
|   |   \-- Disable News and Interests
|   +-- Start Menu Personalization
|   |   +-- Disable Recommendations
|   |   \-- Disable App Launch Tracking
|   +-- Speech Recognition
|   |   +-- Disable Online Speech Recognition
|   |   \-- Disable Speech Model Updates
|   +-- Push Notifications
|   |   \-- Disable Notification Network Traffic
|   +-- Online Tips
|   |   \-- Disable Online Tips
|   +-- Apps for Websites
|   |   \-- Disable App URI Handlers
|   +-- Offline Maps
|   |   +-- Disable Auto Download Map Data
|   |   \-- Disable Unsolicited Map Network Traffic
|   \-- Activity History
|       +-- Disable Activity Feed
|       +-- Disable Publish User Activities
|       \-- Disable Upload User Activities
|
+-- Windows Update
|   +-- Windows Update Settings
|   |   +-- Disable Windows Update Access
|   |   +-- Disable Windows Update Internet Locations
|   |   +-- Set WSUS Server to Blank
|   |   +-- Set WSUS Status Server to Blank
|   |   +-- Set Alternate Download Server to Blank
|   |   \-- Enforce Intranet Update Server
|   +-- Insider Preview Builds
|   |   \-- Disable Insider Preview Builds
|   +-- Delivery Optimization
|   |   \-- Disable Peer-to-Peer Update Sharing
|   +-- Storage Health
|   |   \-- Disable Disk Health Model Updates
|   \-- Services Configuration
|       \-- Disable Services Configuration
|
+-- Browsers
|   +-- Microsoft Edge
|   |   +-- Disable Search Suggestions
|   |   +-- Enable Do Not Track
|   |   +-- Disable Password Manager
|   |   +-- Disable Address Autofill
|   |   +-- Disable Credit Card Autofill
|   |   +-- Disable Default Search Provider
|   |   +-- Disable Edge SmartScreen
|   |   +-- Set New Tab to Blank
|   |   +-- Disable Startup Restore
|   |   +-- Set Startup URL to Blank
|   |   +-- Disable First Run Experience
|   |   \-- Disable Edge Update Experimentation Service
|   +-- Microsoft Edge Update
|   |   +-- Disable Edge Auto Update
|   |   \-- Disable Auto Update Check
|   \-- Internet Explorer
|       +-- Disable Suggested Sites
|       +-- Disable Enhanced Suggestions
|       +-- Disable Browser Geolocation
|       +-- Disable AutoComplete for Web Addresses
|       +-- Disable Feed Background Sync
|       +-- Disable IE SmartScreen
|       +-- Disable ActiveX VersionList Download
|       +-- Set IE Home Page to Blank
|       +-- Lock IE Home Page Setting
|       +-- Disable IE First Run Wizard
|       +-- Set IE New Tab to Blank
|       +-- Disable Compatibility View Editing
|       \-- Disable Flip Ahead
|
\-- Background Services
    +-- Device Metadata Retrieval
    |   \-- Disable Device Metadata Retrieval
    +-- Font Streaming
    |   \-- Disable Font Streaming
    +-- Software Protection Platform
    |   \-- Disable KMS Online Validation
    +-- Teredo
    |   \-- Disable Teredo
    +-- License Manager
    |   \-- Disable License Manager Service
    +-- Network Connection Status Indicator
    |   \-- Disable NCSI Active Tests
    +-- Date & Time
    |   +-- Set Time Sync to NoSync
    |   \-- Disable NTP Client
    +-- Windows SmartScreen
    |   \-- Disable SmartScreen
    \-- Root Certificates
        \-- Disable Automatic Root Certificate Updates
```
