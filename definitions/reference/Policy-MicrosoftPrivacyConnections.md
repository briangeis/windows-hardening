# Policy Definition Reference: Microsoft Privacy Connections

**Source Article:** [Manage connections from Windows 10 and Windows 11 operating system components to Microsoft services](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)

This document maps each setting in [Policy-MicrosoftPrivacyConnections.psd1](Policy-MicrosoftPrivacyConnections.psd1) to its corresponding section in the Microsoft article. It also covers the distribution of settings across registry hives, settings with notable side effects, settings that have no Group Policy equivalent, intentional deviations from the article's registry recommendations, and known inconsistencies in the article's guidance.

The areas are organized navigation-first: each area answers a specific question a sysadmin asks when hardening a standalone device. Telemetry & Diagnostics, Microsoft Cloud Services, and App Permissions cover the highest-priority privacy and compliance decisions. Windows Features and Windows Update cover feature hardening and update policy. Browsers groups all browser-specific configuration. Background Services is a technical catch-all for background infrastructure that does not fit naturally elsewhere and is the least likely to be browsed by most users.

## Contents

**Areas**
- [Telemetry & Diagnostics](#telemetry--diagnostics)
- [Microsoft Cloud Services](#microsoft-cloud-services)
- [App Permissions](#app-permissions)
  - [Personalization & Tracking](#personalization--tracking)
  - [Device Access](#device-access)
  - [Communication](#communication)
  - [App Behavior](#app-behavior)
- [Windows Features](#windows-features)
- [Windows Update](#windows-update)
- [Browsers](#browsers)
- [Background Services](#background-services)

**Reference**
- [Settings Distribution by Area](#settings-distribution-by-area)
- [Settings with Notable Side Effects](#settings-with-notable-side-effects)
- [Settings Without a Group Policy Equivalent](#settings-without-a-group-policy-equivalent)
- [Intentional Deviations from Source Article](#intentional-deviations-from-source-article)
- [Known Article Inconsistencies](#known-article-inconsistencies)
- [Article Sections Not Included as Registry Settings](#article-sections-not-included-as-registry-settings)
- [Settings Tree](#settings-tree)  

## Telemetry & Diagnostics

*What is this device reporting to Microsoft?*

The highest-priority privacy decisions. Defender cloud reporting is grouped here because MAPS, sample submission, and MSRT telemetry are data sent to Microsoft regardless of which product generates them.

| PSD1 Section             | Article Section | HKLM | HKCU | Total |
|--------------------------|:---------------:|:----:|:----:|:-----:|
| Feedback & Diagnostics   | 18.16           | 3    | 3    | 6     |
| Defender Cloud Reporting | 24              | 4    | 0    | 4     |
| Inking & Typing          | 18.21           | 0    | 2    | 2     |

## Microsoft Cloud Services

*Which Microsoft cloud services are connected?*

Settings controlling which Microsoft cloud services this device is permitted to connect to, typically decided when establishing a baseline configuration. Find My Device is included here as a Microsoft cloud location service, not a security tool.

| PSD1 Section       | Article Section | HKLM | HKCU | Total |
|--------------------|:---------------:|:----:|:----:|:-----:|
| Cortana & Search   | 2               | 4    | 0    | 4     |
| OneDrive           | 16              | 2    | 0    | 2     |
| Microsoft Account  | 12              | 1    | 0    | 1     |
| Cloud Sync         | 21, 30          | 3    | 1    | 4     |
| Find My Device     | 5               | 1    | 0    | 1     |
| Windows Mail       | 11              | 1    | 0    | 1     |

## App Permissions

*What can apps access on this device?*

Mirrors the structure of the source article's Privacy & Security section (article section 18), with two exceptions: Feedback & Diagnostics and Inking & Typing move to Telemetry & Diagnostics as settings that are telemetry in function.

### Personalization & Tracking

| PSD1 Section             | Article Section | HKLM | HKCU | Total |
|--------------------------|:---------------:|:----:|:----:|:-----:|
| Advertising ID           | 18.1            | 2    | 0    | 2     |
| Personalization Tracking | 18.1            | 0    | 2    | 2     |
| Cross-Device Experiences | 18.1            | 1    | 0    | 1     |

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
| Messaging    | 18.12           | 2    | 0    | 2     |
| Phone Calls  | 18.13           | 1    | 0    | 1     |
| Call History | 18.10           | 1    | 0    | 1     |

### App Behavior

| PSD1 Section       | Article Section | HKLM | HKCU | Total |
|--------------------|:---------------:|:----:|:----:|:-----:|
| Activity History   | 18.22           | 3    | 0    | 3     |
| Background Apps    | 18.17           | 1    | 0    | 1     |
| Notifications      | 18.5            | 1    | 0    | 1     |
| Speech             | 18.6            | 1    | 1    | 2     |
| Voice Activation   | 18.23           | 2    | 0    | 2     |
| Tasks              | 18.19           | 1    | 0    | 1     |
| News and Interests | 18.24           | 1    | 0    | 1     |
| App Diagnostics    | 18.20           | 1    | 0    | 1     |

## Windows Features

*Which Windows features call home or use cloud content?*

Contains Windows-native features with network or cloud behavior. Sections are ordered by decision priority: Microsoft Store leads as the most consequential configuration decision, Windows 11-specific features follow, and legacy sections trail. Browser-specific SmartScreen settings remain in Browsers.

| PSD1 Section      | Article Section | HKLM | HKCU | Total |
|-------------------|:---------------:|:----:|:----:|:-----:|
| Microsoft Store   | 18.1, 24.1, 26  | 4    | 1    | 5     |
| Windows Spotlight | 25              | 1    | 1    | 2     |
| Widgets           | 32              | 1    | 0    | 1     |
| Recommendations   | 33              | 1    | 0    | 1     |
| Offline Maps      | 15              | 2    | 0    | 2     |
| Live Tiles        | 10              | 1    | 0    | 1     |
| Apps for Websites | 27              | 1    | 0    | 1     |

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

Sections are ordered most-current-first: Chromium Edge, Legacy Edge, Internet Explorer. Within each section, settings follow browser-centric decision priority: data-to-Microsoft settings lead, followed by credential storage, security features, UI and startup defaults, and update behavior.

| PSD1 Section              | Article Section | HKLM | HKCU | Total |
|---------------------------|:---------------:|:----:|:----:|:-----:|
| Microsoft Edge (Chromium) | 13.2            | 14   | 0    | 14    |
| Microsoft Edge (Legacy)   | 13              | 11   | 0    | 11    |
| Internet Explorer         | 8, 8.1          | 9    | 5    | 14    |

## Background Services

*Which background Windows services connect to external networks or Microsoft?*

The technical catch-all for background infrastructure settings. Sections are ordered by inverse decision priority: the safest settings appear first so sysadmins who navigate here for routine hardening encounter low-risk settings before reaching those with significant consequences.

| PSD1 Section                        | Article Section | HKLM | HKCU | Total |
|-------------------------------------|:---------------:|:----:|:----:|:-----:|
| Device Metadata Retrieval           | 4               | 1    | 0    | 1     |
| Font Streaming                      | 6               | 1    | 0    | 1     |
| Wi-Fi Sense                         | 23              | 1    | 0    | 1     |
| License Manager                     | 9               | 1    | 0    | 1     |
| Teredo                              | 22              | 1    | 0    | 1     |
| Software Protection Platform        | 19              | 1    | 0    | 1     |
| Network Connection Status Indicator | 14              | 1    | 0    | 1     |
| Date & Time                         | 3               | 2    | 0    | 2     |
| Windows SmartScreen                 | 24.1            | 1    | 0    | 1     |
| Root Certificates                   | 1               | 1    | 0    | 1     |

---

## Settings Distribution by Area

| Area                     |  HKLM   |  HKCU  |  Total  |
|--------------------------|:-------:|:------:|:-------:|
| Telemetry & Diagnostics  | 7       | 5      | 12      |
| Microsoft Cloud Services | 12      | 1      | 13      |
| App Permissions          | 30      | 3      | 33      |
| Windows Features         | 11      | 2      | 13      |
| Windows Update           | 10      | 0      | 10      |
| Browsers                 | 34      | 5      | 39      |
| Background Services      | 11      | 0      | 11      |
| **Totals**               | **115** | **16** | **131** |

## Settings with Notable Side Effects

The following settings in Background Services carry consequences that are not obvious from the setting name alone. Applying any of these settings without understanding their effects can introduce failures that are difficult to trace back to the registry change.

### Teredo (Background Services)

Disabling may affect Xbox gaming features and Delivery Optimization in certain network configurations.

### Network Connection Status Indicator (Background Services)

Disabling NCSI active tests removes the taskbar network connectivity indicator. Applications that check network status before attempting connections may also behave unexpectedly.

### Date & Time (Background Services)

The two settings together prevent Windows from synchronizing time automatically. The resulting time drift can cause TLS certificate validation failures and break TOTP-based two-factor authentication.

### Windows SmartScreen (Background Services)

Disabling removes system-wide malware and phishing protection in Explorer and for file downloads. Unlike the browser-specific SmartScreen settings in Browsers, this setting affects the entire operating system.

### Root Certificates (Background Services)

The most consequential setting in the file. Disabling automatic root certificate updates can break the TLS trust chain in ways that are difficult to diagnose: certificate validation failures, software refusing to run, and websites becoming inaccessible without an obvious error pointing to the root cause.

## Settings Without a Group Policy Equivalent

The following 13 settings have no corresponding Group Policy per the article. Their `GPOPath` and `GPOState` fields are set to `$null` in the definitions file. On Pro/Enterprise editions, these must be configured via registry even when Group Policy is available for all other settings.

| Setting Name                                | Article Section | PSD1 Section             | Reason                                                       |
|---------------------------------------------|:---------------:|--------------------------|--------------------------------------------------------------|
| Set Time Sync to NoSync                     | 3               | Date & Time              | Registry-only; the NTP Client GPO is a separate setting      |
| Disable License Manager Service             | 9               | License Manager          | Registry-only; article provides no GPO                       |
| Disable Windows Mail                        | 11              | Windows Mail             | Registry-only; article provides no GPO                       |
| Disable Microsoft Account Sign-In Assistant | 12              | Microsoft Account        | Registry-only; article provides no GPO                       |
| Disable Language List Access                | 18.1            | Personalization Tracking | HKCU registry-only; article provides UI or registry only     |
| Disable App Launch Tracking                 | 18.1            | Personalization Tracking | HKCU registry-only; article provides UI or registry only     |
| Disable SmartScreen for Store Apps          | 18.1            | Microsoft Store          | HKCU registry-only; article provides UI or registry only     |
| Set Feedback Frequency to Never (Period)    | 18.16           | Feedback & Diagnostics   | HKCU registry-only; article provides no GPO for these values |
| Set Feedback Frequency to Never (Count)     | 18.16           | Feedback & Diagnostics   | HKCU registry-only; article provides no GPO for these values |
| Disable News and Interests                  | 18.24           | News and Interests        | Registry-only; article provides no GPO                       |
| Disable Messaging Cloud Sync                | 21              | Cloud Sync               | Article explicitly notes no GPO for this registry key        |
| Disable MSRT Diagnostic Data                | 24              | Defender Cloud Reporting | Article explicitly notes no GPO for MSRT diagnostic data     |
| Disable Services Configuration              | 31              | Services Configuration   | Registry-only; article provides no GPO                       |

## Intentional Deviations from Source Article

The following settings use a different registry approach than the article specifies. These are deliberate choices where the definitions file favors the registry path that aligns with how the policy actually functions in Windows, rather than the path the article literally provides. Each deviation is documented here for traceability.

### Edge Update Settings (Section 13.2)

Three settings are affected: Disable Edge Auto Update (`UpdateDefault`), Disable Auto Update Check (`AutoUpdateCheckPeriodMinutes`), and Disable Experimentation Service (`ExperimentationAndConfigurationServiceControl`). The article specifies these at `HKLM\...\Policies\Microsoft\Edge\EdgeUpdate`, but the definitions file uses `HKLM\...\Policies\Microsoft\EdgeUpdate`. The article's path conflates Edge browser policies (`\Microsoft\Edge`) with Edge Update policies (`\Microsoft\EdgeUpdate`). The definitions file uses the path that Windows actually checks for update configuration.

### Disable Cloud Optimized Content (Section 25)

The article specifies the registry path at `HKCU\...\Policies\Microsoft\Windows\CloudContent`, but the definitions file uses `HKLM\...\Policies\Microsoft\Windows\CloudContent`. The article's own GPO for this setting is under Computer Configuration, which writes to HKLM, not HKCU. The article's registry instruction contradicts its own GPO guidance. The definitions file follows the HKLM path consistent with Computer Configuration policy behavior.

### Disable Recommendations (Section 33)

The article specifies `HKCU\...\Explorer\Advanced\Start_TrackDocs` set to `0`, which disables document tracking that feeds the Recommendations section. The definitions file instead uses `HKLM\...\Policies\Microsoft\Windows\Explorer\HideRecommendedSection` set to `1`, which is the registry key corresponding to the article's own GPO recommendation ("Remove Recommended from Start Menu"). This approach is machine-wide (HKLM, consistent with the majority of settings in the file), directly hides the Recommendations UI element rather than indirectly reducing its content, and aligns with the article's GPO guidance rather than its registry guidance.

## Known Article Inconsistencies

The following settings have guidance in the article that is internally inconsistent. The registry values for these settings are correct and produce the intended hardened state; only the article's documentation is affected. The `GPOPath` and `GPOState` fields in the definitions file preserve the article's literal text.

### Set Startup URL to Blank (Section 13.2)

The article states the GPO "Sites to open when the browser starts" should be set to "Disabled," but the corresponding registry sets `RestoreOnStartupURLs\1` to `about:blank`. A disabled policy would not populate this registry value. The intended GPO state is likely "Enabled" with `about:blank` as the URL list entry.

### Disable Experimentation Service (Section 13.2)

The article lists the GPO path as "Auto-update check period override," which is identical to the adjacent AutoUpdateCheckPeriodMinutes entry. This is a copy-paste error; the registry key `ExperimentationAndConfigurationServiceControl` corresponds to a distinct policy. The article's first column correctly identifies the policy as "Experimentation and Configuration Service."

### Disable All Store Apps (Section 26)

The article instructs to "Disable" the GPO named "Disable all apps from Microsoft Store," but the corresponding registry sets `DisableStoreApps` to `1` (disabled). Disabling a policy named "Disable..." would produce the opposite effect. The intended GPO state is likely "Enabled."

## Article Sections Not Included as Registry Settings

| Article Section | Title             | Reason                                                                        |
|:---------------:|-------------------|-------------------------------------------------------------------------------|
| 17              | Preinstalled apps | Handled via PowerShell `Remove-AppxPackage` commands, not registry settings   |

## Settings Tree

Complete map of all 131 settings organized by area, category, and section.

```
Policy-MicrosoftPrivacyConnections.psd1
+-- Area: Telemetry & Diagnostics
|   +-- Feedback & Diagnostics
|   |   +-- Set Diagnostic Data to Minimum
|   |   +-- Disable Tailored Experiences
|   |   +-- Disable Consumer Experiences
|   |   +-- Disable Feedback Notifications
|   |   +-- Set Feedback Frequency to Never (Period)
|   |   \-- Set Feedback Frequency to Never (Count)
|   +-- Defender Cloud Reporting
|   |   +-- Disable MAPS Reporting
|   |   +-- Disable Sample Submission
|   |   +-- Disable MSRT Diagnostic Data
|   |   \-- Disable Enhanced Notifications
|   \-- Inking & Typing
|       +-- Restrict Implicit Text Collection
|       \-- Restrict Implicit Ink Collection
|
+-- Area: Microsoft Cloud Services
|   +-- Cortana & Search
|   |   +-- Disable Cortana
|   |   +-- Disable Search Location
|   |   +-- Disable Web Search
|   |   \-- Disable Web Results in Search
|   +-- OneDrive
|   |   +-- Disable OneDrive File Storage
|   |   \-- Disable OneDrive Network Traffic Before Sign-In
|   +-- Microsoft Account
|   |   \-- Disable Microsoft Account Sign-In Assistant
|   +-- Cloud Sync
|   |   +-- Disable Settings Sync
|   |   +-- Disable Settings Sync User Override
|   |   +-- Disable Cloud Clipboard
|   |   \-- Disable Messaging Cloud Sync
|   +-- Find My Device
|   |   \-- Disable Find My Device
|   \-- Windows Mail
|       \-- Disable Windows Mail
|
+-- Area: App Permissions
|   +-- Category: Personalization & Tracking
|   |   +-- Advertising ID
|   |   |   +-- Disable Advertising ID (Feature)
|   |   |   \-- Disable Advertising ID (Policy)
|   |   +-- Personalization Tracking
|   |   |   +-- Disable Language List Access
|   |   |   \-- Disable App Launch Tracking
|   |   \-- Cross-Device Experiences
|   |       \-- Disable Cross-Device Experiences
|   +-- Category: Device Access
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
|   |       \-- Deny Access to Trusted Devices
|   +-- Category: Communication
|   |   +-- Account Info
|   |   |   \-- Deny App Access to Account Info
|   |   +-- Contacts
|   |   |   \-- Deny App Access to Contacts
|   |   +-- Calendar
|   |   |   \-- Deny App Access to Calendar
|   |   +-- Email
|   |   |   \-- Deny App Access to Email
|   |   +-- Messaging
|   |   |   +-- Deny App Access to Messaging
|   |   |   \-- Disable In-App Message Sync
|   |   +-- Phone Calls
|   |   |   \-- Deny App Access to Phone Calls
|   |   \-- Call History
|   |       \-- Deny App Access to Call History
|   \-- Category: App Behavior
|       +-- Activity History
|       |   +-- Disable Activity Feed
|       |   +-- Disable Publish User Activities
|       |   \-- Disable Upload User Activities
|       +-- Background Apps
|       |   \-- Deny Background App Execution
|       +-- Notifications
|       |   \-- Deny App Access to Notifications
|       +-- Speech
|       |   +-- Disable Online Speech Recognition
|       |   \-- Disable Speech Model Updates
|       +-- Voice Activation
|       |   +-- Deny Voice Activation
|       |   \-- Deny Voice Activation Above Lock
|       +-- Tasks
|       |   \-- Deny App Access to Tasks
|       +-- News and Interests
|       |   \-- Disable News and Interests
|       \-- App Diagnostics
|           \-- Deny App Access to Diagnostics
|
+-- Area: Windows Features
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
|   |   \-- Disable Widgets
|   +-- Recommendations
|   |   \-- Disable Recommendations
|   +-- Offline Maps
|   |   +-- Disable Auto Download Map Data
|   |   \-- Disable Unsolicited Map Network Traffic
|   +-- Live Tiles
|   |   \-- Disable Live Tile Notifications
|   \-- Apps for Websites
|       \-- Disable App URI Handlers
|
+-- Area: Windows Update
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
+-- Area: Browsers
|   +-- Microsoft Edge (Chromium)
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
|   |   +-- Disable Edge Auto Update
|   |   +-- Disable Auto Update Check
|   |   \-- Disable Experimentation Service
|   +-- Microsoft Edge (Legacy)
|   |   +-- Disable Address Bar Suggestions
|   |   +-- Disable Search Suggestions
|   |   +-- Enable Do Not Track
|   |   +-- Disable Password Manager
|   |   +-- Disable Autofill
|   |   +-- Disable Edge SmartScreen
|   |   +-- Set New Tab to Blank
|   |   +-- Set Home Page to Blank
|   |   +-- Disable First Run Page
|   |   +-- Disable Compatibility List
|   |   \-- Disable Books Library Updates
|   \-- Internet Explorer
|       +-- Disable Suggested Sites
|       +-- Disable Enhanced Suggestions
|       +-- Disable Browser Geolocation
|       +-- Disable AutoComplete for Web Addresses
|       +-- Disable Feed Background Sync
|       +-- Disable Online Tips
|       +-- Disable IE SmartScreen
|       +-- Disable ActiveX VersionList Download
|       +-- Set IE Home Page to Blank
|       +-- Lock IE Home Page Setting
|       +-- Disable IE First Run Wizard
|       +-- Set IE New Tab to Blank
|       +-- Disable Compatibility View Editing
|       \-- Disable Flip Ahead
|
\-- Area: Background Services
    +-- Device Metadata Retrieval
    |   \-- Disable Device Metadata Retrieval
    +-- Font Streaming
    |   \-- Disable Font Streaming
    +-- Wi-Fi Sense
    |   \-- Disable Wi-Fi Sense
    +-- License Manager
    |   \-- Disable License Manager Service
    +-- Teredo
    |   \-- Disable Teredo
    +-- Software Protection Platform
    |   \-- Disable KMS Online Validation
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
