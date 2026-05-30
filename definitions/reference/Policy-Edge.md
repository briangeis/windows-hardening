# Policy Definition Reference: Microsoft Edge

[Policy-Edge.psd1](../Policy-Edge.psd1) is a hardening baseline for Microsoft Edge on standalone Windows 11 devices, built around three goals: minimizing the data Edge sends to Microsoft, applying browser security hardening, and producing a clean browser experience free of Microsoft-promoted features. This file is the product of independent research, with each setting drawn from the Microsoft Edge ADMX policy templates and verified through direct registry mapping. This document records the editorial decisions behind each setting and also covers the distribution of settings by category, settings with notable side effects and non-obvious interactions, and counterintuitive Group Policy behavior.

The categories are organized navigation-first: each category answers a specific question a sysadmin asks when hardening Edge on a standalone device, and the order traces the file's three goals. Privacy & Telemetry and Identity & Data cover the data Edge sends to Microsoft and retains about the user. Security and Content Permissions harden the browser and restrict what websites can access. Microsoft Features and Browser UI & Performance clear away Microsoft-promoted features for a clean browsing experience.

## Contents

**Categories**
- [Privacy & Telemetry](#privacy--telemetry)
- [Identity & Data](#identity--data)
- [Security](#security)
- [Content Permissions](#content-permissions)
- [Microsoft Features](#microsoft-features)
- [Browser UI & Performance](#browser-ui--performance)

**Reference**
- [Settings Distribution by Category](#settings-distribution-by-category)
- [Settings with Notable Side Effects](#settings-with-notable-side-effects)
- [Counterintuitive GPO Behavior](#counterintuitive-gpo-behavior)
- [Settings Not Included](#settings-not-included)
- [Settings Tree](#settings-tree)

## Privacy & Telemetry

*What is Edge sending to Microsoft?*

Contains every data flow from the browser to Microsoft, from the diagnostic data and personalization pipelines through tracking prevention to the newer Copilot and AI pathways that expose browsing context and page content. The Experimentation section reaches beyond the browser, covering Microsoft's ability to push configuration and experiment changes to the WebView2 runtime and the Edge Update service alongside Edge itself.

| PSD1 Section                | HKLM | HKCU | Total |
|-----------------------------|:----:|:----:|:-----:|
| Diagnostic Data             | 5    | 0    | 5     |
| Personalization & Profiling | 3    | 0    | 3     |
| Tracking Prevention         | 3    | 0    | 3     |
| Copilot & AI Data Access    | 6    | 0    | 6     |
| Experimentation             | 4    | 0    | 4     |

## Identity & Data

*What does Edge know about who I am and what I have done?*

Contains settings for browser identity, credential storage, and data retention, spanning sign-in and Microsoft account sync, autofill, automatic imports, and targeted data deletion. The category ends with Ephemeral Profiles, a single setting that discards the entire profile directory on close and supersedes every setting in the Browsing Data section.

| PSD1 Section           | HKLM | HKCU | Total |
|------------------------|:----:|:----:|:-----:|
| Sign-In & Sync         | 6    | 0    | 6     |
| Autofill & Credentials | 6    | 0    | 6     |
| Import Settings        | 8    | 0    | 8     |
| Browsing Data          | 5    | 0    | 5     |
| Ephemeral Profiles     | 1    | 0    | 1     |

## Security

*How secure is the browser itself?*

Contains browser-level security hardening. Most sections strengthen the browser through Enhanced Security Mode, site isolation and network-service sandboxing, code-integrity and dynamic-code enforcement, content-execution restrictions, and certificate and TLS controls. SmartScreen is the exception: all five of its settings carry Warning advisories because disabling SmartScreen trades phishing and malware protection for privacy, and each is included so it can be applied independently or skipped entirely.

| PSD1 Section                | HKLM | HKCU | Total |
|-----------------------------|:----:|:----:|:-----:|
| SmartScreen                 | 5    | 0    | 5     |
| Process & Memory Protection | 6    | 0    | 6     |
| Content Security            | 3    | 0    | 3     |
| Connection Security         | 4    | 0    | 4     |

## Content Permissions

*What can websites access on this device?*

Contains default-deny settings for the browser API capabilities that expose device hardware or local data to websites, spanning media capture, geolocation and sensors, the hardware-device APIs, and file and download access. WebRTC stands apart from the default-deny pattern, restricting exposure of the local IP address rather than gating a site permission.

| PSD1 Section       | HKLM | HKCU | Total |
|--------------------|:----:|:----:|:-----:|
| Media Capture      | 3    | 0    | 3     |
| Sensors & Location | 2    | 0    | 2     |
| Hardware APIs      | 4    | 0    | 4     |
| Files & Storage    | 3    | 0    | 3     |
| WebRTC             | 1    | 0    | 1     |

## Microsoft Features

*Which Microsoft cloud services is Edge integrated with?*

The largest category, covering Edge's integrations with Microsoft cloud services, from AI features such as translation, speech, and Microsoft Editor to the sidebar, search, shopping, and promotional surfaces. Address Bar Search is split into its own single-setting section because disabling the default search provider is more consequential than the suggestion controls in Search & Address Bar: it removes address bar search altogether rather than only the keystroke-by-keystroke suggestions.

| PSD1 Section            | HKLM | HKCU | Total |
|-------------------------|:----:|:----:|:-----:|
| AI & Cloud Services     | 8    | 0    | 8     |
| Sidebar & Collaboration | 6    | 0    | 6     |
| Search & Address Bar    | 7    | 0    | 7     |
| Address Bar Search      | 1    | 0    | 1     |
| Shopping & Commerce     | 4    | 0    | 4     |
| Rewards & Promotions    | 4    | 0    | 4     |

## Browser UI & Performance

*What does the browser interface look like and how does it use system resources?*

Contains the settings that produce a clean, stock browser experience. Unlike the rest of the file, these address Microsoft-promoted interface elements and background resource use rather than privacy or security directly: a quiet startup and blank new tab page stripped of Microsoft content and Copilot, the removal of optional interface elements such as the favorites bar and QR generator, and limits on the background processes and performance features that let Edge consume resources while closed.

| PSD1 Section             | HKLM | HKCU | Total |
|--------------------------|:----:|:----:|:-----:|
| Startup & New Tab Page   | 9    | 0    | 9     |
| UI Features              | 5    | 0    | 5     |
| Performance & Background | 6    | 0    | 6     |

---

## Settings Distribution by Category

| Category                 |  HKLM   |  HKCU  |  Total  |
|--------------------------|:-------:|:------:|:-------:|
| Privacy & Telemetry      | 21      | 0      | 21      |
| Identity & Data          | 26      | 0      | 26      |
| Security                 | 18      | 0      | 18      |
| Content Permissions      | 13      | 0      | 13      |
| Microsoft Features       | 30      | 0      | 30      |
| Browser UI & Performance | 20      | 0      | 20      |
| **Totals**               | **128** | **0**  | **128** |

## Settings with Notable Side Effects

The following settings carry consequences not apparent from the setting name or advisory fields alone, or have non-obvious interactions with other settings in the file.

### Enable Ephemeral Profiles (Identity & Data)

Ephemeral profiles go well beyond clearing browsing data on exit. The entire profile directory is created in a temporary location and deleted when Edge closes, taking with it all extensions, favorites, settings, themes, and any passwords saved during the session, not just history and cookies. This supersedes all five Browsing Data settings because those settings operate on a persistent profile that no longer exists.

### SmartScreen (Security)

The section's five settings all carry Warning advisories and harden to the Disabled state. `SmartScreenEnabled` is the master control: setting it to `0` disables SmartScreen outright and supersedes the other four. The remaining settings are included so each protection can be turned off on its own instead, for example setting `SmartScreenDnsRequestsEnabled` to `0` to disable only DNS-based lookups while keeping hash-based URL and download checks. Users who prefer to keep SmartScreen active should skip the section entirely.

### Enable Strict Enhanced Security Mode and Block JavaScript JIT (Security)

Both settings disable JavaScript JIT compilation. **Enable Strict Enhanced Security Mode** turns it off as part of its broader mitigation stack, while **Block JavaScript JIT** (`DefaultJavaScriptJitSetting`) controls it directly at the content-settings level, so applying both is no stronger than applying either one alone. Users who want to keep JIT for performance on heavy sites should apply neither.

### Disable Address Bar Search (Microsoft Features)

Setting `DefaultSearchProviderEnabled` to `0` is more restrictive than disabling search suggestions. With it applied, entering a query in the address bar no longer navigates to a search engine: Edge tries to resolve the input as a URL and shows a navigation error when it cannot. Users who want to stop keystrokes reaching the search engine but still search from the address bar should apply **Disable Search Suggestions** instead and leave this setting unapplied.

## Counterintuitive GPO Behavior

### Disable New Tab App Launcher (Startup & New Tab Page)

The GPO governing this setting is named `Hide App Launcher on Microsoft Edge new tab page`. To hide the App Launcher, the policy must be set to Disabled, which writes `NewTabPageAppLauncherEnabled` to `0`. Setting the policy to Enabled writes `NewTabPageAppLauncherEnabled` to `1`, showing the App Launcher. The registry value name is self-consistent: `0` hides the App Launcher and `1` does not. The GPO name is counterintuitive because disabling a policy named `Hide App Launcher on Microsoft Edge new tab page` is what hides the App Launcher.

## Settings Not Included

The following two settings are covered in [Policy-MicrosoftPrivacyConnections](Policy-MicrosoftPrivacyConnections.md), under its Microsoft Edge Update section, but are intentionally omitted from this file. Disabling automatic Edge updates introduces security risk that runs counter to this file's hardening goals.

| Registry Value                 | Reason |
|--------------------------------|--------|
| `UpdateDefault`                | Controls the overall update policy for Edge. Disabling it prevents all automatic updates from being installed |
| `AutoUpdateCheckPeriodMinutes` | Controls how frequently Edge checks for available updates. Setting it to `0` produces the same security outcome as `UpdateDefault` |

## Settings Tree

```
Policy-Edge.psd1
+-- Privacy & Telemetry
|   +-- Diagnostic Data
|   |   +-- Disable Browser Diagnostic Data
|   |   +-- Disable URL Reporting in Diagnostic Data
|   |   +-- Disable Edge 3P SERP Telemetry
|   |   +-- Disable DNS Interception Checks
|   |   \-- Disable User Feedback
|   +-- Personalization & Profiling
|   |   +-- Disable Personalization Reporting
|   |   +-- Disable Asset Delivery Service
|   |   \-- Disable AI Theme Generation
|   +-- Tracking Prevention
|   |   +-- Enable Strict Tracking Prevention
|   |   +-- Block Third Party Cookies
|   |   \-- Enable Do Not Track
|   +-- Copilot & AI Data Access
|   |   +-- Disable Browsing with Copilot
|   |   +-- Disable Copilot Toolbar Button
|   |   +-- Disable Copilot Page Context Access
|   |   +-- Disable Built-In AI APIs for Pages
|   |   +-- Disable Browsing History Sharing with Copilot Search
|   |   \-- Disable AI-Enhanced History Search
|   \-- Experimentation
|       +-- Disable Experimentation Service
|       +-- Disable Edge Update Experimentation Service
|       +-- Disable WebView2 Experimentation Service
|       \-- Prevent Feature Flag Overrides
|
+-- Identity & Data
|   +-- Sign-In & Sync
|   |   +-- Disable Browser Sign-In
|   |   +-- Disable Microsoft Sync
|   |   +-- Disable Work Account SSO for Websites
|   |   +-- Disable Microsoft Personal Account SSO
|   |   +-- Disable Guided Profile Switch
|   |   \-- Disable Seamless Web-to-Browser Sign-In
|   +-- Autofill & Credentials
|   |   +-- Disable Password Manager
|   |   +-- Disable Password Autofill
|   |   +-- Disable Payment Autofill
|   |   +-- Disable Payment Method Query
|   |   +-- Disable Address Autofill
|   |   \-- Disable Membership Autofill
|   +-- Import Settings
|   |   +-- Disable First-Run Auto-Import
|   |   +-- Disable Repeated Imports on Launch
|   |   +-- Disable Import of Saved Passwords
|   |   +-- Disable Import of Payment Info
|   |   +-- Disable Import of Autofill Data
|   |   +-- Disable Import of Browser Settings
|   |   +-- Disable Import of Home Page Settings
|   |   \-- Disable Import of Search Engine Settings
|   +-- Browsing Data
|   |   +-- Clear Browsing Data on Exit
|   |   +-- Clear Cached Images on Exit
|   |   +-- Disable Saving Browser History
|   |   +-- Delete Browser Data on Migration
|   |   \-- Disable Windows Search Access to Edge Data
|   \-- Ephemeral Profiles
|       \-- Enable Ephemeral Profiles
|
+-- Security
|   +-- SmartScreen
|   |   +-- Disable Microsoft Defender SmartScreen
|   |   +-- Disable SmartScreen Checks for Trusted Downloads
|   |   +-- Disable SmartScreen PUA Protection
|   |   +-- Disable SmartScreen DNS Requests
|   |   \-- Disable Scareware Blocker
|   +-- Process & Memory Protection
|   |   +-- Enable Strict Enhanced Security Mode
|   |   +-- Enable Site Isolation
|   |   +-- Enable Browser Code Integrity
|   |   +-- Enable Dynamic Code Protection
|   |   +-- Block External Extensions
|   |   \-- Enable Network Service Sandbox
|   +-- Content Security
|   |   +-- Block JavaScript JIT
|   |   +-- Block Insecure Content Exceptions
|   |   \-- Disable Internet Explorer Mode
|   \-- Connection Security
|       +-- Require OCSP/CRL Checks for Local Trust Anchors
|       +-- Enable Encrypted Client Hello
|       +-- Disable Basic Authentication over HTTP
|       \-- Disable Network Prediction
|
+-- Content Permissions
|   +-- Media Capture
|   |   +-- Block Audio Capture
|   |   +-- Block Video Capture
|   |   \-- Block Screen Capture
|   +-- Sensors & Location
|   |   +-- Block Geolocation Access
|   |   \-- Block Sensor Access
|   +-- Hardware APIs
|   |   +-- Block Serial API Access
|   |   +-- Block Web Bluetooth Access
|   |   +-- Block WebHID Access
|   |   \-- Block WebUSB Access
|   +-- Files & Storage
|   |   +-- Block File System API (Read)
|   |   +-- Block File System API (Write)
|   |   \-- Block Automatic Downloads
|   \-- WebRTC
|       \-- Restrict WebRTC Local IP Exposure
|
+-- Microsoft Features
|   +-- AI & Cloud Services
|   |   +-- Disable Translate
|   |   +-- Disable Online Text-to-Speech
|   |   +-- Disable Speech Recognition
|   |   +-- Disable Live Captions
|   |   +-- Disable Microsoft Editor Spell Check
|   |   +-- Disable Microsoft Editor Synonyms
|   |   +-- Disable Tab Organization Suggestions
|   |   \-- Disable Image Descriptions from Microsoft
|   +-- Sidebar & Collaboration
|   |   +-- Disable Hubs Sidebar
|   |   +-- Disable Standalone Sidebar
|   |   +-- Disable Collections
|   |   +-- Disable Drop Feature
|   |   +-- Disable Share Experience
|   |   \-- Disable In-App Support
|   +-- Search & Address Bar
|   |   +-- Disable Search Suggestions
|   |   +-- Disable Local Provider Suggestions
|   |   +-- Disable Similar Page Suggestions
|   |   +-- Disable Navigation Error Web Service
|   |   +-- Disable Bing Trending Suggestions
|   |   +-- Disable Typo Protection
|   |   \-- Disable Edge Search Bar
|   +-- Address Bar Search
|   |   \-- Disable Address Bar Search
|   +-- Shopping & Commerce
|   |   +-- Disable Shopping Assistant
|   |   +-- Disable Wallet Checkout
|   |   +-- Disable Wallet E-Tree
|   |   \-- Disable Wallet Donations
|   \-- Rewards & Promotions
|       +-- Disable Microsoft Rewards
|       +-- Disable Insider Promotion
|       +-- Disable Default Browser Campaigns
|       \-- Disable Feature Recommendations
|
+-- Browser UI & Performance
|   +-- Startup & New Tab Page
|   |   +-- Hide First-Run Experience
|   |   +-- Open New Tab on Startup
|   |   +-- Set New Tab Page to Blank
|   |   +-- Disable Microsoft Content on New Tab
|   |   +-- Disable Quick Links on New Tab
|   |   +-- Disable Copilot on New Tab Page
|   |   +-- Disable New Tab App Launcher
|   |   +-- Disable New Tab Page Preload
|   |   \-- Disable Search Bar at Windows Startup
|   +-- UI Features
|   |   +-- Disable Favorites Bar
|   |   +-- Disable Split Screen
|   |   +-- Disable QR Code Generator
|   |   +-- Disable Mobile File Upload
|   |   \-- Disable Google Cast
|   \-- Performance & Background
|       +-- Disable Background Mode
|       +-- Disable Startup Boost
|       +-- Disable Efficiency Mode
|       +-- Disable Sleeping Tabs
|       +-- Disable Performance Detector
|       \-- Disable Pin Toolbar Button
```
