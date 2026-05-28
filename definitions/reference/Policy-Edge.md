# Policy Definition Reference: Microsoft Edge

[Policy-Edge.psd1](../Policy-Edge.psd1) is a standalone Edge hardening baseline covering privacy, security, identity management, content permissions, and browser interface configuration for standalone Windows 11 devices. Settings are drawn from the Microsoft Edge ADMX policy templates and verified through direct registry mapping on a Windows 11 Pro device with the latest Edge ADMX templates installed. This file does not derive from a single source article; each setting reflects independent research and deliberate editorial choices aimed at three goals: minimizing the data Edge sends to Microsoft, applying available browser security hardening, and producing a clean browser experience free of Microsoft-promoted features and background resource use. 124 of the 126 settings write to `HKLM:\SOFTWARE\Policies\Microsoft\Edge`; one setting in the Experimentation section writes to `HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebView2` and one writes to `HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate` to cover the WebView2 and Edge Update experimentation pipelines. The Microsoft Edge ADMX templates provide Computer Configuration policies for 124 of the 126 settings; the WebView2 Experimentation setting is governed by the Microsoft Edge WebView2 ADMX policy, and the EdgeUpdate setting is governed by the Microsoft Edge Update ADMX policy. This document covers settings with notable side effects and non-obvious interactions, counterintuitive Group Policy behavior, and the distribution of settings by category.

The categories are organized navigation-first: each category answers a specific question. Privacy & Telemetry, Security, and Identity & Data cover the highest-priority decisions. Content Permissions and Microsoft Features address site-level access control and Microsoft service integrations. Browser UI & Performance produces the clean browser experience.

Settings whose hardened GPO state is documented as equivalent to Not Configured are excluded. When the GPO description states that the policy's enabled or disabled state produces the same browser behavior as leaving the policy unconfigured, applying the setting writes a registry value without changing how Edge behaves. In an enterprise environment managed by Active Directory, locking the default via local policy provides meaningful protection against domain-applied GPO overrides. On a standalone device, no such competing policy exists. Including settings that enforce an existing default would misrepresent both the browser's built-in behavior and the editorial goals of this file.

## Contents

**Categories**
- [Privacy & Telemetry](#privacy--telemetry)
- [Security](#security)
- [Identity & Data](#identity--data)
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

Contains settings for all data flows from the browser to Microsoft. Diagnostic Data covers the diagnostic data collection level, URL inclusion in crash reports, third-party search engine telemetry, DNS interception probes, and user feedback submission. Personalization & Profiling covers the pipeline that sends browsing history, favorites, and usage data to Microsoft for ad and service personalization, along with content delivery from the Asset Delivery Service and AI-generated themes. Tracking Prevention addresses third-party tracking across all websites. Copilot & AI Data Access covers the newer pipelines where Edge sends browsing context or page content to Microsoft AI services. Experimentation covers Microsoft's ability to push configuration and experiment changes to the browser, the WebView2 runtime, and the Edge Update service.

| PSD1 Section             | HKLM | HKCU | Total |
|--------------------------|:----:|:----:|:-----:|
| Diagnostic Data          | 5    | 0    | 5     |
| Personalization & Profiling | 3 | 0    | 3     |
| Tracking Prevention      | 3    | 0    | 3     |
| Copilot & AI Data Access | 5    | 0    | 5     |
| Experimentation          | 4    | 0    | 4     |

## Security

*How secure is the browser itself?*

Contains browser-level security hardening settings. SmartScreen groups Microsoft Defender SmartScreen and the Scareware Blocker as a set of deliberate privacy-versus-security trade-off settings; all five settings in the SmartScreen section carry Warning advisories and are designed to be applied as a group or not at all. Process & Memory Protection covers Enhanced Security Mode, site isolation, code integrity enforcement, dynamic code restrictions, external extension sideloading, and the network service sandbox. Content Security covers JavaScript JIT blocking, mixed content exception prevention, and the Internet Explorer mode integration. Connection Security covers local trust anchor revocation checking, TLS Encrypted ClientHello, and Basic auth over HTTP.

| PSD1 Section                | HKLM | HKCU | Total |
|-----------------------------|:----:|:----:|:-----:|
| SmartScreen                 | 5    | 0    | 5     |
| Process & Memory Protection | 6    | 0    | 6     |
| Content Security            | 3    | 0    | 3     |
| Connection Security         | 3    | 0    | 3     |

## Identity & Data

*What does Edge know about who I am and what I have done?*

Contains settings for browser identity, credential storage, and data retention. Sign-In & Sync covers browser sign-in, Microsoft account synchronization, and all SSO mechanisms that allow websites to sign in the user through the browser profile. Autofill & Credentials covers the password manager, autofill for addresses, payment instruments, and membership IDs, and prevents websites from detecting stored payment methods. Import Settings covers all automatic data import mechanisms, both at first run and on each subsequent launch. Browsing Data covers targeted data deletion and history settings: clear-on-exit for browsing data and cached images, history saving, browser data migration cleanup, and blocking Windows Search access to Edge data. Ephemeral Profiles is a single-setting section at the end of Identity & Data covering the option to delete the entire profile directory on close; all settings in Browsing Data are superseded when Ephemeral Profiles is also applied.

| PSD1 Section         | HKLM | HKCU | Total |
|----------------------|:----:|:----:|:-----:|
| Sign-In & Sync       | 6    | 0    | 6     |
| Autofill & Credentials | 6  | 0    | 6     |
| Import Settings      | 8    | 0    | 8     |
| Browsing Data        | 5    | 0    | 5     |
| Ephemeral Profiles   | 1    | 0    | 1     |

## Content Permissions

*What can websites access on this device?*

Contains default-deny settings for all browser API capabilities that expose device hardware or local data to websites. All settings configure the default behavior across all sites; users can still grant per-site exceptions through Edge's site permissions UI unless additional policies restrict that capability. Media Capture covers the microphone, camera, and screen. Sensors & Location covers geolocation and ambient device sensors. Hardware APIs covers Serial, Web Bluetooth, WebHID, and WebUSB. Files & Storage covers the File System Access API for both reading and writing and automatic multi-file downloads. WebRTC covers local IP address exposure through the browser's peer connection implementation.

| PSD1 Section           | HKLM | HKCU | Total |
|------------------------|:----:|:----:|:-----:|
| Media Capture          | 3    | 0    | 3     |
| Sensors & Location     | 2    | 0    | 2     |
| Hardware APIs          | 4    | 0    | 4     |
| Files & Storage        | 3    | 0    | 3     |
| WebRTC                 | 1    | 0    | 1     |

## Microsoft Features

*Which Microsoft cloud services is Edge integrated with?*

Contains settings for Microsoft-specific feature integrations. AI & Cloud Services covers translation, text-to-speech, speech recognition, live captions, Microsoft Editor spell checking and synonyms, AI tab organization, and image descriptions fetched from Microsoft for screen readers. Sidebar & Collaboration covers the Hubs sidebar, standalone sidebar, Collections, Drop file sharing, the Share experience, and in-browser support. Search & Address Bar covers address bar suggestions (keystrokes sent to the search engine), local data suggestions, similar page fallbacks, navigation error resolution, Bing trending topics, typo protection that contacts Microsoft, and the floating search bar. Address Bar Search is a single-setting section covering the option to disable the default search provider entirely, removing the ability to search from the address bar. Shopping & Commerce covers the shopping assistant and its price tracking, the Microsoft Wallet checkout and E-Tree features, and wallet donations. Rewards & Promotions covers Microsoft Rewards, Insider promotion, default browser campaigns, and Edge's feature recommendation notifications.

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

Contains settings that produce a clean, stock browser experience. These settings address Microsoft-promoted interface elements and background resource usage rather than privacy or security directly. Startup & New Tab Page suppresses the first-run experience, opens a blank tab on startup, and removes all Microsoft content, quick links, and Copilot integration from the new tab page. UI Features removes optional interface elements including the favorites bar, split screen, QR code generator, mobile upload, and Google Cast. Performance & Background prevents Edge from using system resources when the browser is not actively open, covering background mode, startup boost, efficiency mode, sleeping tabs, the performance detector, and the pinned toolbar button.

| PSD1 Section              | HKLM | HKCU | Total |
|---------------------------|:----:|:----:|:-----:|
| Startup & New Tab Page    | 9    | 0    | 9     |
| UI Features               | 5    | 0    | 5     |
| Performance & Background  | 6    | 0    | 6     |

---

## Settings Distribution by Category

| Category                 |  HKLM   |  HKCU  |  Total  |
|--------------------------|:-------:|:------:|:-------:|
| Privacy & Telemetry      | 20      | 0      | 20      |
| Security                 | 17      | 0      | 17      |
| Identity & Data          | 26      | 0      | 26      |
| Content Permissions      | 13      | 0      | 13      |
| Microsoft Features       | 30      | 0      | 30      |
| Browser UI & Performance | 20      | 0      | 20      |
| **Totals**               | **126** | **0**  | **126** |

## Settings with Notable Side Effects

The following settings carry consequences or interactions that are not apparent from the setting name or advisory fields alone.

### Enable Ephemeral Profiles (Ephemeral Profiles)

Ephemeral profiles are fundamentally different from clearing browsing data on exit. When ephemeral profiles are active, the entire user profile directory is stored in a temporary location and deleted when Edge closes. This includes all installed extensions, bookmarks and favorites, Edge settings, themes, passwords saved during the session, and all customizations, not just browsing history and cookies. All five settings in the Browsing Data section are superseded by this setting when both are applied; those settings operate on a persistent profile that does not exist when ephemeral mode is active.

### Block JavaScript JIT and Enhanced Security Mode Strict (Security)

Both settings independently disable JIT compilation in the browser. Enhanced Security Mode Strict disables JIT as part of its broader mitigation stack. Block JavaScript JIT (`DefaultJavaScriptJitSetting`) controls this separately at the content settings level. When both settings are applied together, the effective behavior is the same as either setting alone; applying both does not compound the protection. Users who want to preserve JIT for performance reasons should not apply either setting.

### Disable Address Bar Search (Address Bar Search)

Setting `DefaultSearchProviderEnabled = 0` is more restrictive than disabling search suggestions. With this setting applied, typing a query in the address bar and pressing Enter does not navigate to a search engine; the browser attempts to resolve the input as a URL and produces a navigation error if it fails. Users who want to suppress keystrokes being sent to the search engine as they type but still want to perform searches should apply only Disable Search Suggestions and leave Disable Address Bar Search unapplied.

### SmartScreen Section Design

The SmartScreen section contains five settings with Warning advisories, all with disabled as the hardened value. `SmartScreenEnabled` is the primary control: setting it to `0` fully disables SmartScreen and renders the remaining four settings irrelevant. All five are included so that each can be applied independently. A user who applies only `SmartScreenDnsRequestsEnabled = 0` retains hash-based URL and download checking while disabling DNS-based lookups. A user who applies only `SmartScreenForTrustedDownloadsEnabled = 0` retains SmartScreen protection for all downloads except those from sources in a trusted zone. The SmartScreen section is designed to be skipped entirely by users who prefer to keep SmartScreen's protections active.

## Counterintuitive GPO Behavior

### Disable New Tab App Launcher (Startup & New Tab Page)

The policy governing this setting is named "Hide App Launcher on Microsoft Edge new tab page." The registry value is `NewTabPageAppLauncherEnabled`. Setting the policy to Disabled (registry value = 0) hides the Microsoft 365 App Launcher from the new tab page. Setting it to Enabled shows the App Launcher. The hardened value is 0 and the GPO state is Disabled, which means "not enabling the App Launcher" results in it being absent from the new tab page.

## Settings Not Included

The following two settings are present in the Microsoft Edge Update ADMX template and are covered in [Policy-MicrosoftPrivacyConnections](Policy-MicrosoftPrivacyConnections.md) under the Microsoft Edge Update section. Both are not included here because disabling automatic Edge updates introduces security risk that runs counter to this file's hardening goals.

| Registry Value | Reason |
|---|---|
| `UpdateDefault` | Controls the overall update policy for Edge; disabling it prevents all automatic updates from being installed |
| `AutoUpdateCheckPeriodMinutes` | Controls how frequently Edge checks for available updates; setting it to `0` produces the same security outcome as `UpdateDefault` |

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
|   |   +-- Disable Copilot Page Context Access
|   |   +-- Disable Built-In AI APIs for Pages
|   |   +-- Disable Browsing History Sharing with Copilot Search
|   |   \-- Disable AI-Enhanced History Search
|   \-- Experimentation
|       +-- Disable Experimentation Service
|       +-- Disable Edge Update Experimentation Service
|       +-- Disable WebView2 Experimentation Service
|       \-- Prevent Feature Flag Overrides
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
|       \-- Disable Basic Authentication over HTTP
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
