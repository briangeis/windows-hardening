# Policy Profile Reference: Windows

[Policy-Windows-Base.psd1](../Policy-Windows-Base.psd1) and [Policy-Windows-NoStoreApps.psd1](../Policy-Windows-NoStoreApps.psd1) are curated, ready-to-apply profiles for standalone Windows devices, assembled from the Microsoft Privacy Connections and Windows Privacy Defaults definitions files and the per-setting research behind them. Where the definitions files catalog what can be configured, these profile files record what to apply and why. This document is the editorial record behind that curation: what the base includes and what it excludes, what it holds back for the optional layer, and the tradeoffs that required a judgment call. For per-setting detail, see the definitions references for [Microsoft Privacy Connections](../../definitions/reference/Policy-MicrosoftPrivacyConnections.md) and [Windows Privacy Defaults](../../definitions/reference/Policy-WindowsPrivacyDefaults.md).

## Contents

- [The Base](#the-base)
- [The No Store Apps Layer](#the-no-store-apps-layer)
- [Tradeoff Verdicts](#tradeoff-verdicts)
- [Notes](#notes)
- [Profile Composition](#profile-composition)

## The Base

[Policy-Windows-Base.psd1](../Policy-Windows-Base.psd1) is the foundational profile: a hardening baseline for a standalone Windows device. It applies the toolkit's six curation principles, set out in the [profiles overview](../README.md), across both axes of privacy and security. What it includes and excludes below follows from those principles.

### What the Base Includes

The base carries the large majority of both definitions files, spanning the telemetry and Microsoft-connection controls, the app permissions, the Windows feature and content-delivery surfaces, the on-device activity and history records, the default-behavior security hardening, the native-application controls, and the whole of Internet Explorer. Several of these settings are genuine tradeoffs between privacy and security, argued under [Tradeoff Verdicts](#tradeoff-verdicts). Per-setting rationale lives in the two definitions references, and this document does not repeat it.

### What the Base Excludes

The base excludes the following settings outright, grouped by reason:

**The loss of security updates.** Automatic Windows Update is how the device gets its security patches, so the base leaves it untouched. Every setting that would block update access or turn off the automatic installation of system and driver updates is excluded.

**A security cost far above the privacy gain.** A few settings would each give up broad security for a small privacy gain, so the base keeps them out. Set Time Sync to NoSync and Disable NTP Client let the clock drift, which breaks TLS certificate validation and time-based 2FA. Disable Automatic Root Certificate Updates makes sites whose root certificate the device lacks fail TLS. Disable SmartScreen turns off Windows-wide malware and phishing protection for files and apps.

**The Edge boundary.** Microsoft Privacy Connections includes a handful of Microsoft Edge and Edge Update settings for fidelity to the source article. Edge is hardened separately as its own target, so the Windows profiles defer those settings to the Edge profile.

**Breakage out of proportion to the gain.** Disable NCSI Active Tests turns off the active connectivity probe, but Windows and applications rely on that probe to tell whether the device is online, so disabling it can break connectivity-dependent apps and services. Disable Hibernation only protects data at rest on an unencrypted disk, and modern devices are encrypted by default, so it would remove hibernation from every device to cover a rare exposure.

## The No Store Apps Layer

[Policy-Windows-NoStoreApps.psd1](../Policy-Windows-NoStoreApps.psd1) is the optional layer for a device that runs without a Microsoft account, the Microsoft Store, or the built-in Store (UWP) apps. Disabling the account and Store services is genuine hardening, and on a device that never uses them it comes at no cost. A typical device depends on those services, so the base holds these settings back rather than break daily use.

The layer disables the Microsoft account sign-in service, OneDrive, the Store and its updates, push notifications, licensing, and cross-device features, and denies the core app permissions, from the camera and microphone to contacts and calendar. System-wide location is the boundary call: the base leaves it on because disabling it removes location from every app, including Weather, Maps, and automatic time-zone, so the layer applies it instead.

## Tradeoff Verdicts

These are the base's genuine tradeoffs, each balancing a real benefit against a real cost:

**Defender cloud protection.** Microsoft Active Protection Service (MAPS) sends file hashes to Microsoft, forming a presence-detection channel that reveals which known files a device holds. That cost is sensitive and continuous, while the security benefit is bounded: signatures, the local engine, behavior monitoring, and SmartScreen all work without it. SmartScreen sends hashes too but is kept, because it is an execution-time gate where MAPS only augments an engine that already works. Disable Sample Submission goes further, uploading the files themselves, so the base disables both.

**Find My Device.** Theft recovery is a real benefit, but it helps mainly on portable devices, works only when location and a Microsoft account are both present, and runs against a continuous, high-sensitivity location stream. That narrow and conditional benefit does not outweigh the sensitive and continuous cost, so the base disables it.

**SmartScreen.** The base keeps the one broad filter and disables the narrow ones. System-wide SmartScreen stays, as broad malware and phishing protection for files and apps. Disable SmartScreen for Store Apps checks only the web content that Store apps load, where vetted apps carry little risk, and Disable IE SmartScreen guards a browser that is effectively extinct. Edge SmartScreen is another narrow filter, but the decision on it is deferred to the Edge profile.

**Teredo.** Teredo is an IPv6 transition technology used only by IPv4-only hosts as a last resort, so devices with native IPv6 are unaffected, and the only realistic breakage is Xbox-app multiplayer and party chat on IPv4-only networks. Disabling an internet-facing IPv6 tunnel is recognized attack-surface reduction, so the base accepts that narrow breakage for a real security gain.

## Notes

**Inert but included.** Several settings do nothing on a current Windows 11 device but harden another supported configuration, so one profile serves the whole range. KMS online validation applies to a volume-licensed device, while News and Interests, the activity feed, Cortana, and Internet Explorer still apply on Windows 10.

## Profile Composition

### Coverage

The base and layer curate 134 of the 162 settings across both definitions files.

| Profile | Settings | Source |
|---------|:--------:|--------|
| [Policy-Windows-Base.psd1](../Policy-Windows-Base.psd1) | 112 | Both definitions files |
| [Policy-Windows-NoStoreApps.psd1](../Policy-Windows-NoStoreApps.psd1) | 22 | Both definitions files |

### Exclusions

The remaining 28 are excluded outright, each with its reason.

| Excluded setting or group | Reason |
|---------------------------|--------|
| Windows Update settings (8) | Block updates or their automatic installation |
| Microsoft Edge and Edge Update (14) | Decisions deferred to the Edge profile |
| Set Time Sync to NoSync, Disable NTP Client | Clock drift breaks TLS certificate validation and time-based 2FA |
| Disable Automatic Root Certificate Updates | TLS failures for sites whose root certificate the device lacks |
| Disable SmartScreen (system-wide) | Kept on for broad malware and phishing protection |
| Disable NCSI Active Tests | Relied on by apps and services to detect internet access |
| Disable Hibernation | Protects an unencrypted disk while removing hibernation |
