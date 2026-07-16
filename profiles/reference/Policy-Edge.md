# Policy Profile Reference: Microsoft Edge

[Policy-Edge-Base.psd1](../Policy-Edge-Base.psd1) and [Policy-Edge-NoWebConferencing.psd1](../Policy-Edge-NoWebConferencing.psd1) are curated, ready-to-apply profiles for Microsoft Edge on standalone Windows devices, assembled from the Edge definitions file and the per-setting research behind it. Where the definitions file catalogs what Edge can configure, these profile files record what to apply and why. This document is the editorial record behind that curation: what the base includes and what it excludes, what it holds back for the optional layer, and the tradeoffs that required a judgment call. For per-setting detail, see the [Microsoft Edge definitions reference](../../definitions/reference/Policy-Edge.md).

## Contents

- [The Base](#the-base)
- [The No Web Conferencing Layer](#the-no-web-conferencing-layer)
- [Tradeoff Verdicts](#tradeoff-verdicts)
- [Notes](#notes)
- [Profile Composition](#profile-composition)

## The Base

[Policy-Edge-Base.psd1](../Policy-Edge-Base.psd1) is the foundational profile: a hardening baseline for Microsoft Edge on a standalone device. It applies the toolkit's six curation principles, set out in the [profiles overview](../README.md), toward its three goals: minimizing the data Edge sends to Microsoft, hardening the browser itself, and producing a clean experience free of Microsoft-promoted features. What it includes and excludes below follows from those principles.

### What the Base Includes

The base carries the large majority of the definitions file, spanning the telemetry and tracking pathways, the Copilot and AI controls, the identity and data-retention controls, the browser-security hardening, the website content permissions, the Microsoft-feature removals, and the browser shell. Several of these settings are genuine tradeoffs between privacy and security, argued under [Tradeoff Verdicts](#tradeoff-verdicts). Per-setting rationale lives in the definitions reference, and this document does not repeat it.

### What the Base Excludes

The base excludes the following settings outright, grouped by reason:

**More than browsing data.** Enable Ephemeral Profiles deletes the entire profile on every close, discarding bookmarks, extensions, and saved settings along with browsing data. The base clears the same browsing data on exit but leaves the profile intact, delivering the privacy benefit without deleting the profile.

**A cost to everyday browsing.** Disable Address Bar Search removes the default search provider, so a non-URL query in the address bar produces a navigation error instead of a search. The base instead applies the gentler Disable Search Suggestions, which stops keystrokes from being sent to the search engine while leaving address-bar search working. Disable Local Provider Suggestions turns off address-bar autocomplete drawn from local history and bookmarks, data that never leaves the device, so disabling it costs usability with no privacy gain.

**Preference, not hardening.** Disable Favorites Bar, Disable Split Screen, Disable QR Code Generator, Disable Efficiency Mode, and Disable Sleeping Tabs turn off ordinary browser features and resource optimizations, none of them Microsoft-promoted and none bearing on privacy or security. Keeping or disabling them is a matter of preference, so the base leaves them at their defaults.

## The No Web Conferencing Layer

[Policy-Edge-NoWebConferencing.psd1](../Policy-Edge-NoWebConferencing.psd1) is the optional layer for a device where Edge is not used for web conferencing. Blocking website access to the microphone, camera, and screen is genuine hardening, and on such a device it comes at no cost. A typical device relies on that access for Microsoft Teams, Zoom, Google Meet, and Discord, so the base holds these settings back rather than break them.

The layer blocks audio, video, and screen capture at the browser level, a hard block with no per-site override. Note that this layer holds no WebRTC setting, since the base already closes the WebRTC IP leak for every device without affecting calls.

## Tradeoff Verdicts

These are the base's genuine tradeoffs, each balancing a real benefit against a real cost:

**SmartScreen.** This is the profile's defining tradeoff. Edge SmartScreen sends a URL reputation query to Microsoft on navigation, a continuous stream of browsing history and exactly the flow the base aims to cut. The benefit is real but partly redundant here: system-wide Windows SmartScreen still covers executed downloads, and download blocking and Enhanced Security Mode narrow the rest, leaving only phishing-URL blocking genuinely unique. All five SmartScreen settings are disabled. The one real residual is that this removes Edge's in-browser phishing and malicious-URL warnings, which nothing else fully replaces.

**Typo Protection.** The SmartScreen tradeoff in miniature: the typosquatting checker guards against lookalike domains, backed by a Microsoft cloud service, the same class of cost for a similar benefit, so the base disables it too.

**Enhanced Security Mode and JavaScript JIT.** Blocking the JavaScript JIT compiler closes the largest browser exploit surface at a performance cost that is imperceptible for ordinary browsing and shows up only on JavaScript-heavy web apps and games, which is niche. Enable Strict Enhanced Security Mode and Block JavaScript JIT overlap, since Strict mode already blocks JIT, but the base includes both for robustness: the explicit control still keeps JIT off if a future Edge version changes what Strict mode bundles.

**Browser sign-in and data retention.** The base disables sign-in, sync, the password manager, and autofill so that credentials and browsing data are neither synced to Microsoft nor stored by Edge. This is a privacy-versus-convenience tradeoff, not a security one: the cost is losing cross-device sync and Edge's autofill services.

## Notes

**WebRTC leak protection has a limit.** The base hardens WebRTC with `default_public_interface_only`, which closes the local-IP and VPN-real-IP leaks whenever the VPN is the default route, at no cost to calls. A split-tunnel VPN that is not the default route needs the stricter `disable_non_proxied_udp`, but that routes every connection through a relay and breaks peer-to-peer calls, so the profile keeps to the call-safe value.

**A few base settings have a side effect worth stating.** Clearing browsing data on exit signs out of every site on each close. The blank new tab page drops that page's own search box, though the address bar still searches. Disabling quick links removes the most-visited tiles, consistent with history being off. None of them breaks the browser, but each is a deliberate choice worth being aware of.

## Profile Composition

### Coverage

The base and layer curate 120 of the definitions file's 128 settings.

| Profile                                                                     | Settings | Source                  |
|-----------------------------------------------------------------------------|:--------:|-------------------------|
| [Policy-Edge-Base.psd1](../Policy-Edge-Base.psd1)                           | 117      | Policy-Edge definitions |
| [Policy-Edge-NoWebConferencing.psd1](../Policy-Edge-NoWebConferencing.psd1) | 3        | Policy-Edge definitions |

### Exclusions

The remaining eight are excluded outright, each with its reason.

| Excluded setting or group              | Reason |
|----------------------------------------|--------|
| Enable Ephemeral Profiles              | Deletes the whole profile on exit, not just browsing data |
| Disable Address Bar Search             | Removes the search provider; non-URL queries become navigation errors |
| Disable Local Provider Suggestions     | Local-only autocomplete; disabling is usability loss with no privacy gain |
| Browser UI and performance toggles (5) | Preferences with no bearing on privacy or security |
