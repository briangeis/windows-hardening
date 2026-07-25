# Curated Profiles

Curated profiles are ready-to-apply configurations for a target such as Windows or Edge, assembled from the definitions files and the per-setting research behind them. Where the definitions files catalog what a component can configure, these profile files record what to apply and why. Each target has one base profile plus a small number of optional additive layers. Unlike the profiles that Build Mode and Snapshot Mode generate, these are tracked deliverables, maintained directly.

## Available Files

### Policy

**Windows Profiles** ([reference doc](reference/Policy-Windows.md))

- [Policy-Windows-Base.psd1](Policy-Windows-Base.psd1) is a privacy and security baseline for standalone devices, with 112 settings covering telemetry, app permissions, activity history, content delivery, and default-behavior security hardening.
- [Policy-Windows-NoStoreApps.psd1](Policy-Windows-NoStoreApps.psd1) is an additive layer for devices that do not use the Microsoft Store or its apps, with 22 settings disabling the Microsoft account, OneDrive, Store, cross-device services, and core app permissions.

**Edge Profiles** ([reference doc](reference/Policy-Edge.md))

- [Policy-Edge-Base.psd1](Policy-Edge-Base.psd1) is a privacy and security baseline for Microsoft Edge, with 117 settings covering telemetry and tracking, Copilot and AI, sign-in and data retention, browser hardening, and Microsoft-feature removals.
- [Policy-Edge-NoWebConferencing.psd1](Policy-Edge-NoWebConferencing.psd1) is an additive layer for devices that do not use web conferencing, with 3 settings blocking website access to the microphone, camera, and screen capture.

## Naming Convention

Curated profiles follow the pattern `Component-Target-Variant.psd1`. Component comes first, consistent with the definitions files. Target is the operating system or application hardened. Variant is `Base` for the foundational profile, or a layer name for an additive layer. A layer is named `No<FeatureOrUseCase>` for what it opts out of, and a shared feature or use case reuses the same variant across targets.

Example: `Policy-Edge-NoWebConferencing.psd1`

## Applying a Profile

A profile is applied with `-ProfilePath` in Profile Mode, which reads the self-contained file and applies every setting without prompting. Apply the base first, then any layers, each with its own `-ProfilePath` invocation. Layers are additive and order-independent, and a layer's settings do not overlap the base or any other layer, so applying the base plus any combination of layers never conflicts.

Apply the base as a vetted configuration, or open it in Build Mode against the definitions file to tune it first.

## Curation Principles

Every curated profile follows the same six curation principles. A target's reference document applies these principles to that target's specific decisions.

1. **Merit, not presence.** A setting earns its place for its effect on the target, not for its presence in a source. Turning off a feature that reports data, promotes a service, or widens the attack surface is hardening, while turning off a neutral one is only preference.
2. **Cost ceiling.** A setting is included in the base when its benefit outweighs a cost that is niche, nominal, or low in breakage. Since Build Mode can reverse any setting, that bar sits high enough to accept a cost to convenience rather than capability.
3. **Tradeoff by metric.** Where privacy and security conflict, a protection's breadth and whether it is already covered by another control are weighed against the sensitivity and continuity of the data it exposes. Broad and unique protection is kept even at a privacy cost, while narrow and redundant protection is traded away when that cost is sensitive or continuous.
4. **Security floor.** No setting whose only effect is to weaken security enters a profile. The integrity of time, certificates, and updates is never sacrificed.
5. **Scope boundary.** The profiles target standalone devices that are not joined to a domain. A setting inert on the current target but harmless and effective on another supported configuration is included, so one profile serves the whole supported range.
6. **Layering.** A hardening setting can have no cost on a device that does not use the feature it affects, yet a real cost on one that does. Such a setting is held back from the base and offered as an optional layer to the devices that lose nothing. A setting whose cost cannot be isolated to a feature is left to Build Mode.

## Reference Documents

Each target has one reference document in [reference/](reference/) for the base and all its layers. A reference document records the editorial decisions behind the curation, covering what the base includes and excludes and why, each layer and the device it assumes, and the tradeoffs that required a judgment call. Per-setting detail stays in the definitions references, which the profile reference document cites rather than repeats.
