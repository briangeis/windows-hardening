# Definitions Files

Definitions files describe the settings each component script can configure, curated from authoritative sources and independent research rather than exhaustive configuration checklists. They are the data layer of the toolkit, kept separate from script logic, and organized into categories and sections that drive the interactive menu.

## Available Files

### Policy

- [Policy-MicrosoftPrivacyConnections.psd1](Policy-MicrosoftPrivacyConnections.psd1) ([reference doc](reference/Policy-MicrosoftPrivacyConnections.md)) covers 116 registry settings controlling connections and data sharing between Windows and Microsoft services, drawn from the Microsoft article "Manage connections from Windows 10 and Windows 11 operating system components to Microsoft services."

- [Policy-WindowsPrivacyDefaults.psd1](Policy-WindowsPrivacyDefaults.psd1) ([reference doc](reference/Policy-WindowsPrivacyDefaults.md)) covers 46 registry settings targeting Windows 11 privacy and security defaults not addressed by Policy-MicrosoftPrivacyConnections, drawn from independent research and direct system analysis.

- [Policy-Edge.psd1](Policy-Edge.psd1) ([reference doc](reference/Policy-Edge.md)) covers 128 registry settings hardening Microsoft Edge for privacy and security on standalone Windows 11 devices, drawn from the Microsoft Edge ADMX policy templates and independent research.

## Naming Convention

Definitions files follow the pattern `Component-Source.psd1`. Component comes first so files cluster by purpose in directory listings. Source is a descriptive identifier for the subject matter of the file and does not imply a one-to-one mapping with a single authoritative source. Each file is specific to one component and cannot be used with another component's script. A component may have multiple definitions files.

Example: `Policy-MicrosoftPrivacyConnections.psd1`

## File Structure

### Header

Every definitions file opens with a comment header, then a machine-readable `Meta` block as the first key inside the file.

The comment header carries the project signature, the file's identity and one-line purpose, its provenance, and authorship:

```powershell
#
# windows-hardening
# https://github.com/briangeis/windows-hardening
#
# Policy Definitions: Edge
# Hardens the Microsoft Edge browser.
#
# Source:    Microsoft Edge policy reference
# URL:       https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies
# Reference: definitions/reference/Policy-Edge.md
#
# Author:  Brian Geis
# License: GPL-3.0-or-later
#
```

The title follows the pattern `Component Definitions: Human-Readable Name`, mirroring the filename. `Source` and `URL` point to the authoritative policy documentation for the settings, and `Reference` links the companion reference document.

The `Meta` block carries the same identity in a form a script can read, along with the review baseline:

```powershell
@{
    Meta = @{
        Component   = 'Policy'
        Name        = 'Edge'
        Description = 'Hardens the Microsoft Edge browser.'
        Target      = 'Microsoft Edge 148'
        Reviewed    = '2026-06-01'
    }
    Categories = @( ... )
}
```

`Component` is the component the file belongs to, `Name` and `Description` are its human-readable identity, `Target` is the upstream version the file was last reviewed against, and `Reviewed` is the date of that review.

### Hierarchy

Settings are organized into a hierarchy of categories and sections. A category may contain either sections directly or nested categories, but not both. Both structures can coexist within the same file, allowing each category to use whichever form fits its size.

**Category > Section**: used when a category is small enough that its sections can be listed directly.

```powershell
Categories = @(
    # ===== Category: Telemetry & Diagnostics =====
    @{
        Name        = 'Telemetry & Diagnostics'
        Description = 'Settings controlling what this device reports to Microsoft'
        Sections    = @(
            # -- Section: Feedback & Diagnostics --
            @{
                Name        = 'Feedback & Diagnostics'
                Description = 'Controls diagnostic data level and feedback frequency'
                Settings    = @(
                    # setting entries
                )
            }
        )
    }
)
```

**Category > Category > Section**: used when a category is large enough that its sections benefit from intermediate grouping.

```powershell
Categories = @(
    # ===== Category: App Permissions =====
    @{
        Name        = 'App Permissions'
        Description = 'Controls app access to device capabilities and personal data'
        Categories  = @(
            # === Category: Device Access ===
            @{
                Name        = 'Device Access'
                Description = 'Controls app access to hardware capabilities'
                Sections    = @(
                    # -- Section: Camera --
                    @{
                        Name        = 'Camera'
                        Description = 'Controls app access to the camera'
                        Settings    = @(
                            # setting entries
                        )
                    }
                )
            }
        )
    }
)
```

### Settings Fields

Every setting entry is a hashtable. Core fields are required. Advisory fields are optional and omitted when no advisory applies.

| Field           | Type   | Required | Description |
|-----------------|:------:|:--------:|-------------|
| `Name`          | String | Yes      | Display name shown in the interactive menu |
| `Description`   | String | Yes      | One-line description of what the setting does |
| `Path`          | String | Yes      | Registry key path, using `HKLM:` or `HKCU:` notation |
| `ValueName`     | String | Yes      | Registry value name within the key |
| `ValueType`     | String | Yes      | Registry value type, one of `DWord`, `String`, or `QWord` |
| `HardenedValue` | Varies | Yes      | The value applied when the setting is hardened |
| `DefaultValue`  | Varies | Yes      | The Windows default value, or `$null` if the value does not exist by default. When `$null`, the script removes the registry value rather than writing one |
| `GPOPath`       | String | Yes      | Group Policy path to the equivalent policy setting, or `$null` if none exists |
| `GPOState`      | String | Yes      | The Group Policy state that produces the hardened value, or `$null` if no Group Policy equivalent exists |
| `Note`          | String | No       | Informational context the user should be aware of before applying the setting |
| `Caution`       | String | No       | Potentially unwanted consequences that apply in certain configurations |
| `Warning`       | String | No       | Significant side effects affecting system functionality or security |

## Reference Documents

Every definitions file is accompanied by a reference document in [reference/](reference/) with the same base name and a `.md` extension. A reference document records the editorial decisions behind the definitions file, covering the distribution of settings across registry hives, settings with notable side effects or applicability conditions, and settings without a Group Policy equivalent. For files derived from a source article, it additionally maps every setting to its corresponding section in the source and documents intentional deviations, known inconsistencies, and excluded source content.
