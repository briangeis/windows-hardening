# Definitions Files

Definitions files describe the settings each component script can configure, curated from authoritative sources and independent research rather than exhaustive configuration checklists. They are the data layer of the toolkit, kept separate from script logic, and organized into categories and sections that drive the interactive menu.

## Available Files

### Policy

- [Policy-MicrosoftPrivacyConnections.psd1](Policy-MicrosoftPrivacyConnections.psd1) ([reference doc](reference/Policy-MicrosoftPrivacyConnections.md))
  Covers 116 registry settings controlling connections and data sharing between Windows and Microsoft services, drawn from the Microsoft article "Manage connections from Windows 10 and Windows 11 operating system components to Microsoft services."

- [Policy-WindowsPrivacyDefaults.psd1](Policy-WindowsPrivacyDefaults.psd1) ([reference doc](reference/Policy-WindowsPrivacyDefaults.md))
  Covers 46 registry settings targeting Windows 11 privacy and security defaults not addressed by Policy-MicrosoftPrivacyConnections, drawn from independent research and direct system analysis.

## Naming Convention

Definitions files follow the pattern `Component-Source.psd1`. Component comes first so files cluster by purpose in directory listings. Source is a descriptive identifier for the subject matter of the file and does not imply a one-to-one mapping with a single authoritative source. Each file is specific to one component and cannot be used with another component's script. A component may have multiple definitions files.

Example: `Policy-MicrosoftPrivacyConnections.psd1`

## File Structure

### Header

Every definitions file opens with a standard header block:

```powershell
#
# Component Definitions: Human-Readable Name
#
# Source: Formal title of the reference material
# URL:    https://link-to-source
#
```

The title follows the pattern `Component Definitions: Human-Readable Name`, mirroring the filename. `Source` is the formal title of the reference material. `URL` is the direct link to the source. A single blank line separates the header from the file content.

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
| `ValueType`     | String | Yes      | Registry value type: `DWord`, `String`, `ExpandString`, `MultiString`, `QWord`, or `Binary` |
| `HardenedValue` | Varies | Yes      | The value applied when the setting is hardened |
| `DefaultValue`  | Varies | Yes      | The Windows default value, or `$null` if the value does not exist by default. When `$null`, the script removes the registry value rather than writing one |
| `GPOPath`       | String | Yes      | Group Policy path to the equivalent policy setting, or `$null` if none exists |
| `GPOState`      | String | Yes      | The Group Policy state that produces the hardened value, or `$null` if no Group Policy equivalent exists |
| `Note`          | String | No       | Informational context the user should be aware of before applying the setting |
| `Caution`       | String | No       | Potentially unwanted consequences that apply in certain configurations |
| `Warning`       | String | No       | Significant side effects affecting system functionality or security |

## Reference Documents

Every definitions file is accompanied by a reference document in [`definitions/reference/`](reference/) with the same base name and a `.md` extension. [Policy-MicrosoftPrivacyConnections.psd1](Policy-MicrosoftPrivacyConnections.psd1) is accompanied by [Policy-MicrosoftPrivacyConnections.md](reference/Policy-MicrosoftPrivacyConnections.md), and [Policy-WindowsPrivacyDefaults.psd1](Policy-WindowsPrivacyDefaults.psd1) by [Policy-WindowsPrivacyDefaults.md](reference/Policy-WindowsPrivacyDefaults.md).

A reference document records the editorial decisions behind the definitions file, covering the distribution of settings across registry hives, settings with notable side effects or applicability conditions, and settings without a Group Policy equivalent. For files derived from a source article, it additionally maps every setting to its corresponding section in the source and documents intentional deviations, known inconsistencies, and excluded source content.
