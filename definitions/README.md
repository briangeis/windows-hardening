# Definitions

Definitions files describe the settings each component script can configure, curated from authoritative sources rather than exhaustive configuration checklists. They are the data layer of the toolkit, kept separate from script logic, and organized into categories, subcategories, and sections that drive the interactive menu.

## Naming Convention

Definitions files follow the pattern `Component-Source.psd1`. Component comes first so files cluster by purpose in directory listings. Source is a descriptive identifier for the file's subject matter and does not imply a one-to-one mapping with a single authoritative source. Each file is specific to one component and cannot be used with another component's script. A component may have multiple definitions files.

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

Settings are organized into a three-tier hierarchy: categories at the top, sections at the leaf, and an optional subcategory tier in between. Both structures can coexist within the same file, allowing each category to use either structure independently.

**Category > Section** (two-tier): used when a category is small enough that its sections can be listed directly.

```powershell
Categories = @(
    @{
        Name        = 'Telemetry & Diagnostics'
        Description = 'Settings controlling what this device reports to Microsoft'
        Sections    = @(
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

**Category > Subcategory > Section** (three-tier): used when a category is large enough that its sections benefit from intermediate grouping.

```powershell
Categories = @(
    @{
        Name          = 'App Permissions'
        Description   = 'Controls app access to device capabilities and personal data'
        Subcategories = @(
            @{
                Name        = 'Personalization & Tracking'
                Description = 'Advertising ID and cross-device experience settings'
                Sections    = @(
                    @{
                        Name        = 'Advertising ID'
                        Description = 'Controls the advertising ID used for app-targeted ads'
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

Every setting entry is a hashtable. All current fields are required.

| Field | Type | Required | Description |
|---|:---:|:---:|---|
| `Name` | String | Yes | Display name shown in the interactive menu |
| `Description` | String | Yes | One-line description of what the setting does |
| `Path` | String | Yes | Registry key path, using `HKLM:` or `HKCU:` notation |
| `ValueName` | String | Yes | Registry value name within the key |
| `ValueType` | String | Yes | Registry value type: `DWord`, `String`, `ExpandString`, `MultiString`, `QWord`, or `Binary` |
| `HardenedValue` | Varies | Yes | The value applied when the setting is hardened |
| `DefaultValue` | Varies | Yes | The Windows default value, or `$null` if the value does not exist by default. When `$null`, the script removes the registry value rather than writing one |
| `GPOPath` | String | Yes | Group Policy path to the equivalent policy setting, or `$null` if none exists |
| `GPOState` | String | Yes | The Group Policy state that produces the hardened value, or `$null` if no Group Policy equivalent exists |

## Reference Documents

Every definitions file is accompanied by a reference document in [`definitions/reference/`](reference/) with the same base name and a `.md` extension. [`Policy-MicrosoftPrivacyConnections.psd1`](Policy-MicrosoftPrivacyConnections.psd1) is accompanied by [`Policy-MicrosoftPrivacyConnections.md`](reference/Policy-MicrosoftPrivacyConnections.md).

A reference document maps every setting in the definitions file to its corresponding section in the source material and records the editorial decisions behind the file: settings with significant side effects, intentional deviations from the source's guidance, known inconsistencies in the source material, and source sections excluded from the file with the reason for each exclusion.

## Available Files

### Policy

- [Policy-MicrosoftPrivacyConnections.psd1](Policy-MicrosoftPrivacyConnections.psd1) ([reference](reference/Policy-MicrosoftPrivacyConnections.md))
  Covers 120 registry settings controlling connections and data sharing between Windows and Microsoft services, drawn from the Microsoft article "Manage connections from Windows 10 and Windows 11 operating system components to Microsoft services."
