<#
.SYNOPSIS
    Applies registry and Local Group Policy hardening settings.

.DESCRIPTION
    A PowerShell script for hardening Windows on standalone devices.
    Home editions write settings directly to the registry.
    Other editions apply settings through Local Group Policy using LGPO.exe.

    Supports four modes of operation:

    Interactive Mode
      Presents a menu of settings from a definitions file, showing the current
      registry state of each setting alongside its hardened and default values.
      Settings can be applied or reset to their default values individually,
      or all at once within a section. A snapshot is saved automatically on
      startup. Requires administrator privileges.

    Profile Mode
      Reads a profile file and applies all settings without prompting.
      A snapshot is saved automatically before applying any changes.
      Requires administrator privileges.

    Build Mode
      Presents the same menu as Interactive Mode but saves selections to a
      profile file instead of applying them to the device. Settings already
      added to the profile can also be removed from it. Does not require
      administrator privileges. Can be run on Windows or Linux to prepare
      a profile before applying it to a Windows device.

    Snapshot Mode
      Reads the current registry state of every setting in a definitions
      file and saves it as a profile. Captures the current device state
      before replication or reimaging. Requires administrator privileges.

.PARAMETER DefinitionsPath
    Path to a PSD1 definitions file. Required for all modes except Profile Mode.

.PARAMETER ProfilePath
    Path to a PSD1 profile file to apply. Triggers Profile Mode: all settings
    in the profile are applied to the registry without prompting.

.PARAMETER Build
    Path to the profile file to build. Triggers Build Mode: presents the same
    settings menu as Interactive Mode, saving selections to the profile file
    instead of the device. An existing file is loaded as the starting state
    and updated in place. Administrator privileges are not required.

.PARAMETER Snapshot
    File or directory path for the snapshot profile. Triggers Snapshot Mode:
    reads the current registry state for every setting in the definitions file
    and saves a profile to the specified path. If a directory is given,
    a generated filename is used. Requires administrator privileges.

.PARAMETER LogPath
    File or directory path for the log file. If a directory is given,
    a generated filename is used. Defaults to the current working directory
    with a generated filename if not provided. Sessions are appended to
    the log file rather than overwriting it.

.PARAMETER LGPOPath
    Explicit path to LGPO.exe. If not provided, the script searches the
    script directory and then the system PATH. Required for Pro, Enterprise,
    Education, and LTSC editions when applying changes.

.EXAMPLE
    .\policy\Invoke-WinHardenPolicy.ps1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1
    Interactive Mode: opens the settings menu. Run from the project root.

.EXAMPLE
    .\policy\Invoke-WinHardenPolicy.ps1 -ProfilePath .\profiles\Policy-Windows-Base.psd1
    Profile Mode: applies all settings in the profile without prompting.

.EXAMPLE
    .\policy\Invoke-WinHardenPolicy.ps1 -Build .\my-profile.psd1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1
    Build Mode: saves selections to my-profile.psd1 for later application.

.EXAMPLE
    .\policy\Invoke-WinHardenPolicy.ps1 -Snapshot .\my-snapshot.psd1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1
    Snapshot Mode: captures the current registry state for each defined setting.

.NOTES
    Author:  Brian Geis
    License: GPL-3.0-or-later
    Project: https://github.com/briangeis/windows-hardening

.LINK
    https://github.com/briangeis/windows-hardening
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'Interactive', Mandatory)]
    [Parameter(ParameterSetName = 'Build',       Mandatory)]
    [Parameter(ParameterSetName = 'Snapshot',    Mandatory)]
    [string]$DefinitionsPath,

    [Parameter(ParameterSetName = 'Profile', Mandatory)]
    [string]$ProfilePath,

    [Parameter(ParameterSetName = 'Build', Mandatory)]
    [string]$Build,

    [Parameter(ParameterSetName = 'Snapshot', Mandatory)]
    [string]$Snapshot,

    [string]$LogPath,

    [Parameter(ParameterSetName = 'Interactive')]
    [Parameter(ParameterSetName = 'Profile')]
    [string]$LGPOPath
)

#region SESSION STATE

$script:HostName = [System.Net.Dns]::GetHostName()

# Component identity and tool name: written into generated files and checked on import
$script:Component = 'Policy'
$script:ToolName  = 'Invoke-WinHardenPolicy'

# Supported value types: scalar registry types and their LGPO prefixes
$script:SupportedValueTypes = [ordered]@{
    DWord  = 'DWORD'
    String = 'SZ'
    QWord  = 'QWORD'
}

# Session counters for the log summary
$script:ChangedCount = 0
$script:FailedCount  = 0

# Windows edition context: populated by Initialize-EditionContext before write operations
$script:IsHomeEdition = $false
$script:LGPOExePath   = $null

# Verify retry: attempt count and delay while a Group Policy refresh completes
$script:VerifyMaxRetries   = 100
$script:VerifyRetryDelayMs = 50

# Build Mode profile data: profile file contents held in memory for the session
$script:IsBuildMode = $false
$script:BuildData   = @{ Meta = @{}; Settings = @{} }

# Resolved log file path: generated from -LogPath or defaulted if omitted
$script:LogPath = if (-not $LogPath) {
    Join-Path (Get-Location) "${script:Component}-Log_${script:HostName}.log"
} elseif (Test-Path $LogPath -PathType Container) {
    Join-Path $LogPath "${script:Component}-Log_${script:HostName}.log"
} else {
    $LogPath
}

#endregion

#region LOGGING

function Write-LogEntry {
    <#
    .SYNOPSIS
        Appends a timestamped entry to the persistent log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    # Collapse embedded line breaks so each entry stays on one physical line
    $singleLine = ($Message -replace '\s*[\r\n]+\s*', ' ').Trim()
    $entry = "[$timestamp] $singleLine"
    $entry | Out-File -FilePath $script:LogPath -Append -Encoding ASCII
}

function Write-LogError {
    <#
    .SYNOPSIS
        Logs a failed operation, naming the command that threw.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    # CategoryInfo.Activity names the failing cmdlet; a .NET method leaves it empty
    $source = if ($ErrorRecord.CategoryInfo.Activity) {
        $ErrorRecord.CategoryInfo.Activity
    } else {
        'Registry operation'
    }
    Write-LogEntry "${source}: $ErrorRecord"
}

function Write-LogSessionStart {
    <#
    .SYNOPSIS
        Writes a session header to the log with environment context.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Mode,
        [string]$DefinitionsPath = '',
        [string]$ProfilePath = ''
    )

    # Gather OS info for the session header
    $osInfo = try {
        (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption
    }
    catch {
        'Unknown OS'
    }

    Write-LogEntry "Session started - $script:HostName - $osInfo - $Mode Mode"
    if ($DefinitionsPath) {
        Write-LogEntry "Definitions file: $DefinitionsPath"
    }
    if ($ProfilePath) {
        Write-LogEntry "Profile file: $ProfilePath"
    }
}

function Write-LogSessionEnd {
    <#
    .SYNOPSIS
        Writes a session summary to the log.
    #>
    [CmdletBinding()]
    param()
    Write-LogEntry "Session ended - $($script:ChangedCount) changed, $($script:FailedCount) failed"
}

function Write-FatalError {
    <#
    .SYNOPSIS
        Logs a fatal error, writes it to the console, and exits with code 1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [string]$Detail = ''
    )
    Write-LogEntry "ERROR: $Message"
    Write-LogSessionEnd
    Write-Host "  [X] $Message" -ForegroundColor Red
    if ($Detail) { Write-Host "      $Detail" -ForegroundColor Red }
    exit 1
}

#endregion

#region PREREQUISITES

function Test-Prerequisite {
    <#
    .SYNOPSIS
        Validates that the script can run in the current environment.
    #>
    [CmdletBinding()]
    param(
        [bool]$RequireElevation = $true
    )

    # PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5 -or
        ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
        Write-FatalError 'PowerShell 5.1 or later is required.'
    }

    # Platform and elevation
    if ($RequireElevation) {
        if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
            Write-FatalError 'This mode requires Windows.'
        }
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$identity
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-FatalError 'This script must be run as Administrator.'
        }
    }
}

function Initialize-EditionContext {
    <#
    .SYNOPSIS
        Detects the Windows edition and resolves the LGPO.exe path
        for Pro, Enterprise, Education, and LTSC editions.
    #>
    [CmdletBinding()]
    param()

    function GetWindowsEdition {
        try {
            # The Home family reports a 'Core' edition
            $editionId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID
            if ($editionId -like 'Core*') { return 'Home' }
            return 'NonHome'
        }
        catch {
            $params = @{
                Message = 'Could not determine the Windows edition.'
                Detail  = 'Ensure the EditionID value under HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion is accessible.'
            }
            Write-FatalError @params
        }
    }

    function ResolveLGPOPath {
        # If -LGPOPath was provided, treat it as a hard requirement
        if ($LGPOPath) {
            if (Test-Path $LGPOPath -PathType Leaf) { return $LGPOPath }
            $params = @{
                Message = "LGPO.exe not found at the specified path: $LGPOPath"
                Detail  = 'Verify the path is correct and the file exists.'
            }
            Write-FatalError @params
        }

        # Check script directory
        $scriptDirPath = Join-Path $PSScriptRoot 'LGPO.exe'
        if (Test-Path $scriptDirPath -PathType Leaf) {
            return $scriptDirPath
        }

        # Check system PATH
        $pathResult = Get-Command 'LGPO.exe' -ErrorAction SilentlyContinue
        if ($pathResult) {
            return $pathResult.Source
        }

        $params = @{
            Message = 'LGPO.exe not found.'
            Detail  = 'Pro, Enterprise, Education, and LTSC editions require LGPO.exe to apply Group Policy settings. Direct registry writes would be overridden at the next Group Policy refresh. Download LGPO.exe from the Microsoft Security Compliance Toolkit.'
        }
        Write-FatalError @params
    }

    $edition = GetWindowsEdition

    if ($edition -eq 'Home') {
        $script:IsHomeEdition = $true
    }
    else {
        $script:IsHomeEdition = $false
        $script:LGPOExePath   = ResolveLGPOPath
    }
}

#endregion

#region FILE I/O

function Import-DefinitionsFile {
    <#
    .SYNOPSIS
        Loads and validates a definitions file, stopping with a fatal error
        if the file is missing, unparsable, or structurally invalid.
    .OUTPUTS
        Returns the loaded definitions hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path -PathType Leaf)) {
        Write-FatalError "Definitions file not found: $Path"
    }

    $definitions = $null
    try {
        $definitions = Import-PowerShellDataFile -Path $Path
    }
    catch {
        Write-FatalError "Failed to load definitions file: $_"
    }

    function ValidateCategory([hashtable]$Category, [string]$Location) {
        $where = if ($Location) { "at '$Location'" } else { 'at the top level' }
        foreach ($key in 'Name', 'Description') {
            if (-not $Category.ContainsKey($key)) {
                $label = if ($Category.ContainsKey('Name')) { $Category.Name } else { '(unnamed)' }
                Write-FatalError "Category '$label' $where is missing key '$key'."
            }
        }
        $childLocation = if ($Location) { "$Location > $($Category.Name)" } else { $Category.Name }
        if ($Category.ContainsKey('Categories')) {
            if (-not $Category.Categories) {
                Write-FatalError "Category '$($Category.Name)' $where has an empty 'Categories' array."
            }
            foreach ($child in @($Category.Categories)) { ValidateCategory $child $childLocation }
        }
        elseif ($Category.ContainsKey('Sections')) {
            if (-not $Category.Sections) {
                Write-FatalError "Category '$($Category.Name)' $where has an empty 'Sections' array."
            }
            foreach ($section in @($Category.Sections)) { ValidateSection $section $childLocation }
        }
        else {
            Write-FatalError "Category '$($Category.Name)' $where has neither 'Categories' nor 'Sections'."
        }
    }

    function ValidateSection([hashtable]$Section, [string]$Location) {
        foreach ($key in 'Name', 'Description') {
            if (-not $Section.ContainsKey($key)) {
                $label = if ($Section.ContainsKey('Name')) { $Section.Name } else { '(unnamed)' }
                Write-FatalError "Section '$label' at '$Location' is missing key '$key'."
            }
        }
        if (-not $Section.ContainsKey('Settings')) {
            Write-FatalError "Section '$($Section.Name)' at '$Location' is missing key 'Settings'."
        }
        if (-not $Section.Settings) {
            Write-FatalError "Section '$($Section.Name)' at '$Location' has an empty 'Settings' array."
        }
        $sectionLocation = "$Location > $($Section.Name)"
        foreach ($setting in @($Section.Settings)) { ValidateSetting $setting $sectionLocation }
    }

    function ValidateSetting([hashtable]$Setting, [string]$Location) {
        $requiredKeys = 'Name', 'Description', 'Path', 'ValueName', 'ValueType', 'HardenedValue', 'DefaultValue'
        foreach ($key in $requiredKeys) {
            if (-not $Setting.ContainsKey($key)) {
                $label = if ($Setting.ContainsKey('Name')) { $Setting.Name } else { '(unnamed)' }
                Write-FatalError "Setting '$label' at '$Location' is missing required key '$key'."
            }
        }
        # Guard against value types the comparison, LGPO, and serialization paths cannot handle
        if ($Setting.ValueType -notin $script:SupportedValueTypes.Keys) {
            $params = @{
                Message = "Setting '$($Setting.Name)' at '$Location' has unsupported ValueType '$($Setting.ValueType)'."
                Detail  = "Set ValueType to one of: $($script:SupportedValueTypes.Keys -join ', ')."
            }
            Write-FatalError @params
        }
        # Guard against a Path under any hive but HKLM or HKCU
        if ($Setting.Path -notmatch '^HK(LM|CU):\\') {
            $params = @{
                Message = "Setting '$($Setting.Name)' at '$Location' has an unsupported registry Path."
                Detail  = "Path must be rooted at HKLM:\ or HKCU:\. Found: '$($Setting.Path)'."
            }
            Write-FatalError @params
        }
    }

    if (-not $definitions.ContainsKey('Meta')) {
        $params = @{
            Message = "Definitions file is missing the required 'Meta' block."
            Detail  = 'Verify the file is a valid definitions file for this script.'
        }
        Write-FatalError @params
    }
    foreach ($key in 'Component', 'Name', 'Description', 'Target', 'Reviewed') {
        if (-not $definitions.Meta.ContainsKey($key)) {
            Write-FatalError "Definitions file 'Meta' block is missing key '$key'."
        }
    }
    if ($definitions.Meta.Component -ne $script:Component) {
        $params = @{
            Message = "Definitions file targets the '$($definitions.Meta.Component)' component, not '$script:Component'."
            Detail  = 'Provide a definitions file for this component.'
        }
        Write-FatalError @params
    }

    if (-not $definitions.ContainsKey('Categories') -or -not $definitions.Categories) {
        $params = @{
            Message = "Definitions file is missing a top-level 'Categories' array."
            Detail  = 'Verify the file is a valid definitions file for this script.'
        }
        Write-FatalError @params
    }

    foreach ($category in @($definitions.Categories)) {
        ValidateCategory $category ''
    }

    return $definitions
}

function Import-ProfileFile {
    <#
    .SYNOPSIS
        Loads and validates a profile file, stopping with a fatal error
        if the file is missing, unparsable, or structurally invalid.
    .OUTPUTS
        Returns the loaded profile hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path -PathType Leaf)) {
        Write-FatalError "Profile file not found: $Path"
    }

    $profileData = $null
    try {
        $profileData = Import-PowerShellDataFile -Path $Path
    }
    catch {
        Write-FatalError "Failed to load profile file: $_"
    }

    # Component guard: require this script's component
    if (-not ($profileData.ContainsKey('Meta') -and $profileData.Meta.ContainsKey('Component'))) {
        $params = @{
            Message = "Profile file is missing the required 'Meta.Component' key."
            Detail  = 'Verify the file was generated by this script or follows the required format.'
        }
        Write-FatalError @params
    }
    if ($profileData.Meta.Component -ne $script:Component) {
        $params = @{
            Message = "Profile file targets the '$($profileData.Meta.Component)' component, not '$script:Component'."
            Detail  = 'Provide a profile generated for this component.'
        }
        Write-FatalError @params
    }

    if (-not $profileData.ContainsKey('Settings')) {
        $params = @{
            Message = "Profile file is missing the required 'Settings' key."
            Detail  = 'Verify the file was generated by this script or follows the required format.'
        }
        Write-FatalError @params
    }

    $requiredKeys = 'Name', 'Path', 'ValueName', 'ValueType', 'Value'
    $index = 0
    foreach ($entry in @($profileData.Settings)) {
        $index++
        $label = if ($entry.ContainsKey('Name')) { "'$($entry.Name)'" } else { "entry $index" }
        foreach ($key in $requiredKeys) {
            if (-not $entry.ContainsKey($key)) {
                $params = @{
                    Message = "Profile $label is missing required key '$key'."
                    Detail  = 'Verify the file was generated by this script or follows the required format.'
                }
                Write-FatalError @params
            }
        }
        if ($entry.ValueType -notin $script:SupportedValueTypes.Keys) {
            $params = @{
                Message = "Profile $label has unsupported ValueType '$($entry.ValueType)'."
                Detail  = "Set ValueType to one of: $($script:SupportedValueTypes.Keys -join ', ')."
            }
            Write-FatalError @params
        }
    }

    return $profileData
}

function Export-ProfileFile {
    <#
    .SYNOPSIS
        Serializes a profile's banner, Meta, and Settings to a PSD1 file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Meta,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Entries,
        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $sb = [System.Text.StringBuilder]::new()

    # Render a value as a single-quoted PSD1 literal, escaping embedded quotes
    function QuoteString([string]$Text) { "'" + ($Text -replace "'", "''") + "'" }

    # Banner: project signature, component identity, and generating mode
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine('# windows-hardening')
    [void]$sb.AppendLine('# https://github.com/briangeis/windows-hardening')
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine("# $($Meta.Component) Profile")
    [void]$sb.AppendLine("# Generated by $($Meta.GeneratedBy) in $($Meta.Mode) Mode.")
    [void]$sb.AppendLine('# Apply with -ProfilePath.')
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('@{')

    # Meta: provenance fields in fixed order (ComputerName omitted when absent)
    [void]$sb.AppendLine('    Meta = @{')
    [void]$sb.AppendLine("        Component    = $(QuoteString $Meta.Component)")
    [void]$sb.AppendLine("        Mode         = $(QuoteString $Meta.Mode)")
    [void]$sb.AppendLine("        GeneratedBy  = $(QuoteString $Meta.GeneratedBy)")
    [void]$sb.AppendLine("        GeneratedOn  = $(QuoteString $Meta.GeneratedOn)")
    if ($Meta.ContainsKey('ComputerName')) {
        [void]$sb.AppendLine("        ComputerName = $(QuoteString $Meta.ComputerName)")
    }
    [void]$sb.AppendLine('        Source       = @(')
    foreach ($src in @($Meta.Source)) {
        if ($null -eq $src) { continue }
        [void]$sb.AppendLine('            @{')
        [void]$sb.AppendLine("                Name     = $(QuoteString $src.Name)")
        [void]$sb.AppendLine("                File     = $(QuoteString $src.File)")
        [void]$sb.AppendLine("                Target   = $(QuoteString $src.Target)")
        [void]$sb.AppendLine("                Reviewed = $(QuoteString $src.Reviewed)")
        [void]$sb.AppendLine('            }')
    }
    [void]$sb.AppendLine('        )')
    [void]$sb.AppendLine('    }')
    [void]$sb.AppendLine('')

    # Settings: one entry per setting in fixed field order
    [void]$sb.AppendLine('    Settings = @(')
    foreach ($entry in $Entries) {
        [void]$sb.AppendLine('        @{')
        [void]$sb.AppendLine("            Name      = $(QuoteString $entry.Name)")
        [void]$sb.AppendLine("            Path      = $(QuoteString $entry.Path)")
        [void]$sb.AppendLine("            ValueName = $(QuoteString $entry.ValueName)")
        [void]$sb.AppendLine("            ValueType = $(QuoteString $entry.ValueType)")
        if ($null -eq $entry.Value) {
            [void]$sb.AppendLine('            Value     = $null')
        }
        elseif ($entry.Value -is [string]) {
            [void]$sb.AppendLine("            Value     = $(QuoteString $entry.Value)")
        }
        else {
            [void]$sb.AppendLine("            Value     = $($entry.Value)")
        }
        [void]$sb.AppendLine('        }')
    }

    [void]$sb.AppendLine('    )')
    [void]$sb.AppendLine('}')

    $sb.ToString() | Out-File -FilePath $OutputPath -Encoding ASCII -Force -ErrorAction Stop
}

#endregion

#region POLICY

function Get-SettingCurrentValue {
    <#
    .SYNOPSIS
        Reads a setting's current value from the registry or build profile.
    .OUTPUTS
        Returns a hashtable with Exists (bool) and Value properties. A read
        failure that is not a genuine absence also includes Error, the
        caught error record. In Build Mode, includes ExplicitAbsence (bool).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName
    )

    if ($script:IsBuildMode) {
        return Get-BuildSettingCurrentValue -Path $Path -ValueName $ValueName
    }

    try {
        return @{ Exists = $true; Value = (Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction Stop).$ValueName }
    }
    catch [System.Management.Automation.ItemNotFoundException],
          [System.Management.Automation.PSArgumentException] {
        # Genuine absence: the key or value is not present
        return @{ Exists = $false; Value = $null }
    }
    catch {
        # A real read error: surface it so callers can tell it from absence
        return @{ Exists = $false; Value = $null; Error = $_ }
    }
}

function Get-SettingState {
    <#
    .SYNOPSIS
        Determines a setting's state by comparing its value, or its absence,
        to the hardened and default values from the definitions file.
    .OUTPUTS
        Returns 'HARDENED', 'DEFAULT', 'CUSTOM', or 'NOT SET'.
        'NOT SET' is Build Mode only; it means the profile has no entry.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Setting
    )

    $current = Get-SettingCurrentValue -Path $Setting.Path -ValueName $Setting.ValueName

    # Build Mode: a setting with no profile entry is not configured at all
    if ($script:IsBuildMode -and -not $current.Exists -and -not $current.ExplicitAbsence) {
        return 'NOT SET'
    }

    # Compare the value to the hardened and default values; $null matches absence
    if ($current.Exists) {
        if ($current.Value -eq $Setting.HardenedValue) { return 'HARDENED' }
        if ($null -ne $Setting.DefaultValue -and $current.Value -eq $Setting.DefaultValue) { return 'DEFAULT' }
        return 'CUSTOM'
    }

    if ($null -eq $Setting.HardenedValue) { return 'HARDENED' }
    if ($null -eq $Setting.DefaultValue)  { return 'DEFAULT' }
    return 'CUSTOM'
}

function Invoke-SettingApply {
    <#
    .SYNOPSIS
        Applies a batch of settings and verifies that each one took effect.
    .OUTPUTS
        Returns one hashtable per setting, in the order given, holding
        Setting, Operation ('Write' or 'Remove'), Outcome ('Changed',
        'Unchanged', 'Failed', or 'VerifyFailed'), and Before (the
        Get-SettingCurrentValue reading taken before the change).
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory)]
        [array]$Settings
    )

    # Pre-read: the Before state, taken before any write so no read falls in the refresh
    $results = @()
    foreach ($entry in $Settings) {
        $operation = if ($null -eq $entry.Value) { 'Remove' } else { 'Write' }
        $results += @{
            Setting   = $entry
            Operation = $operation
            Outcome   = $null
            Before    = Get-SettingCurrentValue -Path $entry.Path -ValueName $entry.ValueName
        }
    }

    # Build Mode: a profile write succeeds or fails outright, so there is nothing to verify
    if ($script:IsBuildMode) {
        foreach ($result in $results) {
            $result.Outcome = Invoke-BuildApply -Setting $result.Setting
        }
        return $results
    }

    if ($script:IsHomeEdition) {
        # Home: a registry read is proof of its own state, so a correct value is left alone
        foreach ($result in $results) {
            $result.Outcome = Invoke-RegistryApply -Setting $result.Setting -Before $result.Before
        }
    }
    else {
        # Non-Home: a registry read is not proof of policy state, so every setting is written
        if (Invoke-LGPOApply -Settings $Settings) {
            foreach ($result in $results) { $result.Outcome = 'Changed' }
        }
        else {
            # A failed call hides which entries reached Registry.pol, so the whole batch fails
            foreach ($result in $results) { $result.Outcome = 'Failed' }
            return $results
        }
    }

    # Verify: re-read until each value matches, on a retry budget shared by the batch
    $retriesLeft = if ($script:IsHomeEdition) { 0 } else { $script:VerifyMaxRetries }

    foreach ($result in $results) {
        if ($result.Outcome -ne 'Changed') { continue }
        $entry = $result.Setting

        # Absence is $null at both ends, so one comparison covers a write and a removal
        $read     = Get-SettingCurrentValue -Path $entry.Path -ValueName $entry.ValueName
        $verified = (-not $read.Error) -and ($read.Value -eq $entry.Value)
        while (-not $verified -and $retriesLeft -gt 0) {
            Start-Sleep -Milliseconds $script:VerifyRetryDelayMs
            $retriesLeft--
            $read     = Get-SettingCurrentValue -Path $entry.Path -ValueName $entry.ValueName
            $verified = (-not $read.Error) -and ($read.Value -eq $entry.Value)
        }
        if ($verified) { continue }

        $expected = if ($null -eq $entry.Value) { '(absent)' } else { "$($entry.Value)" }
        if ($read.Error) {
            Write-LogError $read.Error
        } elseif ($read.Exists) {
            Write-LogEntry "Verify: read $($read.Value), expected $expected"
        } else {
            Write-LogEntry "Verify: read (absent), expected $expected"
        }
        $result.Outcome = 'VerifyFailed'
    }

    return $results
}

function Invoke-RegistryApply {
    <#
    .SYNOPSIS
        Writes or removes one registry value directly on Home editions.
    .OUTPUTS
        Returns 'Changed', 'Unchanged', or 'Failed'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Setting,
        [Parameter(Mandatory)]
        [hashtable]$Before
    )

    # Remove: a read error is not an absence, so it must not skip the removal
    if ($null -eq $Setting.Value) {
        if (-not $Before.Exists -and -not $Before.Error) { return 'Unchanged' }
        try {
            Remove-ItemProperty -Path $Setting.Path -Name $Setting.ValueName -ErrorAction Stop
        }
        catch {
            Write-LogError $_
            return 'Failed'
        }
        return 'Changed'
    }

    # Write: create the key if needed, then set the value
    if ($Before.Exists -and $Before.Value -eq $Setting.Value) { return 'Unchanged' }
    try {
        if (-not (Test-Path $Setting.Path)) {
            New-Item -Path $Setting.Path -Force -ErrorAction Stop | Out-Null
        }
        $params = @{
            Path        = $Setting.Path
            Name        = $Setting.ValueName
            Value       = $Setting.Value
            Type        = $Setting.ValueType
            Force       = $true
            ErrorAction = 'Stop'
        }
        Set-ItemProperty @params
    }
    catch {
        Write-LogError $_
        return 'Failed'
    }

    return 'Changed'
}

function Invoke-LGPOApply {
    <#
    .SYNOPSIS
        Writes a batch of settings to the Local Group Policy Object in
        a single LGPO.exe call on Pro, Enterprise, Education, and LTSC
        editions. The values reach the registry through the Group Policy
        refresh that LGPO.exe triggers, which completes after it returns.
    .OUTPUTS
        Returns $true when LGPO.exe reported success, $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [array]$Settings
    )

    $tempFile = [System.IO.Path]::GetTempFileName()

    try {
        # Compose one text file: an absent target becomes DELETE, any other its LGPO type
        $builder = New-Object System.Text.StringBuilder
        foreach ($setting in $Settings) {
            $section  = if ($setting.Path -like 'HKLM:*') { 'Computer' } else { 'User' }
            $lgpoPath = $setting.Path -replace '^HK(LM|CU):\\', ''

            if ($null -eq $setting.Value) {
                $action = 'DELETE'
            }
            else {
                # DWORD and QWORD are written as decimal, all others literally
                $lgpoType  = $script:SupportedValueTypes[$setting.ValueType]
                $lgpoValue = if ($lgpoType -eq 'DWORD') {
                    [uint32]$setting.Value
                } elseif ($lgpoType -eq 'QWORD') {
                    [uint64]$setting.Value
                } else {
                    "$($setting.Value)"
                }
                $action = "${lgpoType}:$lgpoValue"
            }

            [void]$builder.Append("$section`r`n$lgpoPath`r`n$($setting.ValueName)`r`n$action`r`n`r`n")
        }

        [System.IO.File]::WriteAllText($tempFile, $builder.ToString(), [System.Text.Encoding]::ASCII)
        $lgpoOutput = & $script:LGPOExePath /t $tempFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-LogEntry "LGPO.exe: $($lgpoOutput -join ' ')"
            return $false
        }
        $count = @($Settings).Count
        $noun  = if ($count -eq 1) { 'entry' } else { 'entries' }
        Write-LogEntry "LGPO.exe: $count $noun written to Local Group Policy"
    }
    catch {
        Write-LogError $_
        return $false
    }
    finally {
        Remove-Item $tempFile -ErrorAction SilentlyContinue
    }

    return $true
}

#endregion

#region MENU ENGINE

function Invoke-Menu {
    <#
    .SYNOPSIS
        Drives the interactive menu for the given context level,
        recursing into child levels on selection and returning on exit.
    .OUTPUTS
        Returns 'Back' on Esc or 'Quit' on Q when called with -IsChild;
        'Quit' cascades through all callers. Root calls return nothing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Context,
        [string]$Breadcrumb = '',
        [switch]$IsChild
    )

    $selectedIndex = 0
    $refresh       = $true
    $exitReason    = $null
    $isRoot        = -not $IsChild
    $lastWidth     = [Console]::WindowWidth
    $lastHeight    = [Console]::WindowHeight

    function StateColor([string]$State) {
        switch ($State) {
            'HARDENED' { 'Green'    }
            'DEFAULT'  { 'Yellow'   }
            'CUSTOM'   { 'Magenta'  }
            'NOT SET'  { 'DarkGray' }
        }
    }

    function AdvisoryMarker([hashtable]$Setting) {
        if ($Setting.ContainsKey('Warning')) { return @{ Glyph = '(!)'; Color = 'Red' } }
        if ($Setting.ContainsKey('Caution')) { return @{ Glyph = '(!)'; Color = 'Yellow' } }
        if ($Setting.ContainsKey('Note'))    { return @{ Glyph = '(i)'; Color = 'DarkCyan' } }
        return @{ Glyph = ''; Color = $null }
    }

    # Fit a breadcrumb to one line by dropping its leading segments
    function FitBreadcrumb([string]$Text) {
        $max = [Console]::WindowWidth - 3
        if ($Text.Length -le $max) { return $Text }
        $parts = $Text -split ' > '
        for ($drop = 1; $drop -lt $parts.Count; $drop++) {
            $candidate = '... > ' + ($parts[$drop..($parts.Count - 1)] -join ' > ')
            if ($candidate.Length -le $max) { return $candidate }
        }
        if ($max -ge 4) { return '...' + $Text.Substring($Text.Length - ($max - 3)) }
        return $Text.Substring(0, [Math]::Max($max, 0))
    }

    # Render a menu row; truncate an overlong name to keep the tokens visible
    function WriteMenuItem([string]$Name, [string[]]$Trailing, [switch]$Selected) {
        $w      = [Console]::WindowWidth
        $prefix = if ($Selected) { '  > ' } else { '    ' }

        # Sum the pinned token widths from the flat [text, color] pairs
        $pinnedWidth = 0
        for ($k = 0; $k -lt $Trailing.Count; $k += 2) { $pinnedWidth += $Trailing[$k].Length }

        # Truncate to the budget, which a narrow window can make negative
        $nameBudget  = $w - $prefix.Length - $pinnedWidth
        $displayName = $Name
        if ($displayName.Length -gt $nameBudget) {
            $displayName = if ($nameBudget -ge 4) { $displayName.Substring(0, $nameBudget - 3) + '...' }
                           else                   { $displayName.Substring(0, [Math]::Max($nameBudget, 0)) }
        }

        # Assemble the row as flat [text, color] pairs: name, tokens, padding
        $used     = $prefix.Length + $displayName.Length + $pinnedWidth
        $pad      = [Math]::Max($w - $used, 0)
        $segments = @("$prefix$displayName", '') + $Trailing + @((' ' * $pad), '')

        for ($k = 0; $k -lt $segments.Count; $k += 2) {
            $params = @{ Object = $segments[$k]; NoNewline = $true }
            if ($Selected)             { $params.ForegroundColor = 'Black'; $params.BackgroundColor = 'White' }
            elseif ($segments[$k + 1]) { $params.ForegroundColor = $segments[$k + 1] }
            Write-Host @params
        }
        Write-Host ''
    }

    # At the root, hide the cursor; the finally restores it on any root exit
    if ($isRoot) { [Console]::CursorVisible = $false }
    try {
        while (-not $exitReason) {
            # Refresh: recompute the view's data when the context changes
            if ($refresh) {
                $children = @(
                    if     ($Context.Categories) { $Context.Categories }
                    elseif ($Context.Sections)   { $Context.Sections }
                    else                         { $Context.Settings }
                )

                $isSettingsLevel = $Context.ContainsKey('Settings')

                # Location line: identity label at the root, breadcrumb below it
                $location = if ($isRoot) {
                    "windows-hardening - $($Context.Meta.Component): $($Context.Meta.Name)"
                } else {
                    $Breadcrumb
                }

                $titleName   = if ($isRoot) { $Context.Meta.Name }        else { $Context.Name }
                $description = if ($isRoot) { $Context.Meta.Description } else { $Context.Description }

                # Item rows: each is a name plus its pinned trailing token(s)
                $items         = @()
                $selectedCount = 0
                $totalCount    = 0

                if ($isSettingsLevel) {
                    foreach ($setting in $children) {
                        $state    = Get-SettingState -Setting $setting
                        $adv      = AdvisoryMarker $setting
                        $trailing = @("  [$state]", (StateColor $state))
                        if ($adv.Glyph) { $trailing += @("  $($adv.Glyph)", $adv.Color) }
                        $items += @{ Name = $setting.Name; Trailing = $trailing }

                        if ($script:IsBuildMode) {
                            if ($state -eq 'HARDENED' -or $state -eq 'DEFAULT') { $selectedCount++ }
                        } elseif ($state -eq 'HARDENED') {
                            $selectedCount++
                        }
                    }
                    $totalCount = $children.Count
                    $applyLabel = if ($script:IsBuildMode) { 'Set All' } else { 'Apply All' }
                    $hints = "[Enter] View Detail  [A] $applyLabel  [Esc] Back  [Q] Quit"
                }
                else {
                    foreach ($child in $children) {
                        $counts = Get-SettingCount -Node $child
                        $items += @{
                            Name     = $child.Name
                            Trailing = @("  ($($counts.Selected)/$($counts.Total))", 'DarkGray')
                        }
                        $selectedCount += $counts.Selected
                        $totalCount    += $counts.Total
                    }
                    $hints = if ($isRoot) { '[Enter] Select  [Q] Quit' }
                             else         { '[Enter] Select  [Esc] Back  [Q] Quit' }
                }

                $titleCount = "($selectedCount/$totalCount)"
                $title      = "$titleName  $titleCount"

                # Status line: mode plus the device (Interactive) or profile (Build)
                $modeWord     = if ($script:IsBuildMode) { 'build' } else { 'interactive' }
                $statusTarget = if ($script:IsBuildMode) { [System.IO.Path]::GetFileName($Build) } else { $script:HostName }
                $statusLine   = "$modeWord  -  $statusTarget"

                Clear-Host
                $refresh = $false
            }

            # Resize: clear the screen, since the in-place redraw assumes a fixed size
            if ([Console]::WindowWidth -ne $lastWidth -or [Console]::WindowHeight -ne $lastHeight) {
                $lastWidth  = [Console]::WindowWidth
                $lastHeight = [Console]::WindowHeight
                Clear-Host
            }

            # Render: redraw the view in place over the previous frame
            [Console]::SetCursorPosition(0, 0)

            # Header: location line, title with count, underline, description
            Write-Host "  $(FitBreadcrumb $location)" -ForegroundColor DarkGray
            Write-Host ''
            Write-Host "  $titleName  " -NoNewline -ForegroundColor Cyan
            Write-Host $titleCount -ForegroundColor DarkGray
            Write-Host "  $('-' * $title.Length)" -ForegroundColor DarkCyan
            Write-Host "  $description" -ForegroundColor Gray
            Write-Host ''

            # Items: the selectable rows, with the current row highlighted
            for ($i = 0; $i -lt $items.Count; $i++) {
                WriteMenuItem -Name $items[$i].Name -Trailing $items[$i].Trailing -Selected:($i -eq $selectedIndex)
            }

            # Footer: action hints, then the status line
            Write-Host ''
            Write-Host "  $hints" -ForegroundColor DarkYellow
            Write-Host ''
            Write-Host "  $statusLine" -ForegroundColor DarkGray

            # Input: read one key and update navigation state
            $key = [Console]::ReadKey($true).Key

            switch ($key) {
                'UpArrow'   { $selectedIndex = ($selectedIndex - 1 + $items.Count) % $items.Count }
                'DownArrow' { $selectedIndex = ($selectedIndex + 1) % $items.Count }
                'Escape'    { if ($IsChild) { $exitReason = 'Back' } }
                'Q'         { $exitReason = 'Quit' }
                'Enter'     {
                    $selected    = $children[$selectedIndex]
                    $currentName = if ($isRoot) { $Context.Meta.Name } else { $Context.Name }
                    $childCrumb  = if ($Breadcrumb) { "$Breadcrumb > $currentName" } else { $currentName }
                    if ($isSettingsLevel) {
                        Show-SettingDetail -Setting $selected -Breadcrumb (FitBreadcrumb $childCrumb)
                        $refresh = $true
                    }
                    else {
                        $result = Invoke-Menu -Context $selected -Breadcrumb $childCrumb -IsChild
                        if ($result -eq 'Quit') { $exitReason = 'Quit' } else { $refresh = $true }
                    }
                }
                'A'         {
                    if ($isSettingsLevel) {
                        Invoke-ApplyAll -Settings $children -SectionName $Context.Name
                        $refresh = $true
                    }
                }
            }
        }

        if ($IsChild) { return $exitReason }
    }
    finally {
        if ($isRoot) { [Console]::CursorVisible = $true }
    }
}

#endregion

#region INTERACTIVE MODE

function Show-SettingDetail {
    <#
    .SYNOPSIS
        Shows details of a single setting and allows the user to apply the
        hardened value or reset to default. In Build Mode, the setting can
        also be excluded from the profile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Setting,
        [Parameter(Mandatory)]
        [string]$Breadcrumb
    )

    $done          = $false
    $statusMessage = ''
    $statusColor   = 'White'

    $isHKCU     = $Setting.Path -like 'HKCU:*'
    $scopeLabel = if ($isHKCU) { '[USER]' } else { '[DEVICE]' }

    function StateColor([string]$State) {
        switch ($State) {
            'HARDENED' { 'Green'    }
            'DEFAULT'  { 'Yellow'   }
            'CUSTOM'   { 'Magenta'  }
            'NOT SET'  { 'DarkGray' }
        }
    }

    while (-not $done) {
        # Render: read current state and display setting detail
        $current = Get-SettingCurrentValue -Path $Setting.Path -ValueName $Setting.ValueName
        $state   = Get-SettingState -Setting $Setting

        $valueLabel   = if ($script:IsBuildMode) { 'Profile Value' } else { 'Current Value' }
        $valueDisplay = if ($current.Exists) {
            "$($current.Value)"
        } elseif ($script:IsBuildMode) {
            if ($current.ExplicitAbsence) { '(absent)' } else { '(not in profile)' }
        } else {
            '(absent)'
        }
        $hardenedDisplay = if ($null -ne $Setting.HardenedValue) { "$($Setting.HardenedValue)" } else { '(absent)' }
        $defaultDisplay  = if ($null -ne $Setting.DefaultValue) { "$($Setting.DefaultValue)" } else { '(absent)' }

        Clear-Host

        # Header: location, title, underline, description
        Write-Host "  $Breadcrumb" -ForegroundColor DarkGray
        Write-Host ''
        Write-Host "  $($Setting.Name)" -ForegroundColor Cyan
        Write-Host "  $('-' * $Setting.Name.Length)" -ForegroundColor DarkCyan
        Write-Host "  $($Setting.Description)" -ForegroundColor Gray
        Write-Host ''

        # Technical block: registry coordinates, plus scope for per-user settings
        Write-Host "    Registry Path : $($Setting.Path)" -ForegroundColor Gray
        Write-Host "    Value Name    : $($Setting.ValueName)" -ForegroundColor Gray
        Write-Host "    Value Type    : $($Setting.ValueType)" -ForegroundColor Gray
        if ($isHKCU) {
            Write-Host "    Scope         : Per-user (applies to current user only)" -ForegroundColor Gray
        }
        Write-Host ''

        # State block: only the State value is colored, by state
        Write-Host "    $valueLabel : $valueDisplay"
        Write-Host "    Hardened Value: $hardenedDisplay"
        Write-Host "    Default Value : $defaultDisplay"
        Write-Host "    State         : " -NoNewline
        Write-Host $state -ForegroundColor (StateColor $state)

        # Advisory block: prose at the margin; only the tier label is colored
        $advisories = @()
        if ($Setting.ContainsKey('Warning')) { $advisories += @{ Label = 'Warning'; Text = $Setting.Warning; Color = 'Red' } }
        if ($Setting.ContainsKey('Caution')) { $advisories += @{ Label = 'Caution'; Text = $Setting.Caution; Color = 'Yellow' } }
        if ($Setting.ContainsKey('Note'))    { $advisories += @{ Label = 'Note';    Text = $Setting.Note;    Color = 'DarkCyan' } }
        if ($advisories.Count -gt 0) {
            Write-Host ''
            foreach ($adv in $advisories) {
                Write-Host "  $($adv.Label):" -NoNewline -ForegroundColor $adv.Color
                Write-Host " $($adv.Text)"
            }
        }

        # Footer: action hints, then the status line
        Write-Host ''
        $hints = if ($script:IsBuildMode) {
            '  [H] Set Hardened  [D] Set Default  [X] Exclude from Profile  [Esc] Back'
        } else {
            '  [H] Apply Hardened  [D] Reset to Default  [Esc] Back'
        }
        Write-Host $hints -ForegroundColor DarkYellow
        Write-Host ''
        $modeWord     = if ($script:IsBuildMode) { 'build' } else { 'interactive' }
        $statusTarget = if ($script:IsBuildMode) { [System.IO.Path]::GetFileName($Build) } else { $script:HostName }
        Write-Host "  $modeWord  -  $statusTarget" -ForegroundColor DarkGray

        # Feedback: last line, below the status line, persisting until the next action
        if ($statusMessage) {
            Write-Host ''
            Write-Host "  $statusMessage" -ForegroundColor $statusColor
        }

        # Input: apply hardened value, reset to default, exclude, or exit
        $key = [Console]::ReadKey($true).Key

        switch ($key) {
            'H' {
                $beforeDisplay = $valueDisplay
                $action        = if ($script:IsBuildMode) { 'Set hardened' } else { 'Apply' }
                $afterDisplay  = if ($null -eq $Setting.HardenedValue) { '(absent)' } else { "$($Setting.HardenedValue)" }

                $entry = @{
                    Name      = $Setting.Name
                    Path      = $Setting.Path
                    ValueName = $Setting.ValueName
                    ValueType = $Setting.ValueType
                    Value     = $Setting.HardenedValue
                }
                $result = @(Invoke-SettingApply -Settings @($entry))[0]

                switch ($result.Outcome) {
                    'Changed' {
                        $script:ChangedCount++
                        Write-LogEntry "HARDENED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | After: $afterDisplay | Verified"
                        $statusMessage = if ($script:IsBuildMode) { 'Hardened value set in profile.' } else { 'Applied and verified.' }
                        $statusColor   = 'Green'
                    }
                    'Unchanged' {
                        # Non-Home always writes, so it never reports this
                        $statusMessage = if ($script:IsBuildMode) { 'Hardened value already in profile.' } else { 'Already at the hardened value.' }
                        $statusColor   = 'Green'
                    }
                    'VerifyFailed' {
                        # A profile write fails outright, so Build never reaches this case
                        $script:FailedCount++
                        Write-LogEntry "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | $action verification failed"
                        $statusMessage = 'Applied but verification failed.'
                        $statusColor   = 'Red'
                    }
                    'Failed' {
                        $script:FailedCount++
                        Write-LogEntry "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | $action failed"
                        $statusMessage = if ($script:IsBuildMode) { 'Failed to set the hardened value.' } else { 'Failed to apply.' }
                        $statusColor   = 'Red'
                    }
                }
            }
            'D' {
                $beforeDisplay = $valueDisplay
                $action        = if ($script:IsBuildMode) { 'Set default' } else { 'Reset' }
                $afterDisplay  = if ($null -eq $Setting.DefaultValue) { '(absent)' } else { "$($Setting.DefaultValue)" }

                $entry = @{
                    Name      = $Setting.Name
                    Path      = $Setting.Path
                    ValueName = $Setting.ValueName
                    ValueType = $Setting.ValueType
                    Value     = $Setting.DefaultValue
                }
                $result = @(Invoke-SettingApply -Settings @($entry))[0]

                switch ($result.Outcome) {
                    'Changed' {
                        $script:ChangedCount++
                        Write-LogEntry "DEFAULT $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | After: $afterDisplay | Verified"
                        $statusMessage = if ($script:IsBuildMode) { 'Default value set in profile.' } else { 'Reset to default.' }
                        $statusColor   = 'Green'
                    }
                    'Unchanged' {
                        # Non-Home always writes, so it never reports this
                        $statusMessage = if ($script:IsBuildMode) { 'Default value already in profile.' } else { 'Already at the default value.' }
                        $statusColor   = 'Green'
                    }
                    'VerifyFailed' {
                        # A profile write fails outright, so Build never reaches this case
                        $script:FailedCount++
                        Write-LogEntry "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | $action verification failed"
                        $statusMessage = 'Reset but verification failed.'
                        $statusColor   = 'Red'
                    }
                    'Failed' {
                        $script:FailedCount++
                        Write-LogEntry "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | $action failed"
                        $statusMessage = if ($script:IsBuildMode) { 'Failed to set the default value.' } else { 'Failed to reset.' }
                        $statusColor   = 'Red'
                    }
                }
            }
            'X' {
                if ($script:IsBuildMode) {
                    $beforeDisplay = $valueDisplay

                    $params = @{
                        Path      = $Setting.Path
                        ValueName = $Setting.ValueName
                    }
                    $result = Invoke-BuildSettingExclude @params

                    switch ($result) {
                        'Changed' {
                            $script:ChangedCount++
                            Write-LogEntry "EXCLUDED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | After: (not in profile) | Verified"
                            $statusMessage = 'Excluded from profile.'
                            $statusColor   = 'Green'
                        }
                        'Unchanged' {
                            $statusMessage = 'Already not in profile.'
                            $statusColor   = 'Green'
                        }
                        'Failed' {
                            $script:FailedCount++
                            Write-LogEntry "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Exclude failed"
                            $statusMessage = 'Failed to exclude from profile.'
                            $statusColor   = 'Red'
                        }
                    }
                }
            }
            'Escape' {
                $done = $true
            }
        }
    }
}

function Invoke-ApplyAll {
    <#
    .SYNOPSIS
        Applies the hardened value to the settings in a section
        after user confirmation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Settings,
        [Parameter(Mandatory)]
        [string]$SectionName
    )

    function StateColor([string]$State) {
        switch ($State) {
            'HARDENED' { 'Green'    }
            'DEFAULT'  { 'Yellow'   }
            'CUSTOM'   { 'Magenta'  }
            'NOT SET'  { 'DarkGray' }
        }
    }

    function AdvisoryMarker([hashtable]$Setting) {
        if ($Setting.ContainsKey('Warning')) { return @{ Glyph = '(!)'; Color = 'Red' } }
        if ($Setting.ContainsKey('Caution')) { return @{ Glyph = '(!)'; Color = 'Yellow' } }
        if ($Setting.ContainsKey('Note'))    { return @{ Glyph = '(i)'; Color = 'DarkCyan' } }
        return @{ Glyph = ''; Color = $null }
    }

    # Collect the settings to apply, with their current state. Non-Home includes
    # settings already hardened, since a registry read is not proof of policy state
    $writesAlways = (-not $script:IsBuildMode) -and (-not $script:IsHomeEdition)
    $toApply      = @()
    $stateOf      = @{}
    foreach ($setting in $Settings) {
        $state = Get-SettingState -Setting $setting
        if ($writesAlways -or $state -ne 'HARDENED') {
            $toApply += $setting
            $stateOf["$($setting.Path)|$($setting.ValueName)"] = $state
        }
    }

    Clear-Host
    Write-Host ''

    # Nothing to act on: the confirmation is skipped when every setting is hardened
    if ($toApply.Count -eq 0) {
        $emptyMessage = if ($script:IsBuildMode) {
            '  All settings in this section are already hardened in the profile.'
        } else {
            '  All settings in this section are already hardened.'
        }
        Write-Host $emptyMessage -ForegroundColor Green
        Write-Host ''
        Write-Host '  Press any key to continue...' -ForegroundColor DarkYellow
        [void][Console]::ReadKey($true)
        return
    }

    # Confirmation: heading, affected settings, advisory aggregate, prompt
    $heading = if ($script:IsBuildMode) {
        "  Set all hardened values in profile for: $SectionName"
    } else {
        "  Apply all hardened values for: $SectionName"
    }
    Write-Host $heading -ForegroundColor Cyan
    Write-Host ''

    $warningCount = 0
    $cautionCount = 0
    foreach ($setting in $toApply) {
        $state = $stateOf["$($setting.Path)|$($setting.ValueName)"]
        $adv   = AdvisoryMarker $setting
        Write-Host "    $($setting.Name)  " -NoNewline
        Write-Host "[$state]" -NoNewline -ForegroundColor (StateColor $state)
        if ($adv.Glyph) {
            Write-Host "  $($adv.Glyph)" -ForegroundColor $adv.Color
        } else {
            Write-Host ''
        }
        if     ($setting.ContainsKey('Warning')) { $warningCount++ }
        elseif ($setting.ContainsKey('Caution')) { $cautionCount++ }
    }

    # Advisory aggregate: one line per tier present, highest severity first
    if ($warningCount -gt 0 -or $cautionCount -gt 0) {
        Write-Host ''
        if ($warningCount -gt 0) {
            $phrase = if ($warningCount -eq 1) { 'setting carries' } else { 'settings carry' }
            Write-Host "  (!) $warningCount $phrase a warning." -ForegroundColor Red
        }
        if ($cautionCount -gt 0) {
            $phrase = if ($cautionCount -eq 1) { 'setting carries' } else { 'settings carry' }
            Write-Host "  (!) $cautionCount $phrase a caution." -ForegroundColor Yellow
        }
    }

    Write-Host ''
    $prompt = if ($script:IsBuildMode) {
        "  Set hardened values in profile for $($toApply.Count) setting(s)? [Y/N] "
    } else {
        "  Apply hardened values to $($toApply.Count) setting(s)? [Y/N] "
    }
    Write-Host $prompt -ForegroundColor DarkYellow -NoNewline
    $confirm = [Console]::ReadKey($true).Key

    if ($confirm -ne 'Y') {
        return
    }

    Write-Host ''
    Write-Host ''

    $hardened = 0
    $failed   = 0
    $action   = if ($script:IsBuildMode) { 'Set hardened' } else { 'Apply' }

    # Apply the section in one batch: one LGPO.exe call and one Group Policy refresh
    $entries = foreach ($setting in $toApply) {
        @{
            Name      = $setting.Name
            Path      = $setting.Path
            ValueName = $setting.ValueName
            ValueType = $setting.ValueType
            Value     = $setting.HardenedValue
        }
    }
    $results = @(Invoke-SettingApply -Settings @($entries))

    foreach ($result in $results) {
        $entry         = $result.Setting
        $scopeLabel    = if ($entry.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }
        $afterDisplay  = if ($null -eq $entry.Value) { '(absent)' } else { "$($entry.Value)" }
        $beforeDisplay = if ($result.Before.Exists) {
            "$($result.Before.Value)"
        } elseif ($script:IsBuildMode) {
            if ($result.Before.ExplicitAbsence) { '(absent)' } else { '(not in profile)' }
        } else {
            '(absent)'
        }

        # Unchanged cannot occur: unhardened settings always change, and non-Home rewrites all
        switch ($result.Outcome) {
            'Changed' {
                $hardened++
                $script:ChangedCount++
                Write-Host "  [OK] $scopeLabel $($entry.Name)" -ForegroundColor Green
                Write-LogEntry "HARDENED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | Before: $beforeDisplay | After: $afterDisplay | Verified"
            }
            'VerifyFailed' {
                $failed++
                $script:FailedCount++
                Write-Host "  [!!] $scopeLabel $($entry.Name) - verification failed" -ForegroundColor Red
                Write-LogEntry "FAILED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | $action verification failed"
            }
            'Failed' {
                $failed++
                $script:FailedCount++
                Write-Host "  [!!] $scopeLabel $($entry.Name) - $($action.ToLower()) failed" -ForegroundColor Red
                Write-LogEntry "FAILED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | $action failed"
            }
        }
    }

    Write-Host ''
    Write-Host "  Results: $hardened hardened, $failed failed" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Press any key to continue...' -ForegroundColor DarkYellow
    [void][Console]::ReadKey($true)
}

function Get-SettingCount {
    <#
    .SYNOPSIS
        Counts the settings under a category or section,
        recursing through nested categories and sections.
    .OUTPUTS
        Returns a hashtable with Selected and Total integer counts.
        In Interactive Mode, Selected is the number of hardened settings.
        In Build Mode, Selected is the number of configured settings,
        both hardened and default.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Node
    )

    if ($Node.Settings) {
        $settings = @($Node.Settings)
        $selected = @($settings | Where-Object {
            $state = Get-SettingState -Setting $_
            if ($script:IsBuildMode) { $state -eq 'HARDENED' -or $state -eq 'DEFAULT' }
            else                     { $state -eq 'HARDENED' }
        }).Count
        return @{ Selected = $selected; Total = $settings.Count }
    }

    $selected = 0
    $total    = 0
    $children = if ($Node.Categories) { $Node.Categories } else { $Node.Sections }
    foreach ($child in $children) {
        $c         = Get-SettingCount -Node $child
        $selected += $c.Selected
        $total     += $c.Total
    }
    return @{ Selected = $selected; Total = $total }
}

#endregion

#region PROFILE MODE

function Invoke-ProfileMode {
    <#
    .SYNOPSIS
        Applies all settings in the profile without prompting.
        A pre-change snapshot is saved automatically.
    .OUTPUTS
        Returns $true if all settings were applied successfully,
        $false if any setting failed to apply or verify.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ProfileData
    )

    # Snapshot the settings about to change, inheriting the profile's Source
    $inheritedSource = if ($ProfileData.ContainsKey('Meta') -and $ProfileData.Meta.ContainsKey('Source')) {
        @($ProfileData.Meta.Source)
    } else {
        @()
    }
    $snapshotPath = Get-SnapshotProfilePath
    Export-SnapshotProfile -Settings $ProfileData.Settings -Source $inheritedSource -OutputPath $snapshotPath
    Write-Host "  Snapshot: $snapshotPath"

    $changed = 0
    $failed  = 0
    $skipped = 0

    Write-Host ''

    # Apply the whole profile as one batch, then report each entry, the result's
    # operation supplying the vocabulary that a write and a removal differ by
    $results = @(Invoke-SettingApply -Settings @($ProfileData.Settings))

    foreach ($result in $results) {
        $entry      = $result.Setting
        $isRemoval  = ($result.Operation -eq 'Remove')
        $scopeLabel = if ($entry.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }
        $token      = if ($isRemoval) { 'REMOVED' } else { 'APPLIED' }
        $action     = if ($isRemoval) { 'Remove' }  else { 'Apply' }
        $descriptor = if ($isRemoval) { 'removed' } else { 'applied' }

        $afterDisplay  = if ($isRemoval) { '(absent)' } else { "$($entry.Value)" }
        $beforeDisplay = if ($result.Before.Exists) { "$($result.Before.Value)" } else { '(absent)' }

        switch ($result.Outcome) {
            'Changed' {
                $changed++
                $script:ChangedCount++
                Write-Host "  [OK] $scopeLabel $($entry.Name) - $descriptor" -ForegroundColor Green
                Write-LogEntry "$token $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | Before: $beforeDisplay | After: $afterDisplay | Verified"
            }
            'Unchanged' {
                # Non-Home always writes, so it never reports this
                $skipped++
            }
            'VerifyFailed' {
                $failed++
                $script:FailedCount++
                Write-Host "  [!!] $scopeLabel $($entry.Name) - verification failed" -ForegroundColor Red
                Write-LogEntry "FAILED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | $action verification failed"
            }
            'Failed' {
                $failed++
                $script:FailedCount++
                Write-Host "  [!!] $scopeLabel $($entry.Name) - $($action.ToLower()) failed" -ForegroundColor Red
                Write-LogEntry "FAILED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | $action failed"
            }
        }
    }

    Write-Host ''
    Write-Host "  Results: $changed changed, $failed failed, $skipped skipped" -ForegroundColor Cyan
    return ($failed -eq 0)
}

#endregion

#region BUILD MODE

function Import-BuildProfile {
    <#
    .SYNOPSIS
        Loads the build profile and records the definitions file in Source.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$DefinitionsMeta
    )

    # Start from the existing profile when present, otherwise empty
    $existingSource   = @()
    $existingSettings = @{}
    if (Test-Path $Build -PathType Leaf) {
        $profileData = Import-ProfileFile -Path $Build
        if ($profileData.ContainsKey('Meta') -and $profileData.Meta.ContainsKey('Source')) {
            $existingSource = @($profileData.Meta.Source)
        }
        foreach ($entry in @($profileData.Settings)) {
            $key = "$($entry.Path)|$($entry.ValueName)"
            $existingSettings[$key] = $entry
        }
    }

    # Merge the current definitions file into Source, de-duplicated by File
    $thisFile  = [System.IO.Path]::GetFileName($DefinitionsPath)
    $thisEntry = @{
        Name     = $DefinitionsMeta.Name
        File     = $thisFile
        Target   = $DefinitionsMeta.Target
        Reviewed = $DefinitionsMeta.Reviewed
    }
    $mergedSource = @($existingSource | Where-Object { $_.File -ne $thisFile }) + $thisEntry

    $script:BuildData = @{
        Meta = @{
            Component = $script:Component
            Mode      = 'Build'
            Source    = $mergedSource
        }
        Settings = $existingSettings
    }
}

function Export-BuildProfile {
    <#
    .SYNOPSIS
        Persists the in-memory build profile data to the build file.
    #>
    [CmdletBinding()]
    param()

    $entries = @($script:BuildData.Settings.Keys | Sort-Object | ForEach-Object { $script:BuildData.Settings[$_] })

    $meta = @{
        Component   = $script:Component
        Mode        = 'Build'
        GeneratedBy = $script:ToolName
        GeneratedOn = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Source      = $script:BuildData.Meta.Source
    }

    Export-ProfileFile -Meta $meta -Entries $entries -OutputPath $Build
}

function Get-BuildSettingCurrentValue {
    <#
    .SYNOPSIS
        Reads the current value of a setting from the build profile.
    .OUTPUTS
        Returns a hashtable with Exists (bool), Value, and
        ExplicitAbsence (bool) properties. ExplicitAbsence is true
        when a $null entry is present, distinguishing it from a
        setting not in the profile at all.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName
    )

    # Three states: a value, a $null entry meaning absent, or no entry at all
    $key = "$Path|$ValueName"
    if ($script:BuildData.Settings.ContainsKey($key)) {
        if ($null -ne $script:BuildData.Settings[$key].Value) {
            return @{ Exists = $true; Value = $script:BuildData.Settings[$key].Value; ExplicitAbsence = $false }
        }
        return @{ Exists = $false; Value = $null; ExplicitAbsence = $true }
    }
    return @{ Exists = $false; Value = $null; ExplicitAbsence = $false }
}

function Invoke-BuildApply {
    <#
    .SYNOPSIS
        Records a setting's target value in the build profile. A $null
        target is stored as an entry instructing Profile Mode to remove
        the value, not as the absence of an entry.
    .OUTPUTS
        Returns 'Changed', 'Unchanged', or 'Failed'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Setting
    )

    # Pre-check: return early if an entry already records this target
    $key = "$($Setting.Path)|$($Setting.ValueName)"
    if ($script:BuildData.Settings.ContainsKey($key) -and
        $script:BuildData.Settings[$key].Value -eq $Setting.Value) {
        return 'Unchanged'
    }

    # Write: update in-memory store and persist to file; roll back on failure
    $previous = if ($script:BuildData.Settings.ContainsKey($key)) { $script:BuildData.Settings[$key] } else { $null }
    $script:BuildData.Settings[$key] = @{
        Name      = $Setting.Name
        Path      = $Setting.Path
        ValueName = $Setting.ValueName
        ValueType = $Setting.ValueType
        Value     = $Setting.Value
    }
    try {
        Export-BuildProfile
    }
    catch {
        if ($null -eq $previous) { $script:BuildData.Settings.Remove($key) }
        else                     { $script:BuildData.Settings[$key] = $previous }
        Write-LogError $_
        return 'Failed'
    }

    return 'Changed'
}

function Invoke-BuildSettingExclude {
    <#
    .SYNOPSIS
        Removes a setting entry from the build profile entirely.
    .OUTPUTS
        Returns 'Changed', 'Unchanged', or 'Failed'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName
    )

    # Pre-check: return early if no entry exists
    $key = "$Path|$ValueName"
    if (-not $script:BuildData.Settings.ContainsKey($key)) {
        return 'Unchanged'
    }

    # Remove: delete from in-memory store and persist to file; roll back on failure
    $previous = $script:BuildData.Settings[$key]
    $script:BuildData.Settings.Remove($key)
    try {
        Export-BuildProfile
    }
    catch {
        $script:BuildData.Settings[$key] = $previous
        Write-LogError $_
        return 'Failed'
    }

    return 'Changed'
}

#endregion

#region SNAPSHOT MODE

function Get-SnapshotProfilePath {
    <#
    .SYNOPSIS
        Generates a timestamped snapshot file path in the given directory,
        defaulting to the current working directory.
    .OUTPUTS
        Returns the generated file path as a string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Directory = (Get-Location)
    )
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    return Join-Path $Directory "${script:Component}-Snapshot_${script:HostName}_${timestamp}.psd1"
}

function Export-SnapshotProfile {
    <#
    .SYNOPSIS
        Captures the current state of the provided settings as a profile file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'FromDefinitions')]
        [hashtable]$Definitions,
        [Parameter(Mandatory, ParameterSetName = 'FromSettings')]
        [array]$Settings,
        [Parameter(ParameterSetName = 'FromSettings')]
        [AllowEmptyCollection()]
        [array]$Source = @(),
        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    function CollectSettings([hashtable]$Node) {
        if ($Node.Settings) { return @($Node.Settings) }
        $out      = @()
        $children = if ($Node.Categories) { $Node.Categories } else { $Node.Sections }
        foreach ($child in $children) { $out += CollectSettings $child }
        return $out
    }

    # Resolve the settings to capture and the Source describing their origin
    if ($PSCmdlet.ParameterSetName -eq 'FromDefinitions') {
        $settingSource = @()
        foreach ($category in $Definitions.Categories) {
            $settingSource += CollectSettings $category
        }
        $metaSource = @(
            @{
                Name     = $Definitions.Meta.Name
                File     = [System.IO.Path]::GetFileName($DefinitionsPath)
                Target   = $Definitions.Meta.Target
                Reviewed = $Definitions.Meta.Reviewed
            }
        )
    }
    else {
        $settingSource = $Settings
        $metaSource    = $Source
    }

    $entries = @()

    # Collect: $null captures an absent value for removal when applied
    foreach ($setting in $settingSource) {
        $current = Get-SettingCurrentValue -Path $setting.Path -ValueName $setting.ValueName

        # Omit on a persistent error: a false absence would remove it on apply
        if ($current.Error) {
            Write-LogEntry "Snapshot: read failed for $($setting.Name), setting omitted: $($current.Error)"
            continue
        }

        $entries += @{
            Name      = $setting.Name
            Path      = $setting.Path
            ValueName = $setting.ValueName
            ValueType = $setting.ValueType
            Value     = $current.Value
        }
    }

    $meta = @{
        Component    = $script:Component
        Mode         = 'Snapshot'
        GeneratedBy  = $script:ToolName
        GeneratedOn  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        ComputerName = $script:HostName
        Source       = $metaSource
    }

    Export-ProfileFile -Meta $meta -Entries $entries -OutputPath $OutputPath
    Write-LogEntry "Snapshot saved: $OutputPath"
}

#endregion

#region MAIN ENTRY POINT

switch ($PSCmdlet.ParameterSetName) {
    'Interactive' {
        Write-LogSessionStart -Mode 'Interactive' -DefinitionsPath $DefinitionsPath
        Test-Prerequisite -RequireElevation $true

        $definitions = Import-DefinitionsFile -Path $DefinitionsPath

        Initialize-EditionContext

        $snapshotPath = Get-SnapshotProfilePath
        Export-SnapshotProfile -Definitions $definitions -OutputPath $snapshotPath

        Invoke-Menu -Context $definitions
        Write-LogSessionEnd
        exit 0
    }
    'Profile' {
        Write-LogSessionStart -Mode 'Profile' -ProfilePath $ProfilePath
        Test-Prerequisite -RequireElevation $true

        $profileData = Import-ProfileFile -Path $ProfilePath

        if (-not $profileData.Settings) {
            Write-FatalError 'Profile file contains no settings.'
        }

        Initialize-EditionContext

        Write-Host ''
        Write-Host "  Profile: $ProfilePath"

        $success = Invoke-ProfileMode -ProfileData $profileData
        Write-LogSessionEnd
        if (-not $success) { exit 1 }
        exit 0
    }
    'Build' {
        Write-LogSessionStart -Mode 'Build' -DefinitionsPath $DefinitionsPath -ProfilePath $Build
        Test-Prerequisite -RequireElevation $false

        $definitions = Import-DefinitionsFile -Path $DefinitionsPath

        $script:IsBuildMode = $true
        Import-BuildProfile -DefinitionsMeta $definitions.Meta
        Invoke-Menu -Context $definitions
        Write-LogSessionEnd
        exit 0
    }
    'Snapshot' {
        Write-LogSessionStart -Mode 'Snapshot' -DefinitionsPath $DefinitionsPath
        Test-Prerequisite -RequireElevation $true

        $definitions = Import-DefinitionsFile -Path $DefinitionsPath

        $outputPath = if (Test-Path $Snapshot -PathType Container) {
            Get-SnapshotProfilePath -Directory $Snapshot
        } else {
            $Snapshot
        }
        Export-SnapshotProfile -Definitions $definitions -OutputPath $outputPath
        Write-Host ''
        Write-Host "  Snapshot saved to: $outputPath" -ForegroundColor Green
        Write-LogSessionEnd
        exit 0
    }
}

#endregion
