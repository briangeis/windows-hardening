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
    .\policy\Invoke-WinHardenPolicy.ps1 -ProfilePath .\my-profile.psd1
    Profile Mode: applies all settings in the profile without prompting.

.EXAMPLE
    .\policy\Invoke-WinHardenPolicy.ps1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1 -Build .\my-profile.psd1
    Build Mode: saves selections to my-profile.psd1 for later application.

.EXAMPLE
    .\policy\Invoke-WinHardenPolicy.ps1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1 -Snapshot .\my-snapshot.psd1
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

# Component identity and tool name: written into generated files and checked on import.
$script:Component = 'Policy'
$script:ToolName  = 'Invoke-WinHardenPolicy'

# Session counters for the log summary
$script:ChangedCount = 0
$script:FailedCount  = 0

# Windows edition context: populated by Initialize-EditionContext before write operations.
$script:IsHomeEdition = $false
$script:LGPOExePath   = $null

# Verify retry: attempt count and delay between re-reads
$script:VerifyMaxAttempts  = 5
$script:VerifyRetryDelayMs = 150

# Build Mode profile data: profile file contents held in memory for the session.
$script:IsBuildMode = $false
$script:BuildData   = @{ Meta = @{}; Settings = @{} }

# Resolved log file path: generated from -LogPath or defaulted if omitted.
$script:LogPath = if (-not $LogPath) {
    Join-Path (Get-Location) "Policy-Log_${script:HostName}.log"
} elseif (Test-Path $LogPath -PathType Container) {
    Join-Path $LogPath "Policy-Log_${script:HostName}.log"
} else {
    $LogPath
}

#endregion

#region LOGGING

function Write-Log {
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
    $singleLine = [regex]::Replace($Message, '\s*[\r\n]+\s*', ' ').Trim()
    $entry = "[$timestamp] $singleLine"
    $entry | Out-File -FilePath $script:LogPath -Append -Encoding ASCII
}

function Write-LogError {
    <#
    .SYNOPSIS
        Logs a failed registry operation, naming the command that threw.
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
    Write-Log "${source}: $ErrorRecord"
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

    Write-Log "Session started - $script:HostName - $osInfo - $Mode Mode"
    if ($DefinitionsPath) {
        Write-Log "Definitions file: $DefinitionsPath"
    }
    if ($ProfilePath) {
        Write-Log "Profile file: $ProfilePath"
    }
}

function Write-LogSessionEnd {
    <#
    .SYNOPSIS
        Writes a session summary to the log.
    #>
    [CmdletBinding()]
    param()
    Write-Log "Session ended - $($script:ChangedCount) changed, $($script:FailedCount) failed"
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
    Write-Log "ERROR: $Message"
    Write-LogSessionEnd
    Write-Host "  [X] $Message" -ForegroundColor Red
    if ($Detail) { Write-Host "      $Detail" -ForegroundColor Red }
    exit 1
}

#endregion

#region PREREQUISITES

function Test-Prerequisites {
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
            $caption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption
            if ($caption -like '*Home*') { return 'Home' }
            return 'NonHome'
        }
        catch {
            $params = @{
                Message = 'Could not determine the Windows edition.'
                Detail  = 'Ensure WMI is available and the Win32_OperatingSystem class is accessible.'
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
        if (-not $Category.ContainsKey('Name')) {
            $where = if ($Location) { "at '$Location'" } else { 'at the top level' }
            Write-FatalError "Definitions file has a category $where missing key 'Name'."
        }
        $childLocation = if ($Location) { "$Location > $($Category.Name)" } else { $Category.Name }
        if ($Category.ContainsKey('Categories')) {
            foreach ($child in @($Category.Categories)) { ValidateCategory $child $childLocation }
        }
        elseif ($Category.ContainsKey('Sections')) {
            foreach ($section in @($Category.Sections)) { ValidateSection $section $childLocation }
        }
        else {
            $where = if ($Location) { "at '$Location'" } else { 'at the top level' }
            Write-FatalError "Category '$($Category.Name)' $where has neither 'Categories' nor 'Sections'."
        }
    }

    function ValidateSection([hashtable]$Section, [string]$Location) {
        if (-not $Section.ContainsKey('Name')) {
            Write-FatalError "Definitions file has a section at '$Location' missing key 'Name'."
        }
        if (-not $Section.ContainsKey('Settings')) {
            Write-FatalError "Section '$($Section.Name)' at '$Location' is missing key 'Settings'."
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
        $supportedTypes = 'DWord', 'String', 'ExpandString', 'QWord'
        if ($Setting.ValueType -notin $supportedTypes) {
            Write-FatalError "Setting '$($Setting.Name)' at '$Location' has unsupported ValueType '$($Setting.ValueType)'. Supported types: $($supportedTypes -join ', ')."
        }
    }

    if (-not $definitions.ContainsKey('Meta')) {
        $params = @{
            Message = "Definitions file is missing the required 'Meta' block."
            Detail  = 'Verify the file is a valid definitions file for this script.'
        }
        Write-FatalError @params
    }
    foreach ($key in 'Component', 'Name', 'Target') {
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
            Message = "Profile targets the '$($profileData.Meta.Component)' component, not '$script:Component'."
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

    $requiredKeys = 'Name', 'Path', 'ValueName', 'ValueType', 'Value', 'Exists'
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
    [void]$sb.AppendLine("        Component    = '$($Meta.Component)'")
    [void]$sb.AppendLine("        Mode         = '$($Meta.Mode)'")
    [void]$sb.AppendLine("        GeneratedBy  = '$($Meta.GeneratedBy)'")
    [void]$sb.AppendLine("        GeneratedOn  = '$($Meta.GeneratedOn)'")
    if ($Meta.ContainsKey('ComputerName')) {
        [void]$sb.AppendLine("        ComputerName = '$($Meta.ComputerName)'")
    }
    [void]$sb.AppendLine('        Source       = @(')
    foreach ($src in @($Meta.Source)) {
        if ($null -eq $src) { continue }
        [void]$sb.AppendLine('            @{')
        [void]$sb.AppendLine("                Name     = '$($src.Name)'")
        [void]$sb.AppendLine("                File     = '$($src.File)'")
        [void]$sb.AppendLine("                Target   = '$($src.Target)'")
        [void]$sb.AppendLine("                Reviewed = '$($src.Reviewed)'")
        [void]$sb.AppendLine('            }')
    }
    [void]$sb.AppendLine('        )')
    [void]$sb.AppendLine('    }')
    [void]$sb.AppendLine('')

    # Settings: one entry per setting in fixed field order
    [void]$sb.AppendLine('    Settings = @(')
    foreach ($entry in $Entries) {
        [void]$sb.AppendLine('        @{')
        [void]$sb.AppendLine("            Name      = '$($entry.Name)'")
        [void]$sb.AppendLine("            Path      = '$($entry.Path)'")
        [void]$sb.AppendLine("            ValueName = '$($entry.ValueName)'")
        [void]$sb.AppendLine("            ValueType = '$($entry.ValueType)'")
        if ($null -eq $entry.Value) {
            [void]$sb.AppendLine('            Value     = $null')
        }
        elseif ($entry.Value -is [string]) {
            [void]$sb.AppendLine("            Value     = '$($entry.Value)'")
        }
        else {
            [void]$sb.AppendLine("            Value     = $($entry.Value)")
        }
        [void]$sb.AppendLine("            Exists    = `$$($entry.Exists)")
        [void]$sb.AppendLine('        }')
    }

    [void]$sb.AppendLine('    )')
    [void]$sb.AppendLine('}')

    $sb.ToString() | Out-File -FilePath $OutputPath -Encoding ASCII -Force
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
        $item = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction Stop
        return @{ Exists = $true; Value = $item.$ValueName }
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

function Test-SettingState {
    <#
    .SYNOPSIS
        Determines a setting's state by comparing its value, or its absence,
        to the hardened and default values from the definitions file.
    .OUTPUTS
        Returns a string: 'HARDENED', 'DEFAULT', 'CUSTOM', or 'NOT SET'.
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

    # Compare the value-state to each anchor; an absent value matches an anchor
    # whose value is $null (absence)
    if ($current.Exists) {
        if ($current.Value -eq $Setting.HardenedValue) { return 'HARDENED' }
        if ($null -ne $Setting.DefaultValue -and $current.Value -eq $Setting.DefaultValue) { return 'DEFAULT' }
        return 'CUSTOM'
    }

    if ($null -eq $Setting.HardenedValue) { return 'HARDENED' }
    if ($null -eq $Setting.DefaultValue)  { return 'DEFAULT' }
    return 'CUSTOM'
}

function Invoke-LGPOWrite {
    <#
    .SYNOPSIS
        Writes a registry value to the Local Group Policy Object
        via LGPO.exe, then directly to the registry for immediate effect
        on Pro, Enterprise, Education, and LTSC editions.
    .OUTPUTS
        Returns 'Written' or 'WriteFailed'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName,
        [Parameter(Mandatory)]
        [string]$ValueType,
        [Parameter(Mandatory)]
        $Value
    )

    # Determine section and strip hive from path for LGPO text format
    $section  = if ($Path -like 'HKLM:*') { 'Computer' } else { 'User' }
    $lgpoPath = $Path -replace '^HKL[MC]:\\', '' -replace '^HKCU:\\', ''

    # Convert PowerShell value type to LGPO type prefix
    $lgpoType = switch ($ValueType) {
        'DWord'       { 'DWORD' }
        'String'      { 'SZ' }
        'ExpandString'{ 'EXSZ' }
        'MultiString' { 'MULTISZ' }
        'QWord'       { 'QWORD' }
        'Binary'      { 'BINARY' }
        default       { 'DWORD' }
    }

    # Format value: DWORD and QWORD as decimal, all others as literal string
    $lgpoValue = if ($lgpoType -eq 'DWORD') {
        [uint32]$Value
    } elseif ($lgpoType -eq 'QWORD') {
        [uint64]$Value
    } else {
        "$Value"
    }

    $content  = "$section`r`n$lgpoPath`r`n$ValueName`r`n${lgpoType}:$lgpoValue`r`n`r`n"
    $tempFile = [System.IO.Path]::GetTempFileName()

    try {
        # Write to LGPO first: the authoritative record that survives any Group Policy refresh
        [System.IO.File]::WriteAllText($tempFile, $content, [System.Text.Encoding]::ASCII)
        $lgpoOutput = & $script:LGPOExePath /t $tempFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "LGPO.exe: $($lgpoOutput -join ' ')"
            return 'WriteFailed'
        }

        # Write directly to registry for immediate effect
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $ValueName -Value $Value -Type $ValueType -Force
    }
    catch {
        Write-LogError $_
        return 'WriteFailed'
    }
    finally {
        Remove-Item $tempFile -ErrorAction SilentlyContinue
    }

    return 'Written'
}

function Invoke-LGPORemove {
    <#
    .SYNOPSIS
        Removes a registry value from the Local Group Policy Object
        via LGPO.exe, then directly from the registry for immediate effect
        on Pro, Enterprise, Education, and LTSC editions.
    .OUTPUTS
        Returns 'Removed' or 'RemoveFailed'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName
    )

    # Determine section and strip hive from path for LGPO text format
    $section  = if ($Path -like 'HKLM:*') { 'Computer' } else { 'User' }
    $lgpoPath = $Path -replace '^HKL[MC]:\\', '' -replace '^HKCU:\\', ''

    $content  = "$section`r`n$lgpoPath`r`n$ValueName`r`nDELETE`r`n`r`n"
    $tempFile = [System.IO.Path]::GetTempFileName()

    try {
        # Write to LGPO first: the authoritative record that survives any Group Policy refresh
        [System.IO.File]::WriteAllText($tempFile, $content, [System.Text.Encoding]::ASCII)
        $lgpoOutput = & $script:LGPOExePath /t $tempFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "LGPO.exe: $($lgpoOutput -join ' ')"
            return 'RemoveFailed'
        }

        # Remove directly from registry for immediate effect
        if ((Get-SettingCurrentValue -Path $Path -ValueName $ValueName).Exists) {
            Remove-ItemProperty -Path $Path -Name $ValueName -ErrorAction Stop
        }
    }
    catch {
        # A concurrent Group Policy refresh may remove the value first
        $err   = $_
        $check = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
        if (-not $check.Exists -and -not $check.Error) {
            return 'Removed'
        }
        Write-LogError $err
        return 'RemoveFailed'
    }
    finally {
        Remove-Item $tempFile -ErrorAction SilentlyContinue
    }

    return 'Removed'
}

function Invoke-SettingWrite {
    <#
    .SYNOPSIS
        Writes a registry value and verifies the write succeeded.
    .OUTPUTS
        Returns 'Written', 'AlreadyPresent', 'WriteFailed', or 'VerifyFailed'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName,
        [Parameter(Mandatory)]
        [string]$ValueType,
        [Parameter(Mandatory)]
        $Value
    )

    if ($script:IsBuildMode) {
        $params = @{
            Name      = $Name
            Path      = $Path
            ValueName = $ValueName
            ValueType = $ValueType
            Value     = $Value
        }
        return Invoke-BuildSettingWrite @params
    }

    # Pre-check: capture current state to determine return value
    $current = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
    $alreadyPresent = $current.Exists -and $current.Value -eq $Value

    # Write: dispatch to direct registry write (Home) or LGPO (non-Home)
    if ($script:IsHomeEdition) {
        if ($alreadyPresent) { return 'AlreadyPresent' }
        try {
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }
            Set-ItemProperty -Path $Path -Name $ValueName -Value $Value -Type $ValueType -Force
        }
        catch {
            Write-LogError $_
            return 'WriteFailed'
        }
    }
    else {
        $lgpoResult = Invoke-LGPOWrite -Path $Path -ValueName $ValueName -ValueType $ValueType -Value $Value
        if ($lgpoResult -eq 'WriteFailed') { return 'WriteFailed' }
        if ($alreadyPresent) { return 'AlreadyPresent' }
    }

    # Verify: confirm the write took effect, re-reading through the refresh window
    $verify  = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
    $attempt = 1
    while (-not ($verify.Exists -and $verify.Value -eq $Value) -and $attempt -lt $script:VerifyMaxAttempts) {
        Start-Sleep -Milliseconds $script:VerifyRetryDelayMs
        $verify = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
        $attempt++
    }
    if (-not ($verify.Exists -and $verify.Value -eq $Value)) {
        if ($verify.Error) {
            Write-LogError $verify.Error
        } elseif ($verify.Exists) {
            Write-Log "Verify: read $($verify.Value), expected $Value"
        } else {
            Write-Log "Verify: read (absent), expected $Value"
        }
        return 'VerifyFailed'
    }

    return 'Written'
}

function Invoke-SettingRemove {
    <#
    .SYNOPSIS
        Removes a registry value and verifies the removal succeeded.
    .OUTPUTS
        Returns 'Removed', 'AlreadyAbsent', 'RemoveFailed', or 'VerifyFailed'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName,
        [Parameter(Mandatory)]
        [string]$ValueType
    )

    if ($script:IsBuildMode) {
        $params = @{
            Name      = $Name
            Path      = $Path
            ValueName = $ValueName
            ValueType = $ValueType
        }
        return Invoke-BuildSettingRemove @params
    }

    # Pre-check: capture current state to determine return value
    # A read error is not an absence, so it must not short-circuit the removal
    $current = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
    $alreadyAbsent = (-not $current.Exists) -and (-not $current.Error)

    # Remove: dispatch to direct registry remove (Home) or LGPO (non-Home)
    if ($script:IsHomeEdition) {
        if ($alreadyAbsent) { return 'AlreadyAbsent' }
        try {
            Remove-ItemProperty -Path $Path -Name $ValueName -ErrorAction Stop
        }
        catch {
            Write-LogError $_
            return 'RemoveFailed'
        }
    }
    else {
        $lgpoResult = Invoke-LGPORemove -Path $Path -ValueName $ValueName
        if ($lgpoResult -eq 'RemoveFailed') { return 'RemoveFailed' }
        if ($alreadyAbsent) { return 'AlreadyAbsent' }
    }

    # Verify: confirm the removal took effect, re-reading through the refresh window
    $verify  = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
    $attempt = 1
    while (($verify.Error -or $verify.Exists) -and $attempt -lt $script:VerifyMaxAttempts) {
        Start-Sleep -Milliseconds $script:VerifyRetryDelayMs
        $verify = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
        $attempt++
    }
    if ($verify.Error) {
        Write-LogError $verify.Error
    }
    if ($verify.Exists) {
        Write-Log "Verify: read $($verify.Value), expected (absent)"
        return 'VerifyFailed'
    }

    return 'Removed'
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

    # Fit a breadcrumb to one line by dropping its leading segments.
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

    # Render a menu row; truncate an overlong name to keep the tokens visible.
    function Write-MenuItem([string]$Name, [string[]]$Trailing, [switch]$Selected) {
        $w      = [Console]::WindowWidth
        $prefix = if ($Selected) { '  > ' } else { '    ' }

        $pinnedWidth = 0
        for ($k = 0; $k -lt $Trailing.Count; $k += 2) { $pinnedWidth += $Trailing[$k].Length }

        $nameBudget  = $w - $prefix.Length - $pinnedWidth
        $displayName = $Name
        if ($displayName.Length -gt $nameBudget) {
            $displayName = if ($nameBudget -ge 4) { $displayName.Substring(0, $nameBudget - 3) + '...' }
                           else                   { $displayName.Substring(0, [Math]::Max($nameBudget, 0)) }
        }

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

    # At the root, hide the cursor; the finally restores it on any root exit.
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
                        $state    = Test-SettingState -Setting $setting
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
                        $counts = Get-SettingCounts -Node $child
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
                Write-MenuItem -Name $items[$i].Name -Trailing $items[$i].Trailing -Selected:($i -eq $selectedIndex)
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
        Shows details of a single setting and allows the user
        to apply the hardened value or reset to default.
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

    $isHKCU = $Setting.Path -like 'HKCU:*'

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
        $state   = Test-SettingState -Setting $Setting

        $valueLabel   = if ($script:IsBuildMode) { 'Profile Value' } else { 'Current Value' }
        $valueDisplay = if ($current.Exists) {
            "$($current.Value)"
        } elseif ($script:IsBuildMode) {
            if ($current.ExplicitAbsence) { '(absent)' } else { '(not in profile)' }
        } else {
            '(absent)'
        }
        $hardenedDisplay = "$($Setting.HardenedValue)"
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
                $scopeLabel    = if ($Setting.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }
                $beforeDisplay = $valueDisplay
                $action        = if ($script:IsBuildMode) { 'Set hardened' } else { 'Apply' }

                $params = @{
                    Name      = $Setting.Name
                    Path      = $Setting.Path
                    ValueName = $Setting.ValueName
                    ValueType = $Setting.ValueType
                    Value     = $Setting.HardenedValue
                }
                $result = Invoke-SettingWrite @params

                switch ($result) {
                    'Written' {
                        $script:ChangedCount++
                        Write-Log "HARDENED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | After: $($Setting.HardenedValue) | Verified"
                        $statusMessage = if ($script:IsBuildMode) { 'Hardened value set in profile.' } else { 'Applied and verified.' }
                        $statusColor   = 'Green'
                    }
                    'AlreadyPresent' {
                        $statusMessage = if ($script:IsBuildMode) { 'Hardened value already in profile.' } else { 'Already at the hardened value.' }
                        $statusColor   = 'Green'
                    }
                    'VerifyFailed' {
                        $script:FailedCount++
                        Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | $action verification failed"
                        $statusMessage = if ($script:IsBuildMode) { 'Set the hardened value but verification failed.' } else { 'Applied but verification failed.' }
                        $statusColor   = 'Red'
                    }
                    'WriteFailed' {
                        $script:FailedCount++
                        Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | $action failed"
                        $statusMessage = if ($script:IsBuildMode) { 'Failed to set the hardened value.' } else { 'Failed to apply.' }
                        $statusColor   = 'Red'
                    }
                }
            }
            'D' {
                $scopeLabel    = if ($Setting.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }
                $beforeDisplay = $valueDisplay
                $action        = if ($script:IsBuildMode) { 'Set default' } else { 'Reset' }

                if ($null -eq $Setting.DefaultValue) {
                    $params = @{
                        Name      = $Setting.Name
                        Path      = $Setting.Path
                        ValueName = $Setting.ValueName
                        ValueType = $Setting.ValueType
                    }
                    $result       = Invoke-SettingRemove @params
                    $afterDisplay = '(absent)'
                }
                else {
                    $params = @{
                        Name      = $Setting.Name
                        Path      = $Setting.Path
                        ValueName = $Setting.ValueName
                        ValueType = $Setting.ValueType
                        Value     = $Setting.DefaultValue
                    }
                    $result       = Invoke-SettingWrite @params
                    $afterDisplay = "$($Setting.DefaultValue)"
                }

                switch ($result) {
                    { $_ -in 'Written','Removed' } {
                        $script:ChangedCount++
                        Write-Log "DEFAULT $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | After: $afterDisplay | Verified"
                        $statusMessage = if ($script:IsBuildMode) { 'Default value set in profile.' } else { 'Reset to default.' }
                        $statusColor   = 'Green'
                    }
                    { $_ -in 'AlreadyPresent','AlreadyAbsent' } {
                        $statusMessage = if ($script:IsBuildMode) { 'Default value already in profile.' } else { 'Already at the default value.' }
                        $statusColor   = 'Green'
                    }
                    'VerifyFailed' {
                        $script:FailedCount++
                        Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | $action verification failed"
                        $statusMessage = if ($script:IsBuildMode) { 'Set the default value but verification failed.' } else { 'Reset but verification failed.' }
                        $statusColor   = 'Red'
                    }
                    { $_ -in 'WriteFailed','RemoveFailed' } {
                        $script:FailedCount++
                        Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | $action failed"
                        $statusMessage = if ($script:IsBuildMode) { 'Failed to set the default value.' } else { 'Failed to reset.' }
                        $statusColor   = 'Red'
                    }
                }
            }
            'X' {
                if ($script:IsBuildMode) {
                    $scopeLabel    = if ($Setting.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }
                    $beforeDisplay = $valueDisplay

                    $params = @{
                        Path      = $Setting.Path
                        ValueName = $Setting.ValueName
                    }
                    $result = Invoke-BuildSettingExclude @params

                    switch ($result) {
                        'Removed' {
                            $script:ChangedCount++
                            Write-Log "EXCLUDED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | After: (not in profile) | Verified"
                            $statusMessage = 'Excluded from profile.'
                            $statusColor   = 'Green'
                        }
                        'AlreadyAbsent' {
                            $statusMessage = 'Already not in profile.'
                            $statusColor   = 'Green'
                        }
                        'VerifyFailed' {
                            Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Exclude verification failed"
                            $statusMessage = 'Excluded from profile but verification failed.'
                            $statusColor   = 'Red'
                        }
                        'RemoveFailed' {
                            Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Exclude failed"
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
        Applies the hardened value to all unhardened settings
        in a section after user confirmation.
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

    # Collect the settings not already hardened, with their current state
    $toApply = @()
    $stateOf = @{}
    foreach ($setting in $Settings) {
        $state = Test-SettingState -Setting $setting
        if ($state -ne 'HARDENED') {
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

    foreach ($setting in $toApply) {
        $scopeLabel    = if ($setting.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }
        $before        = Get-SettingCurrentValue -Path $setting.Path -ValueName $setting.ValueName
        $beforeDisplay = if ($before.Exists) {
            "$($before.Value)"
        } elseif ($script:IsBuildMode) {
            if ($before.ExplicitAbsence) { '(absent)' } else { '(not in profile)' }
        } else {
            '(absent)'
        }

        $params = @{
            Name      = $setting.Name
            Path      = $setting.Path
            ValueName = $setting.ValueName
            ValueType = $setting.ValueType
            Value     = $setting.HardenedValue
        }
        $result = Invoke-SettingWrite @params

        switch ($result) {
            'Written' {
                $hardened++
                $script:ChangedCount++
                Write-Host "  [OK] $scopeLabel $($setting.Name)" -ForegroundColor Green
                Write-Log "HARDENED $scopeLabel $($setting.Name) | $($setting.Path)\$($setting.ValueName) | Before: $beforeDisplay | After: $($setting.HardenedValue) | Verified"
            }
            'VerifyFailed' {
                $failed++
                $script:FailedCount++
                Write-Host "  [!!] $scopeLabel $($setting.Name) - verification failed" -ForegroundColor Red
                Write-Log "FAILED $scopeLabel $($setting.Name) | $($setting.Path)\$($setting.ValueName) | $action verification failed"
            }
            'WriteFailed' {
                $failed++
                $script:FailedCount++
                Write-Host "  [!!] $scopeLabel $($setting.Name) - $($action.ToLower()) failed" -ForegroundColor Red
                Write-Log "FAILED $scopeLabel $($setting.Name) | $($setting.Path)\$($setting.ValueName) | $action failed"
            }
        }
    }

    Write-Host ''
    Write-Host "  Results: $hardened hardened, $failed failed" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Press any key to continue...' -ForegroundColor DarkYellow
    [void][Console]::ReadKey($true)
}

function Get-SettingCounts {
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
            $state = Test-SettingState -Setting $_
            if ($script:IsBuildMode) { $state -eq 'HARDENED' -or $state -eq 'DEFAULT' }
            else                     { $state -eq 'HARDENED' }
        }).Count
        return @{ Selected = $selected; Total = $settings.Count }
    }

    $selected = 0
    $total    = 0
    $children = if ($Node.Categories) { $Node.Categories } else { $Node.Sections }
    foreach ($child in $children) {
        $c         = Get-SettingCounts -Node $child
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
        $false if any setting failed to apply or validate.
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

    foreach ($entry in $ProfileData.Settings) {
        $scopeLabel = if ($entry.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }

        if (-not $entry.Exists) {
            # Exists = $false: desired state is absent; remove the value if present
            $before = Get-SettingCurrentValue -Path $entry.Path -ValueName $entry.ValueName
            $beforeDisplay = if ($before.Exists) { "$($before.Value)" } else { '(absent)' }

            $params = @{
                Name      = $entry.Name
                Path      = $entry.Path
                ValueName = $entry.ValueName
                ValueType = $entry.ValueType
            }
            $result = Invoke-SettingRemove @params

            switch ($result) {
                'Removed' {
                    $changed++
                    $script:ChangedCount++
                    Write-Host "  [OK] $scopeLabel $($entry.Name) - removed" -ForegroundColor Green
                    Write-Log "REMOVED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | Before: $beforeDisplay | After: (absent) | Verified"
                }
                'AlreadyAbsent' {
                    $skipped++
                }
                'VerifyFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel $($entry.Name) - verification failed" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | Remove verification failed"
                }
                'RemoveFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel $($entry.Name) - remove failed" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | Remove failed"
                }
            }
        }
        else {
            # Exists = $true: desired state is present; write the value if not already correct
            $before = Get-SettingCurrentValue -Path $entry.Path -ValueName $entry.ValueName
            $beforeDisplay = if ($before.Exists) { "$($before.Value)" } else { '(absent)' }

            $params = @{
                Name      = $entry.Name
                Path      = $entry.Path
                ValueName = $entry.ValueName
                ValueType = $entry.ValueType
                Value     = $entry.Value
            }
            $result = Invoke-SettingWrite @params

            switch ($result) {
                'Written' {
                    $changed++
                    $script:ChangedCount++
                    Write-Host "  [OK] $scopeLabel $($entry.Name) - applied" -ForegroundColor Green
                    Write-Log "APPLIED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | Before: $beforeDisplay | After: $($entry.Value) | Verified"
                }
                'AlreadyPresent' {
                    $skipped++
                }
                'VerifyFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel $($entry.Name) - verification failed" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | Apply verification failed"
                }
                'WriteFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel $($entry.Name) - apply failed" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.Name) | $($entry.Path)\$($entry.ValueName) | Apply failed"
                }
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
        foreach ($entry in $profileData.Settings) {
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
        when an Exists = $false entry is present, distinguishing it
        from a setting not in the profile at all.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName
    )

    $key = "$Path|$ValueName"
    if ($script:BuildData.Settings.ContainsKey($key)) {
        if ($script:BuildData.Settings[$key].Exists) {
            return @{ Exists = $true; Value = $script:BuildData.Settings[$key].Value; ExplicitAbsence = $false }
        }
        return @{ Exists = $false; Value = $null; ExplicitAbsence = $true }
    }
    return @{ Exists = $false; Value = $null; ExplicitAbsence = $false }
}

function Invoke-BuildSettingWrite {
    <#
    .SYNOPSIS
        Writes a setting to the build profile.
    .OUTPUTS
        Returns 'Written', 'AlreadyPresent', 'WriteFailed', or 'VerifyFailed'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName,
        [Parameter(Mandatory)]
        [string]$ValueType,
        [Parameter(Mandatory)]
        $Value
    )

    # Pre-check: return early if the value is already correct
    $key = "$Path|$ValueName"
    if ($script:BuildData.Settings.ContainsKey($key) -and
        $script:BuildData.Settings[$key].Exists -and
        $script:BuildData.Settings[$key].Value -eq $Value) {
        return 'AlreadyPresent'
    }

    # Write: update in-memory store and persist to file
    try {
        $script:BuildData.Settings[$key] = @{
            Name      = $Name
            Path      = $Path
            ValueName = $ValueName
            ValueType = $ValueType
            Value     = $Value
            Exists    = $true
        }
        Export-BuildProfile
    }
    catch {
        return 'WriteFailed'
    }

    # Verify: confirm the entry reflects the written value
    if (-not ($script:BuildData.Settings.ContainsKey($key) -and
              $script:BuildData.Settings[$key].Exists -and
              $script:BuildData.Settings[$key].Value -eq $Value)) {
        return 'VerifyFailed'
    }

    return 'Written'
}

function Invoke-BuildSettingRemove {
    <#
    .SYNOPSIS
        Records a removal instruction for a setting in the build profile
        by writing an Exists = $false entry.
    .OUTPUTS
        Returns 'Removed', 'AlreadyAbsent', 'RemoveFailed', or 'VerifyFailed'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName,
        [Parameter(Mandatory)]
        [string]$ValueType
    )

    # Pre-check: return early if a removal entry already exists
    $key = "$Path|$ValueName"
    if ($script:BuildData.Settings.ContainsKey($key) -and -not $script:BuildData.Settings[$key].Exists) {
        return 'AlreadyAbsent'
    }

    # Write: store Exists = $false to instruct Profile Mode to remove this value
    try {
        $script:BuildData.Settings[$key] = @{
            Name      = $Name
            Path      = $Path
            ValueName = $ValueName
            ValueType = $ValueType
            Value     = $null
            Exists    = $false
        }
        Export-BuildProfile
    }
    catch {
        return 'RemoveFailed'
    }

    # Verify: confirm the removal entry is recorded correctly
    if (-not $script:BuildData.Settings.ContainsKey($key) -or $script:BuildData.Settings[$key].Exists) {
        return 'VerifyFailed'
    }

    return 'Removed'
}

function Invoke-BuildSettingExclude {
    <#
    .SYNOPSIS
        Removes a setting entry from the build profile entirely.
    .OUTPUTS
        Returns 'Removed', 'AlreadyAbsent', 'RemoveFailed', or 'VerifyFailed'.
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
        return 'AlreadyAbsent'
    }

    # Remove: delete from in-memory store and persist to file
    try {
        $script:BuildData.Settings.Remove($key)
        Export-BuildProfile
    }
    catch {
        return 'RemoveFailed'
    }

    # Verify: confirm the entry is no longer present
    if ($script:BuildData.Settings.ContainsKey($key)) {
        return 'VerifyFailed'
    }

    return 'Removed'
}

#endregion

#region SNAPSHOT MODE

function Get-SnapshotProfilePath {
    <#
    .SYNOPSIS
        Generates a timestamped snapshot file path
        in the current working directory.
    .OUTPUTS
        Returns the generated file path as a string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    return Join-Path (Get-Location) "Policy-Snapshot_${script:HostName}_${timestamp}.psd1"
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

    # Collect: Exists = $false captures absent values for removal when applied
    foreach ($setting in $settingSource) {
        $current = Get-SettingCurrentValue -Path $setting.Path -ValueName $setting.ValueName
        if ($current.Error) {
            Write-Log "Snapshot: read failed for $($setting.Name): $($current.Error)"
        }
        $entries += @{
            Name      = $setting.Name
            Path      = $setting.Path
            ValueName = $setting.ValueName
            ValueType = $setting.ValueType
            Value     = $current.Value
            Exists    = $current.Exists
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
    Write-Log "Snapshot saved: $OutputPath"
}

#endregion

#region MAIN ENTRY POINT

switch ($PSCmdlet.ParameterSetName) {
    'Interactive' {
        Write-LogSessionStart -Mode 'Interactive' -DefinitionsPath $DefinitionsPath
        Test-Prerequisites -RequireElevation $true

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
        Test-Prerequisites -RequireElevation $true

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
        Test-Prerequisites -RequireElevation $false

        $definitions = Import-DefinitionsFile -Path $DefinitionsPath

        $script:IsBuildMode = $true
        Import-BuildProfile -DefinitionsMeta $definitions.Meta
        Invoke-Menu -Context $definitions
        Write-LogSessionEnd
        exit 0
    }
    'Snapshot' {
        Write-LogSessionStart -Mode 'Snapshot' -DefinitionsPath $DefinitionsPath
        Test-Prerequisites -RequireElevation $true

        $definitions = Import-DefinitionsFile -Path $DefinitionsPath

        $outputPath = if (Test-Path $Snapshot -PathType Container) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            Join-Path $Snapshot "Policy-Snapshot_${script:HostName}_${timestamp}.psd1"
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
