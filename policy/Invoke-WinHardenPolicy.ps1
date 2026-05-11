<#
.SYNOPSIS
    Applies registry and Local Group Policy hardening settings.

.DESCRIPTION
    A data-driven hardening script for standalone Windows devices.
    Home editions write settings directly to the registry.
    Other editions apply settings through Local Group Policy using LGPO.exe.

    Supports four execution modes:

    Interactive Mode
      Presents a menu of settings from a definitions file, showing the current
      registry state of each setting against its hardened and default values.
      Settings can be applied or restored individually, or all at once within
      a section. A snapshot is saved automatically on startup. Requires
      administrator privileges.

    Profile Mode
      Reads a profile file and applies all settings without prompting.
      A snapshot is saved automatically before applying any changes.
      Requires administrator privileges.

    Build Mode
      Presents the same menu as Interactive Mode but saves selections to a
      profile file instead of applying them to the device. Does not require
      administrator privileges. Can be run on Windows or Linux to prepare
      a profile before applying it to a Windows device.

    Snapshot Mode
      Reads the current registry state of every setting in a definitions
      file and saves it as a profile. Useful for capturing a device state
      before replication or reimaging. Requires administrator privileges.

.PARAMETER DefinitionsPath
    Path to a PSD1 definitions file. Required for Interactive Mode,
    Build Mode, and Snapshot Mode.

.PARAMETER ProfilePath
    Path to a PSD1 profile file to apply. Triggers Profile Mode: all settings
    in the profile are applied to the registry without prompting.

.PARAMETER Build
    Path to the profile file to build. Triggers Build Mode: presents the same
    settings menu as Interactive Mode, saving selections to the profile file
    instead of the device. An existing file loads as the starting state.
    A new file is created on the first save. No elevation required.

.PARAMETER Snapshot
    File or directory path for the snapshot profile. Triggers Snapshot Mode:
    reads the current registry state for every setting in the definitions file
    and saves a profile to the specified path. If a directory is given, a
    generated filename is used. Requires administrator privileges.

.PARAMETER LogPath
    File or directory path for the log file. If a directory is given,
    a generated filename is used. Defaults to the current working directory
    with a generated filename if not specified. Sessions are appended to
    the log file rather than overwriting it.

.PARAMETER LGPOPath
    Explicit path to LGPO.exe. If not specified, the script searches the
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
    Build Mode: opens the profile builder for my-profile.psd1.
    Does not require elevation and can be run on Windows or Linux.

.EXAMPLE
    .\policy\Invoke-WinHardenPolicy.ps1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1 -Snapshot .\my-snapshot.psd1
    Snapshot Mode: captures current registry state to the specified file.
    Requires administrator privileges.
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

# Resolved log file path: generated from -LogPath or defaulted if omitted.
$script:LogPath = if (-not $LogPath) {
    Join-Path (Get-Location) "Policy-Log_${env:COMPUTERNAME}.log"
} elseif (Test-Path $LogPath -PathType Container) {
    Join-Path $LogPath "Policy-Log_${env:COMPUTERNAME}.log"
} else {
    $LogPath
}

# Session counters for the log summary
$script:AppliedCount = 0
$script:FailedCount  = 0

# Windows edition context: populated by Initialize-EditionContext before write operations.
$script:IsHomeEdition = $false
$script:LGPOExePath   = $null

# Build Mode profile data: profile file contents held in memory for the session.
$script:IsBuildMode = $false
$script:BuildData   = @{}

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
    $entry = "[$timestamp] $Message"
    $entry | Out-File -FilePath $script:LogPath -Append -Encoding ASCII
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
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        "$($os.Caption) $($os.Version)"
    }
    catch {
        'Unknown OS'
    }

    Write-Log '============================================================'
    Write-Log "Session started - $env:COMPUTERNAME - $osInfo - $Mode Mode"
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
    Write-Log "Session ended - $($script:AppliedCount) applied, $($script:FailedCount) failed"
    Write-Log '============================================================'
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

    # Elevation
    if ($RequireElevation) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$identity
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-FatalError 'This script must be run as Administrator.'
        }
    }
}

function Import-DefinitionsFile {
    <#
    .SYNOPSIS
        Loads and validates a definitions file, stopping with a fatal error
        if the file is missing, unparseable, or structurally invalid.
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
            Write-FatalError "Definitions file has a category at '$Location' missing key 'Name'."
        }
        $childLocation = "$Location > $($Category.Name)"
        if ($Category.ContainsKey('Categories')) {
            foreach ($child in @($Category.Categories)) { ValidateCategory $child $childLocation }
        }
        elseif ($Category.ContainsKey('Sections')) {
            foreach ($section in @($Category.Sections)) { ValidateSection $section $childLocation }
        }
        else {
            Write-FatalError "Category '$($Category.Name)' at '$Location' has neither 'Categories' nor 'Sections'."
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
    }

    if (-not $definitions.ContainsKey('Categories') -or -not $definitions.Categories) {
        $params = @{
            Message = "Definitions file is missing a top-level 'Categories' array."
            Detail  = 'Verify the file is a valid definitions file for this script.'
        }
        Write-FatalError @params
    }

    foreach ($category in @($definitions.Categories)) {
        ValidateCategory $category 'root'
    }

    return $definitions
}

function Import-ProfileFile {
    <#
    .SYNOPSIS
        Loads and validates a profile file, stopping with a fatal error
        if the file is missing, unparseable, or structurally invalid.
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

    if (-not $profileData.ContainsKey('Settings')) {
        $params = @{
            Message = "Profile file is missing the required 'Settings' key."
            Detail  = 'Verify the file was generated by this script or follows the required format.'
        }
        Write-FatalError @params
    }

    $requiredKeys = 'Path', 'ValueName', 'ValueType', 'Value', 'Exists'
    $index = 0
    foreach ($entry in @($profileData.Settings)) {
        $index++
        foreach ($key in $requiredKeys) {
            if (-not $entry.ContainsKey($key)) {
                $params = @{
                    Message = "Profile entry $index is missing required key '$key'."
                    Detail  = 'Verify the file was generated by this script or follows the required format.'
                }
                Write-FatalError @params
            }
        }
    }

    return $profileData
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

#region POLICY

function Get-SettingCurrentValue {
    <#
    .SYNOPSIS
        Reads the current value of a setting from the registry or the build profile.
    .OUTPUTS
        Returns a hashtable with Exists (bool) and Value properties.
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
    catch {
        return @{ Exists = $false; Value = $null }
    }
}

function Test-SettingState {
    <#
    .SYNOPSIS
        Compares the current value against the hardened value.
    .OUTPUTS
        Returns a string: 'HARDENED', 'DEFAULT', 'CUSTOM', or 'NOT SET'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Setting
    )

    $current = Get-SettingCurrentValue -Path $Setting.Path -ValueName $Setting.ValueName

    if (-not $current.Exists) {
        return 'NOT SET'
    }

    if ($current.Value -eq $Setting.HardenedValue) {
        return 'HARDENED'
    }

    if ($null -ne $Setting.DefaultValue -and $current.Value -eq $Setting.DefaultValue) {
        return 'DEFAULT'
    }

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
        Write-Log "Set-ItemProperty: $_"
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
        if ($null -ne (Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $Path -Name $ValueName -ErrorAction Stop
        }
    }
    catch {
        if ($null -eq (Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue)) {
            return 'Removed'
        }
        Write-Log "Remove-ItemProperty: $_"
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
            Write-Log "Set-ItemProperty: $_"
            return 'WriteFailed'
        }
    }
    else {
        $lgpoResult = Invoke-LGPOWrite -Path $Path -ValueName $ValueName -ValueType $ValueType -Value $Value
        if ($lgpoResult -eq 'WriteFailed') { return 'WriteFailed' }
        if ($alreadyPresent) { return 'AlreadyPresent' }
    }

    # Verify: confirm the write took effect
    $verify = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
    if (-not ($verify.Exists -and $verify.Value -eq $Value)) {
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
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName
    )

    if ($script:IsBuildMode) {
        $params = @{
            Path      = $Path
            ValueName = $ValueName
        }
        return Invoke-BuildSettingRemove @params
    }

    # Pre-check: capture current state to determine return value
    $current = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
    $alreadyAbsent = -not $current.Exists

    # Remove: dispatch to direct registry remove (Home) or LGPO (non-Home)
    if ($script:IsHomeEdition) {
        if ($alreadyAbsent) { return 'AlreadyAbsent' }
        try {
            Remove-ItemProperty -Path $Path -Name $ValueName -ErrorAction Stop
        }
        catch {
            Write-Log "Remove-ItemProperty: $_"
            return 'RemoveFailed'
        }
    }
    else {
        $lgpoResult = Invoke-LGPORemove -Path $Path -ValueName $ValueName
        if ($lgpoResult -eq 'RemoveFailed') { return 'RemoveFailed' }
        if ($alreadyAbsent) { return 'AlreadyAbsent' }
    }

    # Verify: confirm the removal took effect
    $verify = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
    if ($verify.Exists) {
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

    $selectedIndex   = 0
    $refresh         = $true
    $exitReason      = $null

    $children        = @()
    $isSettingsLevel = $false
    $items           = @()
    $icons           = @()
    $title           = ''
    $footer          = ''

    function Pad([string]$Text) {
        $w = [Console]::WindowWidth
        if ($Text.Length -ge $w) { return $Text.Substring(0, $w - 1) }
        return $Text + (' ' * ($w - $Text.Length))
    }

    if (-not $IsChild) { [Console]::CursorVisible = $false }
    try {
        while (-not $exitReason) {
            # Refresh: recompute display data for the current context
            if ($refresh) {
                $children = @(
                    if     ($Context.Categories) { $Context.Categories }
                    elseif ($Context.Sections)   { $Context.Sections }
                    else                         { $Context.Settings }
                )

                $isSettingsLevel = $Context.ContainsKey('Settings')

                $items = @()
                $icons = @()

                if ($isSettingsLevel) {
                    $hardenedCount = 0
                    foreach ($setting in $children) {
                        $state  = Test-SettingState -Setting $setting
                        $items += $setting.Name
                        if ($state -eq 'HARDENED') { $hardenedCount++ }
                        $icon  = "[$state]"
                        if ($setting.Path -like 'HKCU:*') { $icon += ' [USER]' }
                        $icons += $icon
                    }
                    $title  = "$($Context.Name) ($hardenedCount of $($children.Count) hardened)"
                    $footer = '[Enter] View Detail  [A] Apply All  [Esc] Back  [Q] Quit'
                }
                else {
                    foreach ($child in $children) {
                        $items  += $child.Name
                        $counts  = Get-SectionCounts -Node $child
                        $icons  += if ($counts.Total -gt 0) {
                            "($($counts.Hardened)/$($counts.Total))"
                        }
                        else { '' }
                    }
                    $title  = if ($IsChild) { $Context.Name }
                              else          { 'Windows Hardening - Select a Category' }
                    $footer = if ($IsChild) { '[Enter] Select  [Esc] Back  [Q] Quit' }
                              else          { '[Enter] Select  [Q] Quit' }
                }

                Clear-Host
                $refresh = $false
            }

            # Render: overwrite the current view in place
            [Console]::SetCursorPosition(0, 0)

            Write-Host (Pad "  $Breadcrumb") -ForegroundColor DarkGray

            Write-Host (Pad '')
            Write-Host (Pad "  $title") -ForegroundColor Cyan
            Write-Host (Pad ('  ' + ('-' * $title.Length))) -ForegroundColor DarkCyan
            Write-Host (Pad '')

            for ($i = 0; $i -lt $items.Count; $i++) {
                $indicator = if ($i -eq $selectedIndex) { '>' } else { ' ' }
                $status    = if ($icons[$i]) { "  $($icons[$i])" } else { '' }
                $line      = "  $indicator $($items[$i])$status"
                if ($i -eq $selectedIndex) {
                    Write-Host (Pad $line) -ForegroundColor Black -BackgroundColor White
                }
                else {
                    Write-Host (Pad $line)
                }
            }

            Write-Host (Pad '')
            Write-Host (Pad "  $footer") -ForegroundColor DarkYellow

            # Input: read one key and update navigation state
            $key = [Console]::ReadKey($true).Key

            switch ($key) {
                'UpArrow'   { $selectedIndex = ($selectedIndex - 1 + $items.Count) % $items.Count }
                'DownArrow' { $selectedIndex = ($selectedIndex + 1) % $items.Count }
                'Escape'    { if ($IsChild) { $exitReason = 'Back' } }
                'Q'         { $exitReason = 'Quit' }
                'Enter'     {
                    $selected = $children[$selectedIndex]
                    if ($isSettingsLevel) {
                        Show-SettingDetail -Setting $selected -Breadcrumb $Breadcrumb
                        $refresh = $true
                    }
                    else {
                        $childBreadcrumb = if ($Breadcrumb) { "$Breadcrumb > $($selected.Name)" }
                                           else             { $selected.Name }
                        $result = Invoke-Menu -Context $selected -Breadcrumb $childBreadcrumb -IsChild
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
        if (-not $IsChild) { [Console]::CursorVisible = $true }
    }
}

#endregion

#region INTERACTIVE MODE

function Show-SettingDetail {
    <#
    .SYNOPSIS
        Shows details of a single setting and allows the user
        to apply the hardened value or restore the default.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Setting,
        [string]$Breadcrumb = ''
    )

    $done          = $false
    $statusMessage = ''
    $statusColor   = 'White'

    while (-not $done) {
        # Render: read current state and display setting detail
        $current = Get-SettingCurrentValue -Path $Setting.Path -ValueName $Setting.ValueName
        $state   = Test-SettingState -Setting $Setting

        Clear-Host
        Write-Host "  $Breadcrumb" -ForegroundColor DarkGray
        Write-Host ''
        Write-Host "  $($Setting.Name)" -ForegroundColor Cyan
        Write-Host "  $('-' * $Setting.Name.Length)" -ForegroundColor DarkCyan
        Write-Host ''
        Write-Host "  $($Setting.Description)" -ForegroundColor White
        Write-Host ''
        Write-Host "  Registry Path : $($Setting.Path)" -ForegroundColor Gray
        Write-Host "  Value Name    : $($Setting.ValueName)" -ForegroundColor Gray
        Write-Host "  Value Type    : $($Setting.ValueType)" -ForegroundColor Gray
        Write-Host ''

        $currentDisplay  = if ($current.Exists) { "$($current.Value)" } else { '(not set)' }
        $hardenedDisplay = "$($Setting.HardenedValue)"
        $defaultDisplay  = if ($null -ne $Setting.DefaultValue) { "$($Setting.DefaultValue)" } else { '(absent)' }

        Write-Host "  Current Value : $currentDisplay" -ForegroundColor $(if ($state -eq 'HARDENED') { 'Green' } else { 'Yellow' })
        Write-Host "  Hardened Value: $hardenedDisplay" -ForegroundColor Green
        Write-Host "  Default Value : $defaultDisplay" -ForegroundColor Gray
        Write-Host "  Status        : $state" -ForegroundColor $(
            switch ($state) {
                'HARDENED' { 'Green'   }
                'DEFAULT'  { 'Yellow'  }
                'CUSTOM'   { 'Magenta' }
                'NOT SET'  { 'Yellow'  }
            }
        )

        if ($Setting.Path -like 'HKCU:*') {
            Write-Host ''
            Write-Host '  * Per-user setting: applies to current user only' -ForegroundColor DarkYellow
        }

        # Input: apply hardened value, restore default, or exit
        Write-Host ''
        Write-Host '  [H] Apply Hardened  [D] Restore Default  [Esc] Back' -ForegroundColor DarkYellow

        if ($statusMessage) {
            Write-Host ''
            Write-Host "  $statusMessage" -ForegroundColor $statusColor
        }

        $key = [Console]::ReadKey($true).Key

        switch ($key) {
            'H' {
                $scopeLabel    = if ($Setting.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }
                $beforeDisplay = if ($current.Exists) { "$($current.Value)" } else { '(not set)' }

                $params = @{
                    Path      = $Setting.Path
                    ValueName = $Setting.ValueName
                    ValueType = $Setting.ValueType
                    Value     = $Setting.HardenedValue
                }
                $result = Invoke-SettingWrite @params

                switch ($result) {
                    'Written' {
                        $script:AppliedCount++
                        Write-Log "CHANGED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | After: $($Setting.HardenedValue) | Verified"
                        $statusMessage = 'Applied and verified.'
                        $statusColor   = 'Green'
                    }
                    'AlreadyPresent' {
                        $statusMessage = 'Already at the hardened value.'
                        $statusColor   = 'Green'
                    }
                    'VerifyFailed' {
                        $script:FailedCount++
                        Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Verification failed"
                        $statusMessage = 'Applied but verification failed.'
                        $statusColor   = 'Red'
                    }
                    'WriteFailed' {
                        $script:FailedCount++
                        Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Apply failed"
                        $statusMessage = 'Failed to apply.'
                        $statusColor   = 'Red'
                    }
                }
            }
            'D' {
                $scopeLabel    = if ($Setting.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }
                $beforeDisplay = if ($current.Exists) { "$($current.Value)" } else { '(not set)' }

                if ($null -eq $Setting.DefaultValue) {
                    $params = @{
                        Path      = $Setting.Path
                        ValueName = $Setting.ValueName
                    }
                    $result = Invoke-SettingRemove @params

                    switch ($result) {
                        'Removed' {
                            $script:AppliedCount++
                            Write-Log "RESTORED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | Removed registry value"
                            $statusMessage = 'Restored to default.'
                            $statusColor   = 'Green'
                        }
                        'AlreadyAbsent' {
                            $statusMessage = 'Already not set.'
                            $statusColor   = 'Green'
                        }
                        'VerifyFailed' {
                            $script:FailedCount++
                            Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Remove verification failed"
                            $statusMessage = 'Removed but verification failed.'
                            $statusColor   = 'Red'
                        }
                        'RemoveFailed' {
                            $script:FailedCount++
                            Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Remove failed"
                            $statusMessage = 'Failed to remove.'
                            $statusColor   = 'Red'
                        }
                    }
                }
                else {
                    $params = @{
                        Path      = $Setting.Path
                        ValueName = $Setting.ValueName
                        ValueType = $Setting.ValueType
                        Value     = $Setting.DefaultValue
                    }
                    $result = Invoke-SettingWrite @params

                    switch ($result) {
                        'Written' {
                            $script:AppliedCount++
                            Write-Log "RESTORED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | After: $($Setting.DefaultValue)"
                            $statusMessage = 'Restored to default.'
                            $statusColor   = 'Green'
                        }
                        'AlreadyPresent' {
                            $statusMessage = 'Already at the default value.'
                            $statusColor   = 'Green'
                        }
                        'VerifyFailed' {
                            $script:FailedCount++
                            Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Restore verification failed"
                            $statusMessage = 'Restored but verification failed.'
                            $statusColor   = 'Red'
                        }
                        'WriteFailed' {
                            $script:FailedCount++
                            Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Restore failed"
                            $statusMessage = 'Failed to restore.'
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
        Applies the hardened value to all settings
        in a section after user confirmation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Settings,
        [Parameter(Mandatory)]
        [string]$SectionName
    )

    Clear-Host
    Write-Host ''
    Write-Host "  Apply all hardened values for: $SectionName" -ForegroundColor Cyan
    Write-Host ''

    $toApply = @()
    foreach ($setting in $Settings) {
        $state = Test-SettingState -Setting $setting
        if ($state -ne 'HARDENED') {
            $toApply += $setting
            Write-Host "    $($setting.Name)  [$state -> HARDENED]" -ForegroundColor Yellow
        }
    }

    if ($toApply.Count -eq 0) {
        Write-Host '  All settings in this section are already hardened.' -ForegroundColor Green
        Write-Host ''
        Write-Host '  Press any key to continue...' -ForegroundColor DarkYellow
        [void][Console]::ReadKey($true)
        return
    }

    Write-Host ''
    Write-Host "  Apply hardened values to $($toApply.Count) setting(s)? [Y/N] " -ForegroundColor DarkYellow -NoNewline
    $confirm = [Console]::ReadKey($true).Key

    if ($confirm -ne 'Y') {
        return
    }

    Write-Host ''
    Write-Host ''

    $applied = 0
    $failed  = 0

    foreach ($setting in $toApply) {
        $scopeLabel    = if ($setting.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }
        $before        = Get-SettingCurrentValue -Path $setting.Path -ValueName $setting.ValueName
        $beforeDisplay = if ($before.Exists) { "$($before.Value)" } else { '(not set)' }

        $params = @{
            Path      = $setting.Path
            ValueName = $setting.ValueName
            ValueType = $setting.ValueType
            Value     = $setting.HardenedValue
        }
        $result = Invoke-SettingWrite @params

        switch ($result) {
            'Written' {
                $applied++
                $script:AppliedCount++
                Write-Host "  [OK] $scopeLabel $($setting.Name)" -ForegroundColor Green
                Write-Log "CHANGED $scopeLabel $($setting.Name) | $($setting.Path)\$($setting.ValueName) | Before: $beforeDisplay | After: $($setting.HardenedValue) | Verified"
            }
            'VerifyFailed' {
                $failed++
                $script:FailedCount++
                Write-Host "  [!!] $scopeLabel $($setting.Name) - verification failed" -ForegroundColor Red
                Write-Log "FAILED $scopeLabel $($setting.Name) | $($setting.Path)\$($setting.ValueName) | Verification failed"
            }
            'WriteFailed' {
                $failed++
                $script:FailedCount++
                Write-Host "  [!!] $scopeLabel $($setting.Name) - apply failed" -ForegroundColor Red
                Write-Log "FAILED $scopeLabel $($setting.Name) | $($setting.Path)\$($setting.ValueName) | Apply failed"
            }
        }
    }

    Write-Host ''
    Write-Host "  Results: $applied applied, $failed failed" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Press any key to continue...' -ForegroundColor DarkYellow
    [void][Console]::ReadKey($true)
}

function Get-SectionCounts {
    <#
    .SYNOPSIS
        Returns the hardened and total setting counts for a given node,
        recursing into categories and sections as needed.
    .OUTPUTS
        Returns a hashtable with Hardened and Total integer counts.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Node
    )

    if ($Node.Settings) {
        $settings = @($Node.Settings)
        return @{
            Hardened = @($settings | Where-Object { (Test-SettingState -Setting $_) -eq 'HARDENED' }).Count
            Total    = $settings.Count
        }
    }

    $hardened = 0
    $total    = 0
    $children = if ($Node.Categories) { $Node.Categories } else { $Node.Sections }
    foreach ($child in $children) {
        $c        = Get-SectionCounts -Node $child
        $hardened += $c.Hardened
        $total    += $c.Total
    }
    return @{ Hardened = $hardened; Total = $total }
}

#endregion

#region PROFILE MODE

function Invoke-ProfileMode {
    <#
    .SYNOPSIS
        Applies all settings in a loaded profile without prompting,
        after generating a pre-change snapshot.
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

    # Generate snapshot of settings about to be changed
    $snapshotPath = Get-SnapshotProfilePath
    Write-Host ''
    Write-Host '  Generating snapshot before applying profile...' -ForegroundColor Cyan
    Export-SnapshotProfile -Settings $ProfileData.Settings -OutputPath $snapshotPath

    $applied = 0
    $failed  = 0
    $skipped = 0

    Write-Host ''
    Write-Host '  Applying profile...' -ForegroundColor Cyan
    Write-Host ''

    foreach ($entry in $ProfileData.Settings) {
        $scopeLabel = if ($entry.Path -like 'HKCU:*') { '[USER]' } else { '[DEVICE]' }

        if (-not $entry.Exists) {
            # Exists = $false: desired state is absent; remove the value if present
            $params = @{
                Path      = $entry.Path
                ValueName = $entry.ValueName
            }
            $result = Invoke-SettingRemove @params

            switch ($result) {
                'Removed' {
                    $applied++
                    $script:AppliedCount++
                    Write-Host "  [OK] $scopeLabel $($entry.ValueName) - removed" -ForegroundColor Green
                    Write-Log "RESTORED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Removed registry value"
                }
                'AlreadyAbsent' {
                    $skipped++
                }
                'VerifyFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel $($entry.ValueName) - verification failed" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Remove verification failed"
                }
                'RemoveFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel $($entry.ValueName) - remove failed" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Remove failed"
                }
            }
        }
        else {
            # Exists = $true: desired state is present; write the value if not already correct
            $before = Get-SettingCurrentValue -Path $entry.Path -ValueName $entry.ValueName
            $beforeDisplay = if ($before.Exists) { "$($before.Value)" } else { '(not set)' }

            $params = @{
                Path      = $entry.Path
                ValueName = $entry.ValueName
                ValueType = $entry.ValueType
                Value     = $entry.Value
            }
            $result = Invoke-SettingWrite @params

            switch ($result) {
                'Written' {
                    $applied++
                    $script:AppliedCount++
                    Write-Host "  [OK] $scopeLabel $($entry.ValueName) - set to $($entry.Value)" -ForegroundColor Green
                    Write-Log "CHANGED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Before: $beforeDisplay | After: $($entry.Value) | Verified"
                }
                'AlreadyPresent' {
                    $skipped++
                }
                'VerifyFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel $($entry.ValueName) - verification failed" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Verification failed"
                }
                'WriteFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel $($entry.ValueName) - apply failed" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Apply failed"
                }
            }
        }
    }

    Write-Host ''
    Write-Host "  Results: $applied applied, $failed failed, $skipped skipped" -ForegroundColor Cyan
    return ($failed -eq 0)
}

#endregion

#region BUILD MODE

function Import-BuildProfile {
    <#
    .SYNOPSIS
        Loads the build profile file into memory for the session.
    #>
    [CmdletBinding()]
    param()

    $script:BuildData = @{}

    if (-not (Test-Path $Build -PathType Leaf)) {
        return
    }

    $profileData = Import-ProfileFile -Path $Build

    foreach ($entry in $profileData.Settings) {
        $key = "$($entry.Path)|$($entry.ValueName)"
        $script:BuildData[$key] = $entry
    }
}

function Export-BuildProfile {
    <#
    .SYNOPSIS
        Serializes the in-memory profile data to the build profile file.
    #>
    [CmdletBinding()]
    param()

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('@{')
    [void]$sb.AppendLine("    GeneratedOn  = '$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')'")
    [void]$sb.AppendLine("    ComputerName = '$env:COMPUTERNAME'")
    [void]$sb.AppendLine('    Settings = @(')

    foreach ($key in ($script:BuildData.Keys | Sort-Object)) {
        $entry = $script:BuildData[$key]
        [void]$sb.AppendLine('        @{')
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

    $sb.ToString() | Out-File -FilePath $Build -Encoding ASCII -Force
}

function Get-BuildSettingCurrentValue {
    <#
    .SYNOPSIS
        Reads the current value of a setting from the build profile.
    .OUTPUTS
        Returns a hashtable with Exists (bool) and Value properties.
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
    if ($script:BuildData.ContainsKey($key) -and $script:BuildData[$key].Exists) {
        return @{ Exists = $true; Value = $script:BuildData[$key].Value }
    }
    return @{ Exists = $false; Value = $null }
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
    if ($script:BuildData.ContainsKey($key) -and
        $script:BuildData[$key].Exists -and
        $script:BuildData[$key].Value -eq $Value) {
        return 'AlreadyPresent'
    }

    # Write: update in-memory store and persist to file
    try {
        $script:BuildData[$key] = @{
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
    if (-not ($script:BuildData.ContainsKey($key) -and
              $script:BuildData[$key].Exists -and
              $script:BuildData[$key].Value -eq $Value)) {
        return 'VerifyFailed'
    }

    return 'Written'
}

function Invoke-BuildSettingRemove {
    <#
    .SYNOPSIS
        Removes a setting from the build profile.
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

    # Pre-check: return early if the entry is already absent
    $key = "$Path|$ValueName"
    if (-not $script:BuildData.ContainsKey($key) -or -not $script:BuildData[$key].Exists) {
        return 'AlreadyAbsent'
    }

    # Remove: delete from in-memory store and persist to file
    try {
        $script:BuildData.Remove($key)
        Export-BuildProfile
    }
    catch {
        return 'RemoveFailed'
    }

    # Verify: confirm the entry is no longer present
    if ($script:BuildData.ContainsKey($key) -and $script:BuildData[$key].Exists) {
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
    return Join-Path (Get-Location) "Policy-Snapshot_${env:COMPUTERNAME}_${timestamp}.psd1"
}

function Export-SnapshotProfile {
    <#
    .SYNOPSIS
        Captures the current state of the provided settings as a PSD1 profile file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'FromDefinitions')]
        [hashtable]$Definitions,
        [Parameter(Mandatory, ParameterSetName = 'FromSettings')]
        [array]$Settings,
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

    if ($PSCmdlet.ParameterSetName -eq 'FromDefinitions') {
        $source = @()
        foreach ($category in $Definitions.Categories) {
            $source += CollectSettings $category
        }
    }
    else {
        $source = $Settings
    }

    $entries = @()

    # Collect: Exists = $false captures absent values for removal when applied
    foreach ($setting in $source) {
        $current = Get-SettingCurrentValue -Path $setting.Path -ValueName $setting.ValueName
        $entries += @{
            Path      = $setting.Path
            ValueName = $setting.ValueName
            ValueType = $setting.ValueType
            Value     = $current.Value
            Exists    = $current.Exists
        }
    }

    # Build PSD1 content manually for clean formatting
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('@{')
    [void]$sb.AppendLine("    GeneratedOn  = '$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')'")
    [void]$sb.AppendLine("    ComputerName = '$env:COMPUTERNAME'")
    [void]$sb.AppendLine('    Settings = @(')

    foreach ($entry in $entries) {
        [void]$sb.AppendLine('        @{')
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
    Write-Host "  Snapshot saved to: $OutputPath" -ForegroundColor Green
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
        Write-Host '  ================================================' -ForegroundColor Cyan
        Write-Host '  Invoke-WinHardenPolicy - Profile Mode' -ForegroundColor Cyan
        Write-Host '  ================================================' -ForegroundColor Cyan
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
        Import-BuildProfile
        Invoke-Menu -Context $definitions
        Write-LogSessionEnd
        exit 0
    }
    'Snapshot' {
        Write-LogSessionStart -Mode 'Snapshot' -DefinitionsPath $DefinitionsPath -ProfilePath $Snapshot
        Test-Prerequisites -RequireElevation $true

        $definitions = Import-DefinitionsFile -Path $DefinitionsPath

        Write-Host ''
        Write-Host '  ================================================' -ForegroundColor Cyan
        Write-Host '  Invoke-WinHardenPolicy - Snapshot Mode' -ForegroundColor Cyan
        Write-Host '  ================================================' -ForegroundColor Cyan

        $outputPath = if (Test-Path $Snapshot -PathType Container) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            Join-Path $Snapshot "Policy-Snapshot_${env:COMPUTERNAME}_${timestamp}.psd1"
        } else {
            $Snapshot
        }
        Write-Host ''
        Export-SnapshotProfile -Definitions $definitions -OutputPath $outputPath
        Write-LogSessionEnd
        exit 0
    }
}

#endregion
