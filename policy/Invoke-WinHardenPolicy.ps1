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

    Silent Mode
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
    Path to a PSD1 profile file to apply. Triggers Silent Mode: all settings
    in the profile are applied to the registry without prompting.

.PARAMETER Build
    Path to the profile file to build. Triggers Build Mode: presents the same
    settings menu as Interactive Mode, saving selections to the profile file
    instead of the device. An existing file loads as the starting state.
    A new file is created on the first save. No elevation required.

.PARAMETER Snapshot
    Triggers Snapshot Mode: reads the current registry state for every setting
    in the definitions file and saves a profile capturing it without prompting.
    Requires administrator privileges.

.PARAMETER SnapshotPath
    File or directory path for the snapshot profile. If a directory is given,
    a generated filename is used. Defaults to the current working directory
    with a generated filename if not specified. Only valid with -Snapshot.

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
    .\policy\Invoke-WinHardenPolicy.ps1 -ProfilePath .\Policy-Snapshot_WIN11-HOME_20260426_042606.psd1
    Silent Mode: applies all settings in the profile without prompting.

.EXAMPLE
    .\policy\Invoke-WinHardenPolicy.ps1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1 -Build .\my-profile.psd1
    Build Mode: opens the profile builder for my-profile.psd1.
    Does not require elevation and can be run on Windows or Linux.

.EXAMPLE
    .\policy\Invoke-WinHardenPolicy.ps1 -DefinitionsPath .\definitions\Policy-MicrosoftPrivacyConnections.psd1 -Snapshot
    Snapshot Mode: captures current registry state to the working directory.
    Requires administrator privileges.
#>

[CmdletBinding()]
param(
    [string]$DefinitionsPath,

    [string]$ProfilePath,

    [string]$Build,
    [switch]$Snapshot,
    [string]$SnapshotPath,

    [string]$LogPath,
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
        Writes a fatal error to the console and exits with code 1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [string]$Detail = ''
    )
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

    # Format value: DWORD as 8-digit hex, all others as literal string
    $lgpoValue = if ($lgpoType -eq 'DWORD') {
        '{0:X8}' -f [int]$Value
    } else {
        "$Value"
    }

    $content  = "$section`r`n$lgpoPath`r`n$ValueName`r`n${lgpoType}:$lgpoValue`r`n`r`n"
    $tempFile = [System.IO.Path]::GetTempFileName()

    try {
        # Write to LGPO first: the authoritative record that survives any Group Policy refresh
        [System.IO.File]::WriteAllText($tempFile, $content, [System.Text.Encoding]::ASCII)
        & $script:LGPOExePath /t $tempFile 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { return 'WriteFailed' }

        # Write directly to registry for immediate effect
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $ValueName -Value $Value -Type $ValueType -Force
    }
    catch {
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
        & $script:LGPOExePath /t $tempFile 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { return 'RemoveFailed' }

        # Remove directly from registry for immediate effect
        Remove-ItemProperty -Path $Path -Name $ValueName -ErrorAction Stop
    }
    catch {
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

    # Pre-check: return early if the value is already correct
    $current = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
    if ($current.Exists -and $current.Value -eq $Value) {
        return 'AlreadyPresent'
    }

    # Write: dispatch to direct registry write (Home) or LGPO (non-Home)
    if ($script:IsHomeEdition) {
        try {
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }
            Set-ItemProperty -Path $Path -Name $ValueName -Value $Value -Type $ValueType -Force
        }
        catch {
            return 'WriteFailed'
        }
    }
    else {
        $lgpoResult = Invoke-LGPOWrite -Path $Path -ValueName $ValueName -ValueType $ValueType -Value $Value
        if ($lgpoResult -eq 'WriteFailed') { return 'WriteFailed' }
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

    # Pre-check: return early if the value is already absent
    $current = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
    if (-not $current.Exists) {
        return 'AlreadyAbsent'
    }

    # Remove: dispatch to direct registry remove (Home) or LGPO (non-Home)
    if ($script:IsHomeEdition) {
        try {
            Remove-ItemProperty -Path $Path -Name $ValueName -ErrorAction Stop
        }
        catch {
            return 'RemoveFailed'
        }
    }
    else {
        $lgpoResult = Invoke-LGPORemove -Path $Path -ValueName $ValueName
        if ($lgpoResult -eq 'RemoveFailed') { return 'RemoveFailed' }
    }

    # Verify: confirm the removal took effect
    $verify = Get-SettingCurrentValue -Path $Path -ValueName $ValueName
    if ($verify.Exists) {
        return 'VerifyFailed'
    }

    return 'Removed'
}

#endregion

#region INTERACTIVE MODE

function Start-InteractiveMode {
    <#
    .SYNOPSIS
        Entry point for the interactive session. Renders the category list
        and dispatches to Enter-Category on selection.
    #>
    [CmdletBinding()]
    param()

    while ($true) {
        Clear-Host

        $categoryNames = @()
        $statusIcons   = @()
        foreach ($category in $script:Definitions.Categories) {
            $categoryNames += $category.Name
            $counts         = if ($category.Subcategories) {
                $h = 0; $t = 0
                foreach ($subcategory in $category.Subcategories) {
                    $c  = Get-SectionCounts -Sections $subcategory.Sections
                    $h += $c.Hardened
                    $t += $c.Total
                }
                @{ Hardened = $h; Total = $t }
            }
            else {
                Get-SectionCounts -Sections $category.Sections
            }
            $statusIcons += "($($counts.Hardened)/$($counts.Total))"
        }

        $params = @{
            Title       = 'Windows Hardening - Select a Category'
            Items       = $categoryNames
            StatusIcons = $statusIcons
            FooterText  = '[Enter] Select  [Q] Quit'
        }
        $result = Show-Menu @params

        switch ($result) {
            -2 { Invoke-Quit }
            -1 { }  # Esc: no-op at top level
            -3 { }
            default {
                $category = $script:Definitions.Categories[$result]
                Enter-Category -Category $category -Breadcrumb $category.Name
            }
        }
    }
}

function Enter-Category {
    <#
    .SYNOPSIS
        Handles navigation within a category. Detects whether
        the category uses subcategories or direct sections.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Category,
        [string]$Breadcrumb = ''
    )

    if ($Category.Subcategories) {
        while ($true) {
            Clear-Host

            $subcategoryNames = @()
            $statusIcons      = @()
            foreach ($subcategory in $Category.Subcategories) {
                $subcategoryNames += $subcategory.Name
                $counts            = Get-SectionCounts -Sections $subcategory.Sections
                $statusIcons      += "($($counts.Hardened)/$($counts.Total))"
            }

            $params = @{
                Title       = $Category.Name
                Items       = $subcategoryNames
                StatusIcons = $statusIcons
                Breadcrumb  = $Breadcrumb
                FooterText  = '[Enter] Select  [Esc] Back  [Q] Quit'
            }
            $result = Show-Menu @params

            switch ($result) {
                -2 { Invoke-Quit }
                -1 { return }
                -3 { }
                default {
                    $subcategory = $Category.Subcategories[$result]
                    $params = @{
                        Sections   = $subcategory.Sections
                        Title      = $subcategory.Name
                        Breadcrumb = "$Breadcrumb > $($subcategory.Name)"
                    }
                    Enter-Section @params
                }
            }
        }
    }
    else {
        $params = @{
            Sections   = $Category.Sections
            Title      = $Category.Name
            Breadcrumb = $Breadcrumb
        }
        Enter-Section @params
    }
}

function Enter-Section {
    <#
    .SYNOPSIS
        Displays a list of sections and handles navigation into each.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Sections,
        [Parameter(Mandatory)]
        [string]$Title,
        [string]$Breadcrumb = ''
    )

    while ($true) {
        Clear-Host

        $sectionNames = $Sections.Name

        $statusIcons = @()
        foreach ($section in $Sections) {
            if ($section.Settings -and $section.Settings.Count -gt 0) {
                $hardened     = @($section.Settings | Where-Object { (Test-SettingState -Setting $_) -eq 'HARDENED' }).Count
                $statusIcons += "($hardened/$($section.Settings.Count))"
            }
            else {
                $statusIcons += ''
            }
        }

        $params = @{
            Title       = $Title
            Items       = $sectionNames
            StatusIcons = $statusIcons
            Breadcrumb  = $Breadcrumb
            FooterText  = '[Enter] Select  [Esc] Back  [Q] Quit'
        }
        $result = Show-Menu @params

        switch ($result) {
            -2 { Invoke-Quit }
            -1 { return }
            -3 { }
            default {
                $section = $Sections[$result]
                $params = @{
                    SectionName = $section.Name
                    Settings    = $section.Settings
                    Breadcrumb  = "$Breadcrumb > $($section.Name)"
                }
                Show-SettingsView @params
            }
        }
    }
}

function Show-SettingsView {
    <#
    .SYNOPSIS
        Displays individual settings within a section, showing current state,
        and allows the user to view details or apply all hardened values.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SectionName,
        [Parameter(Mandatory)]
        [array]$Settings,
        [string]$Breadcrumb = ''
    )

    while ($true) {
        Clear-Host

        # Live registry read on every render so state reflects writes made mid-session
        $itemNames = @()
        $statusIcons = @()
        $hardenedCount = 0

        foreach ($setting in $Settings) {
            $state = Test-SettingState -Setting $setting
            $itemNames += $setting.Name

            if ($state -eq 'HARDENED') { $hardenedCount++ }

            $icon = "[$state]"

            if ($setting.Path -like 'HKCU:*') {
                $icon += ' [USER]'
            }

            $statusIcons += $icon
        }

        $title = "$SectionName ($hardenedCount of $($Settings.Count) hardened)"

        $footer = '[Enter] View Detail  [A] Apply All  [Esc] Back  [Q] Quit'

        $params = @{
            Title       = $title
            Items       = $itemNames
            StatusIcons = $statusIcons
            Breadcrumb  = $Breadcrumb
            FooterText  = $footer
        }
        $result = Show-Menu @params

        switch ($result) {
            -2 { Invoke-Quit }
            -1 { return }
            -3 { Invoke-ApplyAll -Settings $Settings -SectionName $SectionName }
            default {
                $selected = $Settings[$result]
                Show-SettingDetail -Setting $selected -Breadcrumb $Breadcrumb
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

    # Identify settings that need hardening
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

    # Confirm with user
    Write-Host ''
    Write-Host "  Apply hardened values to $($toApply.Count) setting(s)? [Y/N] " -ForegroundColor DarkYellow -NoNewline
    $confirm = [Console]::ReadKey($true).Key

    if ($confirm -ne 'Y') {
        return
    }

    Write-Host ''
    Write-Host ''

    # Apply each setting
    $applied = 0
    $failed  = 0

    foreach ($setting in $toApply) {
        $scopeLabel = if ($setting.Path -like 'HKCU:*') { '[USER]' } else { '[MACHINE]' }

        $before = Get-SettingCurrentValue -Path $setting.Path -ValueName $setting.ValueName
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
            'AlreadyPresent' {
                Write-Host "  [--] $scopeLabel $($setting.Name) - already hardened" -ForegroundColor Green
            }
            'VerifyFailed' {
                $failed++
                $script:FailedCount++
                Write-Host "  [!!] $scopeLabel $($setting.Name) - verification failed" -ForegroundColor Red
                Write-Log "FAILED $scopeLabel $($setting.Name) | $($setting.Path)\$($setting.ValueName) | Validation failed"
            }
            'WriteFailed' {
                $failed++
                $script:FailedCount++
                Write-Host "  [!!] $scopeLabel $($setting.Name) - write failed" -ForegroundColor Red
                Write-Log "FAILED $scopeLabel $($setting.Name) | $($setting.Path)\$($setting.ValueName) | Write failed"
            }
        }
    }

    Write-Host ''
    Write-Host "  Results: $applied applied, $failed failed" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Press any key to continue...' -ForegroundColor DarkYellow
    [void][Console]::ReadKey($true)
}

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

    while ($true) {
        Clear-Host

        # Render current state
        $current = Get-SettingCurrentValue -Path $Setting.Path -ValueName $Setting.ValueName
        $state   = Test-SettingState -Setting $Setting

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
                'HARDENED' { 'Green'  }
                'DEFAULT'  { 'Yellow' }
                'CUSTOM'   { 'Magenta'}
                'NOT SET'  { 'Yellow' }
            }
        )

        if ($Setting.Path -like 'HKCU:*') {
            Write-Host ''
            Write-Host '  * Per-user setting: applies to current user only' -ForegroundColor DarkYellow
        }

        Write-Host ''
        Write-Host '  [H] Apply Hardened  [D] Restore Default  [Esc] Back  [Q] Quit' -ForegroundColor DarkYellow
        $key = [Console]::ReadKey($true).Key

        switch ($key) {
            'H' {
                $beforeDisplay = if ($current.Exists) { "$($current.Value)" } else { '(not set)' }
                $scopeLabel = if ($Setting.Path -like 'HKCU:*') { '[USER]' } else { '[MACHINE]' }

                Write-Host ''
                $params = @{
                    Path      = $Setting.Path
                    ValueName = $Setting.ValueName
                    ValueType = $Setting.ValueType
                    Value     = $Setting.HardenedValue
                }
                $result = Invoke-SettingWrite @params

                switch ($result) {
                    'Written' {
                        Write-Host '  Applied and verified.' -ForegroundColor Green
                        $script:AppliedCount++
                        Write-Log "CHANGED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | After: $($Setting.HardenedValue) | Verified"
                    }
                    'AlreadyPresent' {
                        Write-Host '  Already at hardened value.' -ForegroundColor Green
                    }
                    'VerifyFailed' {
                        Write-Host '  Applied but verification failed.' -ForegroundColor Red
                        $script:FailedCount++
                        Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Validation failed"
                    }
                    'WriteFailed' {
                        Write-Host '  Write failed.' -ForegroundColor Red
                        $script:FailedCount++
                        Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Write failed"
                    }
                }
                # Any key other than Esc/Q loops back and re-renders the detail view
                $nextKey = [Console]::ReadKey($true).Key
                switch ($nextKey) {
                    'Escape' { return }
                    'Q'      { Invoke-Quit }
                }
            }
            'D' {
                $scopeLabel    = if ($Setting.Path -like 'HKCU:*') { '[USER]' } else { '[MACHINE]' }
                $beforeDisplay = if ($current.Exists) { "$($current.Value)" } else { '(not set)' }

                Write-Host ''
                if ($null -eq $Setting.DefaultValue) {
                    $params = @{
                        Path      = $Setting.Path
                        ValueName = $Setting.ValueName
                    }
                    $result = Invoke-SettingRemove @params

                    switch ($result) {
                        'Removed' {
                            Write-Host '  Restored to default (removed registry value).' -ForegroundColor Green
                            $script:AppliedCount++
                            Write-Log "RESTORED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | Removed registry value"
                        }
                        'AlreadyAbsent' {
                            Write-Host '  Already absent; default state satisfied.' -ForegroundColor Green
                        }
                        'VerifyFailed' {
                            Write-Host '  Remove appeared to succeed but value is still present.' -ForegroundColor Red
                            $script:FailedCount++
                            Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Remove verify failed"
                        }
                        'RemoveFailed' {
                            Write-Host '  Failed to remove registry value.' -ForegroundColor Red
                            $script:FailedCount++
                            Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Remove failed"
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
                            Write-Host '  Restored to default.' -ForegroundColor Green
                            $script:AppliedCount++
                            Write-Log "RESTORED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Before: $beforeDisplay | After: $($Setting.DefaultValue)"
                        }
                        'AlreadyPresent' {
                            Write-Host '  Already at default value.' -ForegroundColor Green
                        }
                        'VerifyFailed' {
                            Write-Host '  Restore appeared to succeed but verification failed.' -ForegroundColor Red
                            $script:FailedCount++
                            Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Restore verify failed"
                        }
                        'WriteFailed' {
                            Write-Host '  Failed to restore default.' -ForegroundColor Red
                            $script:FailedCount++
                            Write-Log "FAILED $scopeLabel $($Setting.Name) | $($Setting.Path)\$($Setting.ValueName) | Restore failed"
                        }
                    }
                }
                # Any key other than Esc/Q loops back and re-renders the detail view
                $nextKey = [Console]::ReadKey($true).Key
                switch ($nextKey) {
                    'Escape' { return }
                    'Q'      { Invoke-Quit }
                }
            }
            'Escape' {
                return
            }
            'Q' {
                Invoke-Quit
            }
        }
    }
}

function Show-Menu {
    <#
    .SYNOPSIS
        Displays a navigable menu with arrow key support and returns
        the user's selection index, or a negative value for special actions.
    .OUTPUTS
        Returns index (0+) for selection, -1 for Escape,
        -2 for Quit, or -3 for Apply All.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        [Parameter(Mandatory)]
        [string[]]$Items,
        [string]$Breadcrumb = '',
        [string[]]$StatusIcons = @(),
        [string]$FooterText = '[Enter] Select  [Esc] Back  [Q] Quit'
    )

    # Uses SetCursorPosition for flicker-free in-place rendering.
    # Caller must call Clear-Host before invoking when transitioning between menu levels.
    $selectedIndex = 0
    $consoleWidth = [Console]::WindowWidth

    function Pad([string]$Text) {
        # Truncate at console width - 1 to prevent accidental line wrapping
        if ($Text.Length -ge $consoleWidth) { return $Text.Substring(0, $consoleWidth - 1) }
        return $Text + (' ' * ($consoleWidth - $Text.Length))
    }

    while ($true) {
        [Console]::SetCursorPosition(0, 0)
        [Console]::CursorVisible = $false

        # Breadcrumb
        if ($Breadcrumb) {
            Write-Host (Pad "  $Breadcrumb") -ForegroundColor DarkGray
        }
        else {
            Write-Host (Pad '')
        }

        # Title
        Write-Host (Pad '')
        Write-Host (Pad "  $Title") -ForegroundColor Cyan
        Write-Host (Pad ('  ' + ('-' * ($Title.Length)))) -ForegroundColor DarkCyan
        Write-Host (Pad '')

        # Menu items
        for ($i = 0; $i -lt $Items.Count; $i++) {
            $indicator = if ($i -eq $selectedIndex) { '>' } else { ' ' }
            $status = if ($StatusIcons.Count -gt $i -and $StatusIcons[$i]) { "  $($StatusIcons[$i])" } else { '' }
            $line = "  $indicator $($Items[$i])$status"

            if ($i -eq $selectedIndex) {
                Write-Host (Pad $line) -ForegroundColor Black -BackgroundColor White
            }
            else {
                Write-Host (Pad $line)
            }
        }

        # Footer
        Write-Host (Pad '')
        Write-Host (Pad "  $FooterText") -ForegroundColor DarkYellow

        # Input
        $key = [Console]::ReadKey($true).Key

        switch ($key) {
            'UpArrow' {
                $selectedIndex = ($selectedIndex - 1 + $Items.Count) % $Items.Count
            }
            'DownArrow' {
                $selectedIndex = ($selectedIndex + 1) % $Items.Count
            }
            'Enter' {
                [Console]::CursorVisible = $true
                return $selectedIndex
            }
            'Escape' {
                [Console]::CursorVisible = $true
                return -1
            }
            'Q' {
                [Console]::CursorVisible = $true
                return -2
            }
            'A' {
                [Console]::CursorVisible = $true
                return -3
            }
        }
    }
}

function Get-SectionCounts {
    <#
    .SYNOPSIS
        Aggregates hardened and total setting counts across an array of sections.
    .OUTPUTS
        Returns a hashtable with Hardened and Total integer counts.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [array]$Sections
    )

    $hardened = 0
    $total    = 0
    foreach ($section in $Sections) {
        if ($section.Settings) {
            $total    += @($section.Settings).Count
            $hardened += @($section.Settings | Where-Object { (Test-SettingState -Setting $_) -eq 'HARDENED' }).Count
        }
    }
    return @{ Hardened = $hardened; Total = $total }
}

function Invoke-Quit {
    <#
    .SYNOPSIS
        Writes the session summary to the log and exits cleanly.
    #>
    [CmdletBinding()]
    param()
    Write-LogSessionEnd
    Clear-Host
    exit 0
}


#endregion

#region SILENT MODE

function Invoke-ProfileMode {
    <#
    .SYNOPSIS
        Applies all settings in a profile file without prompting,
        after generating a pre-change snapshot.
    .OUTPUTS
        Returns $true if all settings were applied successfully,
        $false if any setting failed to apply or validate.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$ProfilePath
    )

    $profileData = Import-PowerShellDataFile -Path $ProfilePath

    if (-not $profileData.Settings) {
        Write-Host '  [X] Profile file contains no settings.' -ForegroundColor Red
        Write-Log 'ERROR: Profile file contains no settings.'
        return $false
    }

    # Generate snapshot of settings about to be changed
    $snapshotPath = Get-SnapshotProfilePath
    Write-Host ''
    Write-Host '  Generating snapshot before applying profile...' -ForegroundColor Cyan
    Export-SnapshotProfile -Settings $profileData.Settings -OutputPath $snapshotPath

    $applied = 0
    $failed  = 0
    $skipped = 0

    Write-Host ''
    Write-Host '  Applying profile...' -ForegroundColor Cyan
    Write-Host ''

    foreach ($entry in $profileData.Settings) {
        $scopeLabel = if ($entry.Path -like 'HKCU:*') { '[USER]' } else { '[MACHINE]' }

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
                    Write-Host "  [OK] $scopeLabel Removed: $($entry.ValueName)" -ForegroundColor Green
                    Write-Log "RESTORED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Removed registry value"
                }
                'AlreadyAbsent' {
                    $skipped++
                }
                'VerifyFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel Remove verify failed: $($entry.ValueName)" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Remove verify failed"
                }
                'RemoveFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel Failed to remove: $($entry.ValueName)" -ForegroundColor Red
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
                    Write-Host "  [OK] $scopeLabel Set: $($entry.ValueName) = $($entry.Value)" -ForegroundColor Green
                    Write-Log "CHANGED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Before: $beforeDisplay | After: $($entry.Value) | Verified"
                }
                'AlreadyPresent' {
                    $skipped++
                }
                'VerifyFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel Validation failed: $($entry.ValueName)" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Validation failed"
                }
                'WriteFailed' {
                    $failed++
                    $script:FailedCount++
                    Write-Host "  [!!] $scopeLabel Write failed: $($entry.ValueName)" -ForegroundColor Red
                    Write-Log "FAILED $scopeLabel $($entry.ValueName) | $($entry.Path)\$($entry.ValueName) | Write failed"
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

function Start-BuildMode {
    <#
    .SYNOPSIS
        Entry point for Build Mode. Loads the build profile
        and launches the interactive menu.
    #>
    [CmdletBinding()]
    param()

    $script:IsBuildMode = $true
    Import-BuildProfile
    Start-InteractiveMode
}

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

    try {
        $profileData = Import-PowerShellDataFile -Path $Build
        if ($profileData.Settings) {
            foreach ($entry in $profileData.Settings) {
                $key = "$($entry.Path)|$($entry.ValueName)"
                $script:BuildData[$key] = $entry
            }
        }
    }
    catch {
        $params = @{
            Message = "Failed to load build profile: $_"
            Detail  = "Verify that $Build is a valid PSD1 profile file."
        }
        Write-FatalError @params
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
        [void]$script:BuildData.Remove($key)
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

    if ($PSCmdlet.ParameterSetName -eq 'FromDefinitions') {
        $source = @()
        foreach ($category in $Definitions.Categories) {
            if ($category.Subcategories) {
                foreach ($subcategory in $category.Subcategories) {
                    foreach ($section in $subcategory.Sections) {
                        $source += $section.Settings
                    }
                }
            }
            elseif ($category.Sections) {
                foreach ($section in $category.Sections) {
                    if ($section.Settings) {
                        $source += $section.Settings
                    }
                }
            }
        }
    }
    else {
        $source = $Settings
    }

    $entries = @()

    foreach ($setting in $source) {
        $current = Get-SettingCurrentValue -Path $setting.Path -ValueName $setting.ValueName
        $entries += @{
            Path      = $setting.Path
            ValueName = $setting.ValueName
            ValueType = $setting.ValueType
            Value     = $current.Value       # $null if the value does not exist
            Exists    = $current.Exists       # $false flags this value for removal on restore
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

# Validate parameter combinations
if ($ProfilePath -and $DefinitionsPath) {
    $params = @{
        Message = '-ProfilePath and -DefinitionsPath cannot be used together.'
        Detail  = 'Use -DefinitionsPath for Interactive Mode; use -ProfilePath alone for Silent Mode.'
    }
    Write-FatalError @params
}
if ($ProfilePath -and $Build) {
    $params = @{
        Message = '-ProfilePath and -Build cannot be used together.'
        Detail  = 'Pass the profile file path directly to -Build.'
    }
    Write-FatalError @params
}
if ($ProfilePath -and $Snapshot) {
    $params = @{
        Message = '-ProfilePath and -Snapshot cannot be used together.'
        Detail  = 'Use -SnapshotPath to set the Snapshot Mode output path.'
    }
    Write-FatalError @params
}
if ($Build -and $Snapshot) {
    $params = @{
        Message = '-Build and -Snapshot cannot be used together.'
        Detail  = 'Use -Build <path> to save settings; use -Snapshot to capture system state.'
    }
    Write-FatalError @params
}
if ($PSBoundParameters.ContainsKey('Build') -and -not $Build) {
    $params = @{
        Message = '-Build requires a file path.'
        Detail  = 'Provide the path to the profile file as the argument: -Build <path>.'
    }
    Write-FatalError @params
}
if ($Build -and -not $DefinitionsPath) {
    Write-FatalError '-Build requires -DefinitionsPath.'
}
if ($Snapshot -and -not $DefinitionsPath) {
    Write-FatalError '-Snapshot requires -DefinitionsPath.'
}
if ($SnapshotPath -and -not $Snapshot) {
    $params = @{
        Message = '-SnapshotPath requires -Snapshot.'
        Detail  = 'Pass -Snapshot to trigger Snapshot Mode, then use -SnapshotPath to set the output path.'
    }
    Write-FatalError @params
}

if ($DefinitionsPath -and -not (Test-Path $DefinitionsPath -PathType Leaf)) {
    Write-FatalError "Definitions file not found: $DefinitionsPath"
}

# Run prerequisite checks (-Build is cross-platform and unprivileged)
Test-Prerequisites -RequireElevation (-not $Build)

# Load definitions file once for all modes that require it
$script:Definitions = $null
if ($DefinitionsPath) {
    try {
        $script:Definitions = Import-PowerShellDataFile -Path $DefinitionsPath
    }
    catch {
        Write-FatalError "Failed to load definitions file: $_"
    }
}

# Mode priority: Build > Snapshot > ProfilePath > Interactive
if ($Build) {
    # Build Mode
    Write-LogSessionStart -Mode 'Build' -DefinitionsPath $DefinitionsPath -ProfilePath $Build
    Start-BuildMode
}
elseif ($Snapshot) {
    # Snapshot Mode
    Write-LogSessionStart -Mode 'Snapshot' -DefinitionsPath $DefinitionsPath -ProfilePath $SnapshotPath

    Write-Host ''
    Write-Host '  ================================================' -ForegroundColor Cyan
    Write-Host '  Invoke-WinHardenPolicy - Snapshot Mode' -ForegroundColor Cyan
    Write-Host '  ================================================' -ForegroundColor Cyan

    $outputPath = if (-not $SnapshotPath) {
        Get-SnapshotProfilePath
    } elseif (Test-Path $SnapshotPath -PathType Container) {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        Join-Path $SnapshotPath "Policy-Snapshot_${env:COMPUTERNAME}_${timestamp}.psd1"
    } else {
        $SnapshotPath
    }
    Write-Host ''
    Export-SnapshotProfile -Definitions $script:Definitions -OutputPath $outputPath
    Write-LogSessionEnd
    exit 0
}
elseif ($ProfilePath) {
    # Silent Mode
    if (-not (Test-Path $ProfilePath -PathType Leaf)) {
        Write-FatalError "Profile file not found: $ProfilePath"
    }

    Write-LogSessionStart -Mode 'Silent' -ProfilePath $ProfilePath
    Initialize-EditionContext

    Write-Host ''
    Write-Host '  ================================================' -ForegroundColor Cyan
    Write-Host '  Invoke-WinHardenPolicy - Silent Mode' -ForegroundColor Cyan
    Write-Host '  ================================================' -ForegroundColor Cyan
    Write-Host "  Profile: $ProfilePath"

    $success = Invoke-ProfileMode -ProfilePath $ProfilePath
    Write-LogSessionEnd
    if (-not $success) { exit 1 }
}
else {
    # Interactive Mode
    if (-not $DefinitionsPath) {
        Write-FatalError '-DefinitionsPath is required for Interactive Mode.'
    }

    Write-LogSessionStart -Mode 'Interactive' -DefinitionsPath $DefinitionsPath
    Initialize-EditionContext

    $snapshotPath = Get-SnapshotProfilePath
    Export-SnapshotProfile -Definitions $script:Definitions -OutputPath $snapshotPath

    Start-InteractiveMode
}

#endregion
