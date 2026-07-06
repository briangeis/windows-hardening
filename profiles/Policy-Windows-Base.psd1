#
# windows-hardening
# https://github.com/briangeis/windows-hardening
#
# Policy Profile: Windows Base
# A curated privacy and security baseline for standalone devices.
#
# Reference: profiles/reference/Policy-Windows.md
#
# Author:  Brian Geis
# License: GPL-3.0-or-later
#

@{
    Meta = @{
        Component   = 'Policy'
        Name        = 'Windows Base'
        Description = 'A curated privacy and security baseline for standalone devices.'
        Target      = 'Windows 11 25H2'
        Reviewed    = '2026-06-29'
        Source      = @(
            @{ Name = 'Microsoft Privacy Connections'; File = 'Policy-MicrosoftPrivacyConnections.psd1'; Target = 'Windows 11 25H2'; Reviewed = '2026-06-01' }
            @{ Name = 'Windows Privacy Defaults'; File = 'Policy-WindowsPrivacyDefaults.psd1'; Target = 'Windows 11 25H2'; Reviewed = '2026-06-01' }
        )
    }
    Settings = @(
        @{
            Name      = 'Set Diagnostic Data to Minimum'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowTelemetry'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Tailored Experiences'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableTailoredExperiencesWithDiagnosticData'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Consumer Experiences'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Feedback Notifications'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'DoNotShowFeedbackNotifications'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Set Feedback Period to Zero'
            Path      = 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules'
            ValueName = 'PeriodInNanoSeconds'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Set Feedback Count to Zero'
            Path      = 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules'
            ValueName = 'NumberOfSIUFInPeriod'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Advertising ID (Feature)'
            Path      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Advertising ID (Policy)'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
            ValueName = 'DisabledByGroupPolicy'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Language List Access'
            Path      = 'HKCU:\Control Panel\International\User Profile'
            ValueName = 'HttpAcceptLanguageOptOut'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable MAPS Reporting'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'SpyNetReporting'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Sample Submission'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'SubmitSamplesConsent'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Disable MSRT Diagnostic Data'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\MRT'
            ValueName = 'DontReportInfectionInformation'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Enhanced Notifications'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
            ValueName = 'DisableEnhancedNotifications'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Restrict Implicit Text Collection'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            ValueName = 'RestrictImplicitTextCollection'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Restrict Implicit Ink Collection'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            ValueName = 'RestrictImplicitInkCollection'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Web Results in Search'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'ConnectedSearchUseWeb'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Web Search'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'DisableWebSearch'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Search Location'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowSearchToUseLocation'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Cortana'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCortana'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Settings Sync'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
            ValueName = 'DisableSettingSync'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Disable Settings Sync User Override'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
            ValueName = 'DisableSettingSyncUserOverride'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Cloud Clipboard'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'AllowCrossDeviceClipboard'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Find My Device'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice'
            ValueName = 'AllowFindMyDevice'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Radios'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessRadios'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Motion'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessMotion'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny Sync with Unpaired Devices'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsSyncWithDevices'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Notifications'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessNotifications'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny Voice Activation'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsActivateWithVoice'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny Voice Activation Above Lock'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsActivateWithVoiceAboveLock'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Tasks'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessTasks'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Diagnostics'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsGetDiagnosticInfo'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Suppress Store App Recommendations (Policy)'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen'
            ValueName = 'ConfigureAppInstallControlEnabled'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Suppress Store App Recommendations (Source)'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen'
            ValueName = 'ConfigureAppInstallControl'
            ValueType = 'String'
            Value     = 'Anywhere'
            Exists    = $true
        }
        @{
            Name      = 'Disable SmartScreen for Store Apps'
            Path      = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'
            ValueName = 'EnableWebContentEvaluation'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable All Spotlight Features'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableWindowsSpotlightFeatures'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Cloud Optimized Content'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableCloudOptimizedContent'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Widgets'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'
            ValueName = 'AllowNewsAndInterests'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable News and Interests'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds'
            ValueName = 'EnableFeeds'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Recommendations'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'HideRecommendedSection'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable App Launch Tracking'
            Path      = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'Start_TrackProgs'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Online Speech Recognition'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            ValueName = 'AllowInputPersonalization'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Speech Model Updates'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Speech'
            ValueName = 'AllowSpeechModelUpdate'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Online Tips'
            Path      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'AllowOnlineTips'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable App URI Handlers'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableAppUriHandlers'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Auto Download Map Data'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps'
            ValueName = 'AutoDownloadAndUpdateMapData'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Unsolicited Map Network Traffic'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps'
            ValueName = 'AllowUntriggeredNetworkTrafficOnSettingsPage'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Activity Feed'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableActivityFeed'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Publish User Activities'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'PublishUserActivities'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Upload User Activities'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'UploadUserActivities'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Insider Preview Builds'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'
            ValueName = 'AllowBuildPreview'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Peer-to-Peer Update Sharing'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
            ValueName = 'DODownloadMode'
            ValueType = 'DWord'
            Value     = 99
            Exists    = $true
        }
        @{
            Name      = 'Disable Disk Health Model Updates'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageHealth'
            ValueName = 'AllowDiskHealthModelUpdates'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Services Configuration'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'DisableOneSettingsDownloads'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Suggested Sites'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Enhanced Suggestions'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer'
            ValueName = 'AllowServicePoweredQSA'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Browser Geolocation'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation'
            ValueName = 'PolicyDisableGeolocation'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable AutoComplete for Web Addresses'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete'
            ValueName = 'AutoSuggest'
            ValueType = 'String'
            Value     = 'no'
            Exists    = $true
        }
        @{
            Name      = 'Disable Feed Background Sync'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName = 'BackgroundSyncStatus'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable IE SmartScreen'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueName = 'EnabledV9'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable ActiveX VersionList Download'
            Path      = 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\VersionManager'
            ValueName = 'DownloadVersionList'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Set IE Home Page to Blank'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'Start Page'
            ValueType = 'String'
            Value     = 'about:blank'
            Exists    = $true
        }
        @{
            Name      = 'Lock IE Home Page Setting'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel'
            ValueName = 'HomePage'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable IE First Run Wizard'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'DisableFirstRunCustomize'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Set IE New Tab to Blank'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing'
            ValueName = 'NewTabPageShow'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Compatibility View Editing'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\BrowserEmulation'
            ValueName = 'DisableSiteListEditing'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Flip Ahead'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Device Metadata Retrieval'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'
            ValueName = 'PreventDeviceMetadataFromNetwork'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Font Streaming'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableFontProviders'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable KMS Online Validation'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
            ValueName = 'NoGenTicket'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Teredo'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition'
            ValueName = 'Teredo_State'
            ValueType = 'String'
            Value     = 'Disabled'
            Exists    = $true
        }
        @{
            Name      = 'Exclude Device Name from Diagnostic Data'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowDeviceNameInTelemetry'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Limit Diagnostic Log Collection'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'LimitDiagnosticLogCollection'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Limit Dump Collection'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'LimitDumpCollection'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Windows Error Reporting'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'Disabled'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Application Telemetry'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
            ValueName = 'AITEnable'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Inventory Collector'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
            ValueName = 'DisableInventory'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Inking and Typing Data Collection'
            Path      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput'
            ValueName = 'AllowLinguisticDataCollection'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disallow AutoPlay for Non-Volume Devices'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoAutoplayfornonVolume'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable AutoRun Command Execution'
            Path      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoAutorun'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable AutoPlay'
            Path      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'DWord'
            Value     = 255
            Exists    = $true
        }
        @{
            Name      = 'Disable Multicast Name Resolution'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName = 'EnableMulticast'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Smart Multi-Homed Name Resolution'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName = 'DisableSmartNameResolution'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Lock Screen App Notifications'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'DisableLockScreenAppNotifications'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Automatic Sign-In After Restart'
            Path      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'DisableAutomaticRestartSignOn'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Local Account Security Questions'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'NoLocalPasswordResetQuestions'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Fast Startup'
            Path      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
            ValueName = 'HiberbootEnabled'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Indexing of Encrypted Files'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable MDM Enrollment'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM'
            ValueName = 'DisableRegistration'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Recently Opened Document History'
            Path      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoRecentDocsHistory'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Remove Recently Added List from Start Menu'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'HideRecentlyAddedApps'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable File Explorer Search History'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'DisableSearchBoxSuggestions'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Search History'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'DisableSearchHistory'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable File Explorer Account Insights'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'DisableGraphRecentItems'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Clipboard History'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'AllowClipboardHistory'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Windows Tips'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableSoftLanding'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Consumer Account State Content'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableConsumerAccountStateContent'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Spotlight Collection on Desktop'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableSpotlightCollectionOnDesktop'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Windows Welcome Experience'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableWindowsSpotlightWindowsWelcomeExperience'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Spotlight on Action Center'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableWindowsSpotlightOnActionCenter'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Spotlight on Settings'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableWindowsSpotlightOnSettings'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Search Highlights'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'EnableDynamicContentInWSB'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Cloud Search'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCloudSearch'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Push To Install Service'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall'
            ValueName = 'DisablePushToInstall'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Account Notifications in Start'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AccountNotifications'
            ValueName = 'DisableAccountNotifications'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Windows Copilot'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
            ValueName = 'TurnOffWindowsCopilot'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Recall'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            ValueName = 'AllowRecallEnablement'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Click to Do'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            ValueName = 'DisableClickToDo'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Settings Agentic Search'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            ValueName = 'DisableSettingsAgent'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Game Recording and Broadcasting'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
            ValueName = 'AllowGameDVR'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Windows Media DRM Internet Access'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\WMDRM'
            ValueName = 'DisableOnline'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable CD and DVD Media Information Retrieval'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
            ValueName = 'PreventCDDVDMetadataRetrieval'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Music File Media Information Retrieval'
            Path      = 'HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
            ValueName = 'PreventMusicFileMetadataRetrieval'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
    )
}
