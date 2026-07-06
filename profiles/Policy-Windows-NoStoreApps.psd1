#
# windows-hardening
# https://github.com/briangeis/windows-hardening
#
# Policy Profile: Windows No Store Apps
# Additive layer for devices that do not use the Microsoft Store or its apps.
#
# Reference: profiles/reference/Policy-Windows.md
#
# Author:  Brian Geis
# License: GPL-3.0-or-later
#

@{
    Meta = @{
        Component   = 'Policy'
        Name        = 'Windows No Store Apps'
        Description = 'Additive layer for devices that do not use the Microsoft Store or its apps.'
        Target      = 'Windows 11 25H2'
        Reviewed    = '2026-06-29'
        Source      = @(
            @{ Name = 'Microsoft Privacy Connections'; File = 'Policy-MicrosoftPrivacyConnections.psd1'; Target = 'Windows 11 25H2'; Reviewed = '2026-06-01' }
            @{ Name = 'Windows Privacy Defaults'; File = 'Policy-WindowsPrivacyDefaults.psd1'; Target = 'Windows 11 25H2'; Reviewed = '2026-06-01' }
        )
    }
    Settings = @(
        @{
            Name      = 'Disable OneDrive File Storage'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
            ValueName = 'DisableFileSyncNGSC'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable OneDrive Network Traffic Before Sign-In'
            Path      = 'HKLM:\SOFTWARE\Microsoft\OneDrive'
            ValueName = 'PreventNetworkTrafficPreUserSignIn'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Microsoft Account Sign-In Assistant'
            Path      = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlidsvc'
            ValueName = 'Start'
            ValueType = 'DWord'
            Value     = 4
            Exists    = $true
        }
        @{
            Name      = 'Disable Cross-Device Experiences'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableCdp'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Disable Location Services'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
            ValueName = 'DisableLocation'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Location'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessLocation'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Camera'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessCamera'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Microphone'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessMicrophone'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Trusted Devices'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessTrustedDevices'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Account Info'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessAccountInfo'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Contacts'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessContacts'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Calendar'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessCalendar'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Email'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessEmail'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Messaging'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessMessaging'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Phone Calls'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessPhone'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny App Access to Call History'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsAccessCallHistory'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Deny Background App Execution'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueName = 'LetAppsRunInBackground'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Disable All Store Apps'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
            ValueName = 'DisableStoreApps'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable Auto Download and Install of Updates'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
            ValueName = 'AutoDownload'
            ValueType = 'DWord'
            Value     = 2
            Exists    = $true
        }
        @{
            Name      = 'Disable Notification Network Traffic'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
            ValueName = 'NoCloudApplicationNotification'
            ValueType = 'DWord'
            Value     = 1
            Exists    = $true
        }
        @{
            Name      = 'Disable License Manager Service'
            Path      = 'HKLM:\SYSTEM\CurrentControlSet\Services\LicenseManager'
            ValueName = 'Start'
            ValueType = 'DWord'
            Value     = 4
            Exists    = $true
        }
        @{
            Name      = 'Disable Phone-PC Linking'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableMmx'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
    )
}
