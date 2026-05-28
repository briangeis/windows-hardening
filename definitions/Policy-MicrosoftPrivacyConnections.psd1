#
# Policy Definitions: Microsoft Privacy Connections
#
# Source: Manage connections from Windows 10 and Windows 11 operating system components to Microsoft services
# URL:    https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
#

@{
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
                        @{
                            Name          = 'Set Diagnostic Data to Minimum'
                            Description   = 'Sets diagnostic data collection to the minimum level'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                            ValueName     = 'AllowTelemetry'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds > Allow Diagnostic Data'
                            GPOState      = 'Enabled (0)'
                        }
                        @{
                            Name          = 'Disable Tailored Experiences'
                            Description   = 'Prevents using diagnostic data for tailored experiences'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                            ValueName     = 'DisableTailoredExperiencesWithDiagnosticData'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Cloud Content > Do not use diagnostic data for tailored experiences'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Consumer Experiences'
                            Description   = 'Turns off Microsoft consumer experiences and tailored suggestions'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                            ValueName     = 'DisableWindowsConsumerFeatures'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off Microsoft consumer experiences'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Feedback Notifications'
                            Description   = 'Prevents Windows from asking for feedback'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                            ValueName     = 'DoNotShowFeedbackNotifications'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds > Do not show feedback notifications'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Set Feedback Period to Zero'
                            Description   = 'Sets the feedback period value to zero'
                            Path          = 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules'
                            ValueName     = 'PeriodInNanoSeconds'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Set Feedback Count to Zero'
                            Description   = 'Sets the number of feedback prompts per period to zero'
                            Path          = 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules'
                            ValueName     = 'NumberOfSIUFInPeriod'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                    )
                }

                # -- Section: Advertising & Tracking --
                @{
                    Name        = 'Advertising & Tracking'
                    Description = 'Controls advertising ID and language tracking for behavioral profiling'
                    Settings    = @(
                        @{
                            Name          = 'Disable Advertising ID (Feature)'
                            Description   = 'Turns off the advertising ID at the feature level'
                            Path          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
                            ValueName     = 'Enabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > User Profiles > Turn off the advertising ID'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Advertising ID (Policy)'
                            Description   = 'Enforces the advertising ID disable at the policy level'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
                            ValueName     = 'DisabledByGroupPolicy'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > User Profiles > Turn off the advertising ID'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Language List Access'
                            Description   = 'Prevents websites from using your language list for targeted content'
                            Path          = 'HKCU:\Control Panel\International\User Profile'
                            ValueName     = 'HttpAcceptLanguageOptOut'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                            Note          = 'Affects UWP apps and WinHTTP apps but not Chromium-based browsers.'
                        }
                    )
                }

                # -- Section: Defender Cloud Reporting --
                @{
                    Name        = 'Defender Cloud Reporting'
                    Description = 'Controls Defender cloud services, sample submission, and reporting'
                    Settings    = @(
                        @{
                            Name          = 'Disable MAPS Reporting'
                            Description   = 'Prevents joining Microsoft MAPS (cloud protection)'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
                            ValueName     = 'SpyNetReporting'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > MAPS > Join Microsoft MAPS'
                            GPOState      = 'Enabled (Disabled)'
                            Note          = 'Disabling reduces real-time cloud-based threat detection in Defender.'
                        }
                        @{
                            Name          = 'Disable Sample Submission'
                            Description   = 'Prevents sending file samples to Microsoft for analysis'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
                            ValueName     = 'SubmitSamplesConsent'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Never Send
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > MAPS > Send file samples when further analysis is required'
                            GPOState      = 'Enabled (Never Send)'
                            Note          = 'Disabling reduces Defender''s ability to analyze new or unknown threats.'
                        }
                        @{
                            Name          = 'Disable MSRT Diagnostic Data'
                            Description   = 'Prevents Malicious Software Reporting Tool from sending diagnostic data'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\MRT'
                            ValueName     = 'DontReportInfectionInformation'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Disable Enhanced Notifications'
                            Description   = 'Turns off enhanced notifications from Defender'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
                            ValueName     = 'DisableEnhancedNotifications'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Reporting > Turn off enhanced notifications'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Inking & Typing --
                @{
                    Name        = 'Inking & Typing'
                    Description = 'Controls inking and typing data collection for personalization'
                    Settings    = @(
                        @{
                            Name          = 'Restrict Implicit Text Collection'
                            Description   = 'Prevents collection of text input data for personalization'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
                            ValueName     = 'RestrictImplicitTextCollection'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Control Panel > Regional and Language Options > Handwriting personalization > Turn off automatic learning'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Restrict Implicit Ink Collection'
                            Description   = 'Prevents collection of inking data for personalization'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
                            ValueName     = 'RestrictImplicitInkCollection'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Control Panel > Regional and Language Options > Handwriting personalization > Turn off automatic learning'
                            GPOState      = 'Enabled'
                        }
                    )
                }

            ) # End Telemetry & Diagnostics Sections
        }

        # ===== Category: Microsoft Cloud Services =====
        @{
            Name        = 'Microsoft Cloud Services'
            Description = 'Settings controlling data flow to and from Microsoft cloud services'
            Sections    = @(

                # -- Section: OneDrive --
                @{
                    Name        = 'OneDrive'
                    Description = 'Controls OneDrive integration and network traffic'
                    Settings    = @(
                        @{
                            Name          = 'Disable OneDrive File Storage'
                            Description   = 'Prevents the usage of OneDrive for file storage'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
                            ValueName     = 'DisableFileSyncNGSC'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > OneDrive > Prevent the usage of OneDrive for file storage'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable OneDrive Network Traffic Before Sign-In'
                            Description   = 'Prevents OneDrive from generating network traffic until signed in'
                            Path          = 'HKLM:\SOFTWARE\Microsoft\OneDrive'
                            ValueName     = 'PreventNetworkTrafficPreUserSignIn'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > OneDrive > Prevent OneDrive from generating network traffic until the user signs in to OneDrive'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Microsoft Account --
                @{
                    Name        = 'Microsoft Account'
                    Description = 'Controls the Microsoft Account sign-in service'
                    Settings    = @(
                        @{
                            Name          = 'Disable Microsoft Account Sign-In Assistant'
                            Description   = 'Turns off the Microsoft Account Sign-In Assistant service'
                            Path          = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlidsvc'
                            ValueName     = 'Start'
                            ValueType     = 'DWord'
                            HardenedValue = 4  # 4 = Disabled
                            DefaultValue  = 2  # 2 = Automatic
                            GPOPath       = $null
                            GPOState      = $null
                            Warning       = 'Breaks sign-in for Store, OneDrive, Office, Xbox, and Windows Update.'
                        }
                    )
                }

                # -- Section: Windows Search --
                @{
                    Name        = 'Windows Search'
                    Description = 'Controls Windows Search features and web integration'
                    Settings    = @(
                        @{
                            Name          = 'Disable Web Results in Search'
                            Description   = 'Prevents web queries and results from appearing in Search'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
                            ValueName     = 'ConnectedSearchUseWeb'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Search > Don''t search the web or display web results in Search'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Web Search'
                            Description   = 'Prevents searching the web from Windows Desktop Search'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
                            ValueName     = 'DisableWebSearch'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Search > Do not allow web search'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Search Location'
                            Description   = 'Prevents Cortana and Search from using location data'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
                            ValueName     = 'AllowSearchToUseLocation'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Search > Allow search and Cortana to use location'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Cortana'
                            Description   = 'Turns off Cortana'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
                            ValueName     = 'AllowCortana'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Search > Allow Cortana'
                            GPOState      = 'Disabled'
                            Note          = 'Cortana is deprecated on Windows 11 and removed as of version 23H2.'
                        }
                    )
                }

                # -- Section: Cross-Device Experiences --
                @{
                    Name        = 'Cross-Device Experiences'
                    Description = 'Controls the Microsoft cross-device platform and connected sync features'
                    Settings    = @(
                        @{
                            Name          = 'Disable Cross-Device Experiences'
                            Description   = 'Prevents other devices from launching or continuing apps on this device'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'EnableCdp'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > Group Policy > Continue experiences on this device'
                            GPOState      = 'Disabled'
                            Caution       = 'May break Phone Link features including SMS mirroring and call handling.'
                        }
                        @{
                            Name          = 'Disable Settings Sync'
                            Description   = 'Turns off settings synchronization and blocks the user from re-enabling'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
                            ValueName     = 'DisableSettingSync'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Fully Disabled (user cannot re-enable)
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Sync your settings > Do not sync'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Settings Sync User Override'
                            Description   = 'Prevents users from re-enabling settings sync'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
                            ValueName     = 'DisableSettingSyncUserOverride'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Sync your settings > Do not sync'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Cloud Clipboard'
                            Description   = 'Prevents clipboard items from roaming across devices'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'AllowCrossDeviceClipboard'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > OS Policies > Allow Clipboard synchronization across devices'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Find My Device --
                @{
                    Name        = 'Find My Device'
                    Description = 'Controls the Find My Device feature'
                    Settings    = @(
                        @{
                            Name          = 'Disable Find My Device'
                            Description   = 'Turns off the Find My Device feature'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice'
                            ValueName     = 'AllowFindMyDevice'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Find My Device > Turn On/Off Find My Device'
                            GPOState      = 'Disabled'
                        }
                    )
                }

            ) # End Microsoft Cloud Services Sections
        }

        # ===== Category: App Permissions =====
        @{
            Name        = 'App Permissions'
            Description = 'Controls app access to device capabilities and personal data'
            Categories = @(

                # === Category: Device Access ===
                @{
                    Name        = 'Device Access'
                    Description = 'Controls app access to hardware capabilities'
                    Sections    = @(

                        # -- Section: Location --
                        @{
                            Name        = 'Location'
                            Description = 'Controls app access to device location'
                            Settings    = @(
                                @{
                                    Name          = 'Disable Location Services'
                                    Description   = 'Turns off location for the device'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
                                    ValueName     = 'DisableLocation'
                                    ValueType     = 'DWord'
                                    HardenedValue = 1
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Location and Sensors > Turn off location'
                                    GPOState      = 'Enabled'
                                    Note          = 'Disables the system-wide location platform, affecting all apps.'
                                }
                                @{
                                    Name          = 'Deny App Access to Location'
                                    Description   = 'Prevents apps from accessing location data'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessLocation'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access location'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Camera --
                        @{
                            Name        = 'Camera'
                            Description = 'Controls app access to the camera'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Camera'
                                    Description   = 'Prevents apps from accessing the camera'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessCamera'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access the camera'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Microphone --
                        @{
                            Name        = 'Microphone'
                            Description = 'Controls app access to the microphone'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Microphone'
                                    Description   = 'Prevents apps from accessing the microphone'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessMicrophone'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access the microphone'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Radios --
                        @{
                            Name        = 'Radios'
                            Description = 'Controls app access to device radios'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Radios'
                                    Description   = 'Prevents apps from controlling radios'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessRadios'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps control radios'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Controls UWP app ability to toggle radios on and off, not communication.'
                                }
                            )
                        }

                        # -- Section: Motion --
                        @{
                            Name        = 'Motion'
                            Description = 'Controls app access to motion data'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Motion'
                                    Description   = 'Prevents apps from accessing motion data and collecting motion history'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessMotion'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access motion'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Other Devices --
                        @{
                            Name        = 'Other Devices'
                            Description = 'Controls communication with unpaired and trusted devices'
                            Settings    = @(
                                @{
                                    Name          = 'Deny Sync with Unpaired Devices'
                                    Description   = 'Prevents apps from syncing with wireless devices not explicitly paired'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsSyncWithDevices'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps communicate with unpaired devices'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                                @{
                                    Name          = 'Deny Access to Trusted Devices'
                                    Description   = 'Prevents apps from accessing paired hardware and connected accessories'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessTrustedDevices'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access trusted devices'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                    ) # End Device Access Sections
                }

                # === Category: Communication ===
                @{
                    Name        = 'Communication'
                    Description = 'Controls app access to contacts, calendar, email, messaging, and calls'
                    Sections    = @(

                        # -- Section: Account Info --
                        @{
                            Name        = 'Account Info'
                            Description = 'Controls app access to name, picture, and other account info'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Account Info'
                                    Description   = 'Prevents apps from accessing your name, picture, and other account info'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessAccountInfo'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access account information'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Contacts --
                        @{
                            Name        = 'Contacts'
                            Description = 'Controls app access to contacts'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Contacts'
                                    Description   = 'Prevents apps from accessing contacts'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessContacts'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access contacts'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Calendar --
                        @{
                            Name        = 'Calendar'
                            Description = 'Controls app access to the calendar'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Calendar'
                                    Description   = 'Prevents apps from accessing the calendar'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessCalendar'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access the calendar'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Email --
                        @{
                            Name        = 'Email'
                            Description = 'Controls app access to email'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Email'
                                    Description   = 'Prevents apps from accessing and sending email'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessEmail'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access email'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Messaging --
                        @{
                            Name        = 'Messaging'
                            Description = 'Controls app access to messaging'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Messaging'
                                    Description   = 'Prevents apps from reading or sending messages'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessMessaging'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access messaging'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Phone Calls --
                        @{
                            Name        = 'Phone Calls'
                            Description = 'Controls app access to phone call features'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Phone Calls'
                                    Description   = 'Prevents apps from making phone calls'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessPhone'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps make phone calls'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Call History --
                        @{
                            Name        = 'Call History'
                            Description = 'Controls app access to call history'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Call History'
                                    Description   = 'Prevents apps from accessing call history'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessCallHistory'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access call history'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                    ) # End Communication Sections
                }

                # === Category: App Behavior ===
                @{
                    Name        = 'App Behavior'
                    Description = 'Controls general app behavior and permissions'
                    Sections    = @(

                        # -- Section: Background Apps --
                        @{
                            Name        = 'Background Apps'
                            Description = 'Controls whether apps can run in the background'
                            Settings    = @(
                                @{
                                    Name          = 'Deny Background App Execution'
                                    Description   = 'Prevents apps from running in the background'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsRunInBackground'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps run in the background'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. May affect background sync for apps like Mail.'
                                }
                            )
                        }

                        # -- Section: Notifications --
                        @{
                            Name        = 'Notifications'
                            Description = 'Controls app access to notifications'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Notifications'
                                    Description   = 'Prevents apps from accessing notifications'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessNotifications'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access notifications'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Voice Activation --
                        @{
                            Name        = 'Voice Activation'
                            Description = 'Controls app voice activation features'
                            Settings    = @(
                                @{
                                    Name          = 'Deny Voice Activation'
                                    Description   = 'Prevents apps from listening for a voice keyword'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsActivateWithVoice'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps activate with voice'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                                @{
                                    Name          = 'Deny Voice Activation Above Lock'
                                    Description   = 'Prevents apps from voice activation while the device is locked'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsActivateWithVoiceAboveLock'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps activate with voice while the system is locked'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: Tasks --
                        @{
                            Name        = 'Tasks'
                            Description = 'Controls app access to tasks'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Tasks'
                                    Description   = 'Prevents apps from accessing tasks'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsAccessTasks'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access Tasks'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                        # -- Section: App Diagnostics --
                        @{
                            Name        = 'App Diagnostics'
                            Description = 'Controls app access to diagnostic information about other apps'
                            Settings    = @(
                                @{
                                    Name          = 'Deny App Access to Diagnostics'
                                    Description   = 'Prevents apps from accessing diagnostic information about other apps'
                                    Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
                                    ValueName     = 'LetAppsGetDiagnosticInfo'
                                    ValueType     = 'DWord'
                                    HardenedValue = 2  # 2 = Force Deny
                                    DefaultValue  = $null
                                    GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > App Privacy > Let Windows apps access diagnostic information about other apps'
                                    GPOState      = 'Enabled (Force Deny)'
                                    Note          = 'Applies to UWP apps only. Win32 desktop apps are not affected.'
                                }
                            )
                        }

                    ) # End App Behavior Sections
                }

            ) # End App Permissions Categories
        }

        # ===== Category: Windows Features =====
        @{
            Name        = 'Windows Features'
            Description = 'Windows-native features with network or cloud behavior'
            Sections    = @(

                # -- Section: Microsoft Store --
                @{
                    Name        = 'Microsoft Store'
                    Description = 'Controls the Microsoft Store and automatic app downloads'
                    Settings    = @(
                        @{
                            Name          = 'Disable All Store Apps'
                            Description   = 'Turns off launching of preinstalled and downloaded Store apps'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
                            ValueName     = 'DisableStoreApps'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Store > Disable all apps from Microsoft Store'
                            GPOState      = 'Disabled'
                            Note          = 'Also disables the Microsoft Store application itself.'
                        }
                        @{
                            Name          = 'Disable Auto Download and Install of Updates'
                            Description   = 'Turns off automatic downloading and installing of Store app updates'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
                            ValueName     = 'AutoDownload'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Turn off automatic download
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Store > Turn off Automatic Download and Install of updates'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Suppress Store App Recommendations (Policy)'
                            Description   = 'Enables the app install policy used to suppress Store recommendations'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen'
                            ValueName     = 'ConfigureAppInstallControlEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Defender SmartScreen > Explorer > Configure App Install Control'
                            GPOState      = 'Enabled (Turn off app recommendations)'
                        }
                        @{
                            Name          = 'Suppress Store App Recommendations (Source)'
                            Description   = 'Turns off app recommendations from the Store'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen'
                            ValueName     = 'ConfigureAppInstallControl'
                            ValueType     = 'String'
                            HardenedValue = 'Anywhere'
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Defender SmartScreen > Explorer > Configure App Install Control'
                            GPOState      = 'Enabled (Turn off app recommendations)'
                        }
                        @{
                            Name          = 'Disable SmartScreen for Store Apps'
                            Description   = 'Prevents SmartScreen from checking web content that Store apps use'
                            Path          = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'
                            ValueName     = 'EnableWebContentEvaluation'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                    )
                }

                # -- Section: Windows Spotlight --
                @{
                    Name        = 'Windows Spotlight'
                    Description = 'Controls personalized lock screen images, suggestions, and tips'
                    Settings    = @(
                        @{
                            Name          = 'Disable All Spotlight Features'
                            Description   = 'Turns off all Windows Spotlight features'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                            ValueName     = 'DisableWindowsSpotlightFeatures'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off all Windows spotlight features'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Cloud Optimized Content'
                            Description   = 'Turns off cloud-optimized content for Spotlight features'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                            ValueName     = 'DisableCloudOptimizedContent'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off cloud optimized content'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Widgets --
                @{
                    Name        = 'Widgets'
                    Description = 'Controls the Widgets feature and news and interests feed'
                    Settings    = @(
                        @{
                            Name          = 'Disable Widgets'
                            Description   = 'Turns off the Widgets feature'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'
                            ValueName     = 'AllowNewsAndInterests'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Widgets > Allow widgets'
                            GPOState      = 'Disabled'
                            Note          = 'Applies to Windows 11 only. This feature does not exist on Windows 10.'
                        }
                        @{
                            Name          = 'Disable News and Interests'
                            Description   = 'Turns off the news and interests feed'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds'
                            ValueName     = 'EnableFeeds'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                            Note          = 'Applies to Windows 10 only. This feature was removed from Windows 11.'
                        }
                    )
                }

                # -- Section: Start Menu Personalization --
                @{
                    Name        = 'Start Menu Personalization'
                    Description = 'Controls app launch tracking and personalized content in the Start menu'
                    Settings    = @(
                        @{
                            Name          = 'Disable Recommendations'
                            Description   = 'Turns off recommended content in the Start menu'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                            ValueName     = 'HideRecommendedSection'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Start Menu and Taskbar > Remove Recommended section from Start Menu'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable App Launch Tracking'
                            Description   = 'Turns off app launch tracking used to personalize Start and search'
                            Path          = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
                            ValueName     = 'Start_TrackProgs'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                    )
                }

                # -- Section: Speech Recognition --
                @{
                    Name        = 'Speech Recognition'
                    Description = 'Controls online speech recognition and automatic model updates'
                    Settings    = @(
                        @{
                            Name          = 'Disable Online Speech Recognition'
                            Description   = 'Turns off online speech recognition services'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
                            ValueName     = 'AllowInputPersonalization'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Control Panel > Regional and Language Options > Allow users to enable online speech recognition services'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Speech Model Updates'
                            Description   = 'Prevents automatic updates to speech recognition and synthesis models'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Speech'
                            ValueName     = 'AllowSpeechModelUpdate'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Speech > Allow Automatic Update of Speech Data'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Push Notifications --
                @{
                    Name        = 'Push Notifications'
                    Description = 'Controls whether apps can use the network for push notification delivery'
                    Settings    = @(
                        @{
                            Name          = 'Disable Notification Network Traffic'
                            Description   = 'Turns off the device connection to the Windows Push Notification Service'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
                            ValueName     = 'NoCloudApplicationNotification'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Start Menu and Taskbar > Notifications > Turn off notifications network usage'
                            GPOState      = 'Enabled'
                            Note          = 'App background sync is not affected.'
                        }
                    )
                }

                # -- Section: Online Tips --
                @{
                    Name        = 'Online Tips'
                    Description = 'Controls online tips and help content in the Windows Settings app'
                    Settings    = @(
                        @{
                            Name          = 'Disable Online Tips'
                            Description   = 'Turns off retrieval of online tips and help in the Settings app'
                            Path          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                            ValueName     = 'AllowOnlineTips'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Control Panel > Allow Online Tips'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Apps for Websites --
                @{
                    Name        = 'Apps for Websites'
                    Description = 'Controls web-to-app linking with URI handlers'
                    Settings    = @(
                        @{
                            Name          = 'Disable App URI Handlers'
                            Description   = 'Turns off web-to-app linking for apps with registered URI handlers'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'EnableAppUriHandlers'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > Group Policy > Configure web-to-app linking with app URI handlers'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Offline Maps --
                @{
                    Name        = 'Offline Maps'
                    Description = 'Controls automatic map downloads and updates'
                    Settings    = @(
                        @{
                            Name          = 'Disable Auto Download Map Data'
                            Description   = 'Turns off automatic downloading and updating of map data'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps'
                            ValueName     = 'AutoDownloadAndUpdateMapData'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Maps > Turn off Automatic Download and Update of Map Data'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Unsolicited Map Network Traffic'
                            Description   = 'Turns off unsolicited network traffic on the Offline Maps settings page'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps'
                            ValueName     = 'AllowUntriggeredNetworkTrafficOnSettingsPage'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Maps > Turn off unsolicited network traffic on the Offline Maps settings page'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Activity History --
                @{
                    Name        = 'Activity History'
                    Description = 'Controls Windows Timeline activity tracking and synchronization'
                    Settings    = @(
                        @{
                            Name          = 'Disable Activity Feed'
                            Description   = 'Turns off the activity feed'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'EnableActivityFeed'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > OS Policies > Enables Activity Feed'
                            GPOState      = 'Disabled'
                            Note          = 'Applies to Windows 10 only. This feature was removed from Windows 11.'
                        }
                        @{
                            Name          = 'Disable Publish User Activities'
                            Description   = 'Prevents publishing of user activities'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'PublishUserActivities'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > OS Policies > Allow publishing of User Activities'
                            GPOState      = 'Disabled'
                            Note          = 'Applies to Windows 10 only. This feature was removed from Windows 11.'
                        }
                        @{
                            Name          = 'Disable Upload User Activities'
                            Description   = 'Prevents uploading of user activities'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'UploadUserActivities'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > OS Policies > Allow upload of User Activities'
                            GPOState      = 'Disabled'
                            Note          = 'Applies to Windows 10 only. This feature was removed from Windows 11.'
                        }
                    )
                }

            ) # End Windows Features Sections
        }

        # ===== Category: Windows Update =====
        @{
            Name        = 'Windows Update'
            Description = 'Settings controlling what Windows downloads or updates from Microsoft'
            Sections    = @(

                # -- Section: Windows Update Settings --
                @{
                    Name        = 'Windows Update Settings'
                    Description = 'Controls Windows Update connections and behavior'
                    Settings    = @(
                        @{
                            Name          = 'Disable Windows Update Access'
                            Description   = 'Turns off access to all Windows Update features'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                            ValueName     = 'DisableWindowsUpdateAccess'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > Internet Communication Management > Internet Communication settings > Turn off access to all Windows Update features'
                            GPOState      = 'Enabled'
                            Warning       = 'Windows will not receive security updates while this setting is applied.'
                        }
                        @{
                            Name          = 'Disable Windows Update Internet Locations'
                            Description   = 'Prevents connecting to Windows Update internet locations'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                            ValueName     = 'DoNotConnectToWindowsUpdateInternetLocations'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage updates offered from Windows Server Update Service > Do not connect to any Windows Update Internet locations'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Set WSUS Server to Blank'
                            Description   = 'Sets the intranet update service address to blank'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                            ValueName     = 'WUServer'
                            ValueType     = 'String'
                            HardenedValue = ' '  # Space character; article specifies ' ' rather than empty string
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage updates offered from Windows Server Update Service > Specify intranet Microsoft update service location'
                            GPOState      = 'Enabled (Blank)'
                        }
                        @{
                            Name          = 'Set WSUS Status Server to Blank'
                            Description   = 'Sets the intranet statistics server to blank'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                            ValueName     = 'WUStatusServer'
                            ValueType     = 'String'
                            HardenedValue = ' '  # Space character; article specifies ' ' rather than empty string
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage updates offered from Windows Server Update Service > Specify intranet Microsoft update service location'
                            GPOState      = 'Enabled (Blank)'
                        }
                        @{
                            Name          = 'Set Alternate Download Server to Blank'
                            Description   = 'Sets the alternate download server to blank'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                            ValueName     = 'UpdateServiceUrlAlternate'
                            ValueType     = 'String'
                            HardenedValue = ' '  # Space character; article specifies ' ' rather than empty string
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage updates offered from Windows Server Update Service > Specify intranet Microsoft update service location'
                            GPOState      = 'Enabled (Blank)'
                        }
                        @{
                            Name          = 'Enforce Intranet Update Server'
                            Description   = 'Directs Windows Update to use the configured intranet update server'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
                            ValueName     = 'UseWUServer'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage updates offered from Windows Server Update Service > Specify intranet Microsoft update service location'
                            GPOState      = 'Enabled (Blank)'
                        }
                    )
                }

                # -- Section: Insider Preview Builds --
                @{
                    Name        = 'Insider Preview Builds'
                    Description = 'Controls communication with the Windows Insider Preview service'
                    Settings    = @(
                        @{
                            Name          = 'Disable Insider Preview Builds'
                            Description   = 'Prevents checking for and receiving Insider Preview builds'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'
                            ValueName     = 'AllowBuildPreview'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds > Toggle user control over Insider builds'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Delivery Optimization --
                @{
                    Name        = 'Delivery Optimization'
                    Description = 'Controls peer-to-peer and cloud download behavior for updates'
                    Settings    = @(
                        @{
                            Name          = 'Disable Peer-to-Peer Update Sharing'
                            Description   = 'Sets Delivery Optimization to Simple Mode, disabling P2P sharing'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
                            ValueName     = 'DODownloadMode'
                            ValueType     = 'DWord'
                            HardenedValue = 99  # 99 = Simple Mode
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Delivery Optimization > Download Mode'
                            GPOState      = 'Enabled (Simple Mode (99))'
                        }
                    )
                }

                # -- Section: Storage Health --
                @{
                    Name        = 'Storage Health'
                    Description = 'Controls disk failure prediction model updates'
                    Settings    = @(
                        @{
                            Name          = 'Disable Disk Health Model Updates'
                            Description   = 'Prevents downloading updates to the Disk Failure Prediction Model'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageHealth'
                            ValueName     = 'AllowDiskHealthModelUpdates'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > Storage Health > Allow downloading updates to the Disk Failure Prediction Model'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Services Configuration --
                @{
                    Name        = 'Services Configuration'
                    Description = 'Controls the dynamic configuration service used by Windows components'
                    Settings    = @(
                        @{
                            Name          = 'Disable Services Configuration'
                            Description   = 'Turns off dynamic configuration updates for Windows components'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                            ValueName     = 'DisableOneSettingsDownloads'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds > Disable OneSettings Downloads'
                            GPOState      = 'Enabled'
                            Note          = 'Prevents Microsoft from pushing remote configuration changes to Windows.'
                        }
                    )
                }

            ) # End Windows Update Sections
        }

        # ===== Category: Browsers =====
        @{
            Name        = 'Browsers'
            Description = 'Settings for Internet Explorer and Microsoft Edge'
            Sections    = @(

                # -- Section: Microsoft Edge --
                @{
                    Name        = 'Microsoft Edge'
                    Description = 'Controls privacy and connection settings for Microsoft Edge'
                    Settings    = @(
                        @{
                            Name          = 'Disable Search Suggestions'
                            Description   = 'Turns off search suggestions in the address bar'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SearchSuggestEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Enable Do Not Track'
                            Description   = 'Sends Do Not Track headers with browsing requests'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ConfigureDoNotTrack'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                            Note          = 'Most websites do not honor Do Not Track headers.'
                        }
                        @{
                            Name          = 'Disable Password Manager'
                            Description   = 'Prevents saving passwords to the password manager'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'PasswordManagerEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Disable Address Autofill'
                            Description   = 'Turns off AutoFill for addresses'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AutofillAddressEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Disable Credit Card Autofill'
                            Description   = 'Turns off AutoFill for credit cards'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AutofillCreditCardEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Disable Default Search Provider'
                            Description   = 'Turns off the default search provider'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultSearchProviderEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Disable Edge SmartScreen'
                            Description   = 'Turns off Microsoft Defender SmartScreen in Microsoft Edge'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SmartScreenEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Defender SmartScreen > Microsoft Edge > Configure Windows Defender SmartScreen'
                            GPOState      = 'Disabled'
                            Warning       = 'Removes phishing and malware protection within Microsoft Edge.'
                        }
                        @{
                            Name          = 'Set New Tab to Blank'
                            Description   = 'Sets the new tab page to about:blank'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'NewTabPageLocation'
                            ValueType     = 'String'
                            HardenedValue = 'about:blank'
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Disable Startup Restore'
                            Description   = 'Turns off session restore on startup'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'RestoreOnStartup'
                            ValueType     = 'DWord'
                            HardenedValue = 5  # 5 = Open a specific page or pages
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Set Startup URL to Blank'
                            Description   = 'Sets the startup page to about:blank'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\RestoreOnStartupURLs'
                            ValueName     = '1'
                            ValueType     = 'String'
                            HardenedValue = 'about:blank'
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Disable First Run Experience'
                            Description   = 'Turns off the First-run experience and splash screen'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'HideFirstRunExperience'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                        @{
                            Name          = 'Disable Experimentation Service'
                            Description   = 'Turns off the Edge Experimentation and Configuration Service'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
                            ValueName     = 'ExperimentationAndConfigurationServiceControl'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                            Note          = 'Prevents Microsoft from pushing remote configuration changes to Edge.'
                        }
                    )
                }

                # -- Section: Microsoft Edge Update --
                @{
                    Name        = 'Microsoft Edge Update'
                    Description = 'Controls automatic update behavior for Microsoft Edge'
                    Settings    = @(
                        @{
                            Name          = 'Disable Edge Auto Update'
                            Description   = 'Turns off automatic Edge updates'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
                            ValueName     = 'UpdateDefault'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                            Warning       = 'Edge will not receive security patches without manual intervention.'
                        }
                        @{
                            Name          = 'Disable Auto Update Check'
                            Description   = 'Turns off periodic checks for Edge updates'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
                            ValueName     = 'AutoUpdateCheckPeriodMinutes'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = $null
                            GPOState      = $null
                        }
                    )
                }

                # -- Section: Internet Explorer --
                @{
                    Name        = 'Internet Explorer'
                    Description = 'Controls privacy and connection settings for Internet Explorer'
                    Settings    = @(
                        @{
                            Name          = 'Disable Suggested Sites'
                            Description   = 'Turns off the Suggested Sites feature'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites'
                            ValueName     = 'Enabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Turn on Suggested Sites'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Enhanced Suggestions'
                            Description   = 'Turns off Microsoft-powered enhanced suggestions in the address bar'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer'
                            ValueName     = 'AllowServicePoweredQSA'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Allow Microsoft services to provide enhanced suggestions as the user types in the Address Bar'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Browser Geolocation'
                            Description   = 'Prevents websites from requesting location data from IE'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation'
                            ValueName     = 'PolicyDisableGeolocation'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Turn off browser geolocation'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable AutoComplete for Web Addresses'
                            Description   = 'Turns off the auto-complete feature for web addresses'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete'
                            ValueName     = 'AutoSuggest'
                            ValueType     = 'String'
                            HardenedValue = 'no'
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Turn off the auto-complete feature for web addresses'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Feed Background Sync'
                            Description   = 'Turns off background synchronization for feeds and Web Slices'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
                            ValueName     = 'BackgroundSyncStatus'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > RSS Feeds > Turn off background synchronization for feeds and Web Slices'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable IE SmartScreen'
                            Description   = 'Turns off Microsoft Defender SmartScreen in Internet Explorer'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter'
                            ValueName     = 'EnabledV9'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Prevent managing SmartScreen Filter'
                            GPOState      = 'Enabled (Off)'
                            Warning       = 'Removes phishing and malware protection within Internet Explorer.'
                        }
                        @{
                            Name          = 'Disable ActiveX VersionList Download'
                            Description   = 'Turns off automatic download of the ActiveX VersionList'
                            Path          = 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\VersionManager'
                            ValueName     = 'DownloadVersionList'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Internet Explorer > Security Features > Add-on Management > Turn off Automatic download of the ActiveX VersionList'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Set IE Home Page to Blank'
                            Description   = 'Sets the IE home page to about:blank'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main'
                            ValueName     = 'Start Page'
                            ValueType     = 'String'
                            HardenedValue = 'about:blank'
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Internet Explorer > Disable changing home page settings'
                            GPOState      = 'Enabled (about:blank)'
                        }
                        @{
                            Name          = 'Lock IE Home Page Setting'
                            Description   = 'Prevents the user from changing the home page'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel'
                            ValueName     = 'HomePage'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Internet Explorer > Disable changing home page settings'
                            GPOState      = 'Enabled (about:blank)'
                        }
                        @{
                            Name          = 'Disable IE First Run Wizard'
                            Description   = 'Prevents running the First Run wizard'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main'
                            ValueName     = 'DisableFirstRunCustomize'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Prevent running First Run wizard'
                            GPOState      = 'Enabled (Go directly to home page)'
                        }
                        @{
                            Name          = 'Set IE New Tab to Blank'
                            Description   = 'Sets the new tab page to about:blank'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing'
                            ValueName     = 'NewTabPageShow'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Specify default behavior for a new tab'
                            GPOState      = 'Enabled (about:blank)'
                        }
                        @{
                            Name          = 'Disable Compatibility View Editing'
                            Description   = 'Prevents users from configuring Compatibility View'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\BrowserEmulation'
                            ValueName     = 'DisableSiteListEditing'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Compatibility View > Turn off Compatibility View'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Flip Ahead'
                            Description   = 'Turns off the flip ahead with page prediction feature'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead'
                            ValueName     = 'Enabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Internet Control Panel > Advanced Page > Turn off the flip ahead with page prediction feature'
                            GPOState      = 'Enabled'
                        }
                    )
                }

            ) # End Browsers Sections
        }

        # ===== Category: Background Services =====
        @{
            Name        = 'Background Services'
            Description = 'Background services that connect to Microsoft or external networks'
            Sections    = @(

                # -- Section: Device Metadata Retrieval --
                @{
                    Name        = 'Device Metadata Retrieval'
                    Description = 'Controls device metadata downloading from the internet'
                    Settings    = @(
                        @{
                            Name          = 'Disable Device Metadata Retrieval'
                            Description   = 'Prevents Windows from retrieving device metadata from the internet'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'
                            ValueName     = 'PreventDeviceMetadataFromNetwork'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > Device Installation > Prevent automatic download of applications associated with device metadata'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Font Streaming --
                @{
                    Name        = 'Font Streaming'
                    Description = 'Controls on-demand font downloading'
                    Settings    = @(
                        @{
                            Name          = 'Disable Font Streaming'
                            Description   = 'Prevents on-demand downloading of fonts not stored locally'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'EnableFontProviders'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Network > Fonts > Enable Font Providers'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Software Protection Platform --
                @{
                    Name        = 'Software Protection Platform'
                    Description = 'Controls KMS client activation data sent to Microsoft'
                    Settings    = @(
                        @{
                            Name          = 'Disable KMS Online Validation'
                            Description   = 'Opts out of sending KMS client activation data to Microsoft'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
                            ValueName     = 'NoGenTicket'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Software Protection Platform > Turn off KMS Client Online AVS Validation'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Teredo --
                @{
                    Name        = 'Teredo'
                    Description = 'Controls the Teredo IPv6 transition technology'
                    Settings    = @(
                        @{
                            Name          = 'Disable Teredo'
                            Description   = 'Turns off Teredo IPv6 tunneling'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition'
                            ValueName     = 'Teredo_State'
                            ValueType     = 'String'
                            HardenedValue = 'Disabled'
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Network > TCPIP Settings > IPv6 Transition Technologies > Set Teredo State'
                            GPOState      = 'Enabled (Disabled State)'
                            Caution       = 'May affect Xbox gaming and Delivery Optimization.'
                        }
                    )
                }

                # -- Section: License Manager --
                @{
                    Name        = 'License Manager'
                    Description = 'Controls the LicenseManager service for Store and subscription licensing'
                    Settings    = @(
                        @{
                            Name          = 'Disable License Manager Service'
                            Description   = 'Turns off the LicenseManager service'
                            Path          = 'HKLM:\SYSTEM\CurrentControlSet\Services\LicenseManager'
                            ValueName     = 'Start'
                            ValueType     = 'DWord'
                            HardenedValue = 4  # 4 = Disabled
                            DefaultValue  = 3  # 3 = Manual
                            GPOPath       = $null
                            GPOState      = $null
                            Caution       = 'May affect Microsoft Store app licensing and Microsoft 365.'
                        }
                    )
                }

                # -- Section: Network Connection Status Indicator --
                @{
                    Name        = 'Network Connection Status Indicator'
                    Description = 'Controls NCSI internet connectivity detection'
                    Settings    = @(
                        @{
                            Name          = 'Disable NCSI Active Tests'
                            Description   = 'Turns off active network connectivity status indicator tests'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator'
                            ValueName     = 'NoActiveProbe'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > Internet Communication Management > Internet Communication settings > Turn off Windows Network Connectivity Status Indicator active tests'
                            GPOState      = 'Enabled'
                            Warning       = 'Connectivity status reporting to apps and system services is disabled.'
                        }
                    )
                }

                # -- Section: Date & Time --
                @{
                    Name        = 'Date & Time'
                    Description = 'Controls automatic time synchronization'
                    Settings    = @(
                        @{
                            Name          = 'Set Time Sync to NoSync'
                            Description   = 'Prevents Windows from synchronizing time automatically'
                            Path          = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
                            ValueName     = 'Type'
                            ValueType     = 'String'
                            HardenedValue = 'NoSync'
                            DefaultValue  = 'NTP'
                            GPOPath       = $null
                            GPOState      = $null
                            Warning       = 'Time drift will cause TLS certificate failures and break TOTP 2FA.'
                        }
                        @{
                            Name          = 'Disable NTP Client'
                            Description   = 'Turns off the Windows NTP client time provider'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
                            ValueName     = 'Enabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > Windows Time Service > Time Providers > Enable Windows NTP Client'
                            GPOState      = 'Disabled'
                            Warning       = 'Time drift will cause TLS certificate failures and break TOTP 2FA.'
                        }
                    )
                }

                # -- Section: Windows SmartScreen --
                @{
                    Name        = 'Windows SmartScreen'
                    Description = 'Controls system-wide SmartScreen filtering'
                    Settings    = @(
                        @{
                            Name          = 'Disable SmartScreen'
                            Description   = 'Turns off Windows Defender SmartScreen'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'EnableSmartScreen'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Defender SmartScreen > Explorer > Configure Windows Defender SmartScreen'
                            GPOState      = 'Disabled'
                            Warning       = 'Removes Windows-wide malware and phishing protection for files and apps.'
                        }
                    )
                }

                # -- Section: Root Certificates --
                @{
                    Name        = 'Root Certificates'
                    Description = 'Controls automatic root certificate updates via Windows Update'
                    Settings    = @(
                        @{
                            Name          = 'Disable Automatic Root Certificate Updates'
                            Description   = 'Prevents automatic root certificate updates from Windows Update'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot'
                            ValueName     = 'DisableRootAutoUpdate'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > Internet Communication Management > Internet Communication settings > Turn off Automatic Root Certificates Update'
                            GPOState      = 'Enabled'
                            Warning       = 'Sites using root certificates not already on this device will fail TLS.'
                        }
                    )
                }

            ) # End Background Services Sections
        }

    ) # End Categories
}
