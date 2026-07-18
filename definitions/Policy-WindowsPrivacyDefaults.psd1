#
# windows-hardening
# https://github.com/briangeis/windows-hardening
#
# Policy Definitions: Windows Privacy Defaults
# Hardens Windows privacy and security defaults.
#
# Source:    Windows Policy CSP reference
# URL:       https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider
# Reference: definitions/reference/Policy-WindowsPrivacyDefaults.md
#
# Author:  Brian Geis
# License: GPL-3.0-or-later
#

@{
    Meta = @{
        Component   = 'Policy'
        Name        = 'Windows Privacy Defaults'
        Description = 'Hardens Windows privacy and security defaults.'
        Target      = 'Windows 11 25H2'
        Reviewed    = '2026-06-01'
    }

    Categories = @(

        # ===== Category: Telemetry & Reporting =====
        @{
            Name        = 'Telemetry & Reporting'
            Description = 'Settings controlling diagnostic data collection and telemetry reporting'
            Sections    = @(

                # -- Section: Diagnostic Data --
                @{
                    Name        = 'Diagnostic Data'
                    Description = 'Controls the volume and content of diagnostic data Windows collects'
                    Settings    = @(
                        @{
                            Name          = 'Exclude Device Name from Diagnostic Data'
                            Description   = 'Prevents the device name from being included in diagnostic data uploads'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                            ValueName     = 'AllowDeviceNameInTelemetry'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds > Allow device name to be sent in Windows diagnostic data'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Limit Diagnostic Log Collection'
                            Description   = 'Limits the amount of diagnostic log data Windows collects'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                            ValueName     = 'LimitDiagnosticLogCollection'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds > Limit Diagnostic Log Collection'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Limit Dump Collection'
                            Description   = 'Limits collection of memory dumps for diagnostic purposes'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                            ValueName     = 'LimitDumpCollection'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds > Limit Dump Collection'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Error Reporting --
                @{
                    Name        = 'Error Reporting'
                    Description = 'Controls Windows Error Reporting and crash data submission'
                    Settings    = @(
                        @{
                            Name          = 'Disable Windows Error Reporting'
                            Description   = 'Turns off Windows Error Reporting, blocking crash report submissions'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
                            ValueName     = 'Disabled'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Error Reporting > Disable Windows Error Reporting'
                            GPOState      = 'Enabled'
                            Note          = 'Removes crash analysis capability useful for diagnosing failures.'
                        }
                    )
                }

                # -- Section: Application Compatibility --
                @{
                    Name        = 'Application Compatibility'
                    Description = 'Controls telemetry and inventory collection for compatibility reporting'
                    Settings    = @(
                        @{
                            Name          = 'Disable Application Telemetry'
                            Description   = 'Turns off Application Impact Telemetry, which profiles app usage'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
                            ValueName     = 'AITEnable'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Application Compatibility > Turn off Application Telemetry'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Inventory Collector'
                            Description   = 'Turns off the compatibility inventory collector for installed programs'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
                            ValueName     = 'DisableInventory'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Application Compatibility > Turn off Inventory Collector'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Input Data --
                @{
                    Name        = 'Input Data'
                    Description = 'Controls inking and typing data transmission for recognition improvement'
                    Settings    = @(
                        @{
                            Name          = 'Disable Inking and Typing Data Collection'
                            Description   = 'Prevents inking and typing samples from being sent to Microsoft'
                            Path          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput'
                            ValueName     = 'AllowLinguisticDataCollection'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Text Input > Improve inking and typing recognition'
                            GPOState      = 'Disabled'
                        }
                    )
                }

            ) # End Telemetry & Reporting Sections
        }

        # ===== Category: Security Defaults =====
        @{
            Name        = 'Security Defaults'
            Description = 'Default Windows behaviors with security implications'
            Sections    = @(

                # -- Section: Removable Media --
                @{
                    Name        = 'Removable Media'
                    Description = 'Controls AutoPlay and AutoRun behavior for drives and devices'
                    Settings    = @(
                        @{
                            Name          = 'Disallow AutoPlay for Non-Volume Devices'
                            Description   = 'Prevents AutoPlay from running for non-volume devices such as phones'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                            ValueName     = 'NoAutoplayfornonVolume'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Disallow Autoplay for non-volume devices'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable AutoRun Command Execution'
                            Description   = 'Prevents AutoRun commands from executing when media is inserted'
                            Path          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                            ValueName     = 'NoAutorun'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Set the default behavior for AutoRun'
                            GPOState      = 'Enabled (Do not execute any AutoRun commands)'
                        }
                        @{
                            Name          = 'Disable AutoPlay'
                            Description   = 'Turns off AutoPlay for all drive types'
                            Path          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                            ValueName     = 'NoDriveTypeAutoRun'
                            ValueType     = 'DWord'
                            HardenedValue = 255  # 255 = All drive types
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Turn off Autoplay'
                            GPOState      = 'Enabled (All Drives)'
                        }
                    )
                }

                # -- Section: Network --
                @{
                    Name        = 'Network'
                    Description = 'Controls network-level name resolution privacy behaviors'
                    Settings    = @(
                        @{
                            Name          = 'Disable Multicast Name Resolution'
                            Description   = 'Prevents Windows from broadcasting LLMNR queries for name resolution'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
                            ValueName     = 'EnableMulticast'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution'
                            GPOState      = 'Enabled'
                            Note          = 'Relevant for devices that use a VPN or connect to untrusted networks.'
                        }
                        @{
                            Name          = 'Disable Smart Multi-Homed Name Resolution'
                            Description   = 'Prevents Windows from querying all active interfaces for name resolution'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
                            ValueName     = 'DisableSmartNameResolution'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Network > DNS Client > Turn off smart multi-homed name resolution'
                            GPOState      = 'Enabled'
                            Note          = 'Relevant for devices that use a VPN or have multiple active interfaces.'
                        }
                    )
                }

                # -- Section: Authentication & Lock Screen --
                @{
                    Name        = 'Authentication & Lock Screen'
                    Description = 'Controls sign-in, local account authentication defaults, and lock screen'
                    Settings    = @(
                        @{
                            Name          = 'Disable Lock Screen App Notifications'
                            Description   = 'Prevents app notification content from appearing on the lock screen'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'DisableLockScreenAppNotifications'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > Logon > Turn off app notifications on the lock screen'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Automatic Sign-In After Restart'
                            Description   = 'Prevents automatic sign-in of the last user after a restart'
                            Path          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                            ValueName     = 'DisableAutomaticRestartSignOn'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Logon Options > Sign-in and lock last interactive user automatically after a restart'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Local Account Security Questions'
                            Description   = 'Prevents security questions as a local account password reset method'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'NoLocalPasswordResetQuestions'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Credential User Interface > Prevent the use of security questions for local accounts'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Data at Rest --
                @{
                    Name        = 'Data at Rest'
                    Description = 'Controls features that write memory contents or sensitive data to disk'
                    Settings    = @(
                        @{
                            Name          = 'Disable Hibernation'
                            Description   = 'Turns off hibernation, which writes RAM contents to disk on shutdown'
                            Path          = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
                            ValueName     = 'HibernateEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = 1
                            GPOPath       = $null
                            GPOState      = $null
                            Note          = 'Run powercfg /H off separately to remove the existing hiberfile.sys.'
                        }
                        @{
                            Name          = 'Disable Fast Startup'
                            Description   = 'Turns off Fast Startup, which saves a partial kernel session on shutdown'
                            Path          = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
                            ValueName     = 'HiberbootEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = 1
                            GPOPath       = $null
                            GPOState      = $null
                            Caution       = 'Applying without Disable Hibernation may let Fast Startup re-activate.'
                        }
                        @{
                            Name          = 'Disable Indexing of Encrypted Files'
                            Description   = 'Prevents the indexer from caching decrypted content of encrypted files'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
                            ValueName     = 'AllowIndexingEncryptedStoresOrItems'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Search > Allow indexing of encrypted files'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Device Management --
                @{
                    Name        = 'Device Management'
                    Description = 'Controls remote device management enrollment capabilities'
                    Settings    = @(
                        @{
                            Name          = 'Disable MDM Enrollment'
                            Description   = 'Prevents this device from being enrolled in Mobile Device Management'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM'
                            ValueName     = 'DisableRegistration'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > MDM > Disable MDM Enrollment'
                            GPOState      = 'Enabled'
                        }
                    )
                }

            ) # End Security Defaults Sections
        }

        # ===== Category: Activity & History =====
        @{
            Name        = 'Activity & History'
            Description = 'Settings controlling activity records Windows maintains on this device'
            Sections    = @(

                # -- Section: Document & App History --
                @{
                    Name        = 'Document & App History'
                    Description = 'Controls tracking of recently opened documents and installed apps'
                    Settings    = @(
                        @{
                            Name          = 'Disable Recently Opened Document History'
                            Description   = 'Prevents Windows from tracking recently opened documents in jump lists'
                            Path          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                            ValueName     = 'NoRecentDocsHistory'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Start Menu and Taskbar > Do not keep history of recently opened documents'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Remove Recently Added List from Start Menu'
                            Description   = 'Removes the recently installed applications list from the Start menu'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                            ValueName     = 'HideRecentlyAddedApps'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Start Menu and Taskbar > Remove "Recently added" list from Start Menu'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Search & Explorer --
                @{
                    Name        = 'Search & Explorer'
                    Description = 'Controls search history and account-driven content in File Explorer'
                    Settings    = @(
                        @{
                            Name          = 'Disable File Explorer Search History'
                            Description   = 'Prevents the File Explorer search box from displaying recent searches'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                            ValueName     = 'DisableSearchBoxSuggestions'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > File Explorer > Turn off display of recent search entries in the File Explorer search box'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Search History'
                            Description   = 'Prevents past queries from being stored and shown as search suggestions'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                            ValueName     = 'DisableSearchHistory'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Search > Turn off storage and display of search history'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable File Explorer Account Insights'
                            Description   = 'Turns off account and cloud-based file recommendations in File Explorer'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                            ValueName     = 'DisableGraphRecentItems'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > File Explorer > Show files based on your account and cloud provider activity'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Clipboard --
                @{
                    Name        = 'Clipboard'
                    Description = 'Controls the local clipboard history feature'
                    Settings    = @(
                        @{
                            Name          = 'Disable Clipboard History'
                            Description   = 'Turns off clipboard history, a local store of recently copied items'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'AllowClipboardHistory'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > OS Policies > Allow Clipboard History'
                            GPOState      = 'Disabled'
                        }
                    )
                }

            ) # End Activity & History Sections
        }

        # ===== Category: Content Delivery =====
        @{
            Name        = 'Content Delivery'
            Description = 'Settings controlling what Windows delivers to this device automatically'
            Sections    = @(

                # -- Section: Cloud Content --
                @{
                    Name        = 'Cloud Content'
                    Description = 'Controls cloud-delivered tips, suggestions, and account-tailored content'
                    Settings    = @(
                        @{
                            Name          = 'Disable Windows Tips'
                            Description   = 'Prevents Windows from showing tips and suggestions to guide new users'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                            ValueName     = 'DisableSoftLanding'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Cloud Content > Do not show Windows tips'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Consumer Account State Content'
                            Description   = 'Prevents Windows from delivering account-tailored cloud content'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                            ValueName     = 'DisableConsumerAccountStateContent'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off cloud consumer account state content'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Spotlight --
                @{
                    Name        = 'Spotlight'
                    Description = 'Controls Windows 11 Spotlight surfaces not covered by the global disable'
                    Settings    = @(
                        @{
                            Name          = 'Disable Spotlight Collection on Desktop'
                            Description   = 'Turns off the Spotlight rotating image collection on the desktop'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                            ValueName     = 'DisableSpotlightCollectionOnDesktop'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off Spotlight collection on Desktop'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Windows Welcome Experience'
                            Description   = 'Turns off the fullscreen Windows Welcome Experience shown after updates'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                            ValueName     = 'DisableWindowsSpotlightWindowsWelcomeExperience'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off the Windows Welcome Experience'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Spotlight on Action Center'
                            Description   = 'Turns off Windows Spotlight suggestions in the Action Center'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                            ValueName     = 'DisableWindowsSpotlightOnActionCenter'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off Windows Spotlight on Action Center'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Spotlight on Settings'
                            Description   = 'Turns off Windows Spotlight suggestions embedded within Settings pages'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                            ValueName     = 'DisableWindowsSpotlightOnSettings'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off Windows Spotlight on Settings'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Search --
                @{
                    Name        = 'Search'
                    Description = 'Controls search behavior that connects to Microsoft services'
                    Settings    = @(
                        @{
                            Name          = 'Disable Search Highlights'
                            Description   = 'Prevents curated content and trending suggestions in the Search panel'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
                            ValueName     = 'EnableDynamicContentInWSB'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Search > Allow search highlights'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Cloud Search'
                            Description   = 'Prevents Windows Search from querying cloud sources such as OneDrive'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
                            ValueName     = 'AllowCloudSearch'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Search > Allow Cloud Search'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: App Delivery --
                @{
                    Name        = 'App Delivery'
                    Description = 'Controls remote and silent application installation channels'
                    Settings    = @(
                        @{
                            Name          = 'Disable Push To Install Service'
                            Description   = 'Turns off the service allowing apps to be pushed remotely to this device'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall'
                            ValueName     = 'DisablePushToInstall'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Push To Install > Turn off Push To Install service'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Account Notifications --
                @{
                    Name        = 'Account Notifications'
                    Description = 'Controls Microsoft account notifications delivered to the Start menu'
                    Settings    = @(
                        @{
                            Name          = 'Disable Account Notifications in Start'
                            Description   = 'Prevents Microsoft account notifications and prompts in the Start menu'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AccountNotifications'
                            ValueName     = 'DisableAccountNotifications'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Account Notifications > Turn off account notifications in Start'
                            GPOState      = 'Enabled'
                        }
                    )
                }

            ) # End Content Delivery Sections
        }

        # ===== Category: Windows Update =====
        @{
            Name        = 'Windows Update'
            Description = 'Settings controlling Windows Update behavior and delivery on this device'
            Sections    = @(

                # -- Section: Update Behavior --
                @{
                    Name        = 'Update Behavior'
                    Description = 'Controls timing and content of Windows Update downloads and installs'
                    Settings    = @(
                        @{
                            Name          = 'Disable Automatic Windows Update'
                            Description   = 'Sets Windows Update to manual mode, requiring explicit update checks'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
                            ValueName     = 'NoAutoUpdate'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage end user experience > Configure Automatic Updates'
                            GPOState      = 'Disabled'
                            Caution       = 'Users who do not check for updates regularly will miss security patches.'
                        }
                        @{
                            Name          = 'Exclude Driver Updates from Windows Update'
                            Description   = 'Prevents Windows Update from including driver updates in regular updates'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                            ValueName     = 'ExcludeWUDriversInQualityUpdate'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage updates offered from Windows Update > Do not include drivers with Windows Update'
                            GPOState      = 'Enabled'
                        }
                    )
                }

            ) # End Windows Update Sections
        }

        # ===== Category: Windows Applications =====
        @{
            Name        = 'Windows Applications'
            Description = 'Privacy and network access settings for Windows built-in applications'
            Sections    = @(

                # -- Section: Windows AI --
                @{
                    Name        = 'Windows AI'
                    Description = 'Controls AI features introduced in Windows 11 23H2 and later'
                    Settings    = @(
                        @{
                            Name          = 'Disable Windows Copilot'
                            Description   = 'Turns off the Windows Copilot panel introduced in Windows 11 23H2'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
                            ValueName     = 'TurnOffWindowsCopilot'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Windows Copilot > Turn off Windows Copilot'
                            GPOState      = 'Enabled'
                            Note          = 'Deprecated in 24H2 where Copilot was moved to a standalone Store app.'
                        }
                        @{
                            Name          = 'Disable Recall'
                            Description   = 'Prevents Recall from being enabled on this device'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
                            ValueName     = 'AllowRecallEnablement'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows AI > Allow Recall to be enabled'
                            GPOState      = 'Disabled'
                            Note          = 'Recall requires Copilot+ PC hardware and has no effect on other devices.'
                        }
                        @{
                            Name          = 'Disable Click to Do'
                            Description   = 'Turns off Click to Do, which analyzes screen content for AI actions'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
                            ValueName     = 'DisableClickToDo'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows AI > Disable Click to Do'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Settings Agentic Search'
                            Description   = 'Turns off the AI-powered natural language search in the Settings app'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
                            ValueName     = 'DisableSettingsAgent'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows AI > Disable Settings agentic search experience'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Phone Link --
                @{
                    Name        = 'Phone Link'
                    Description = 'Controls the Phone Link connection between this device and a phone'
                    Settings    = @(
                        @{
                            Name          = 'Disable Phone-PC Linking'
                            Description   = 'Prevents Phone Link from connecting this device to a paired phone'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
                            ValueName     = 'EnableMmx'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > System > Group Policy > Phone-PC linking on this device'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Game Recording --
                @{
                    Name        = 'Game Recording'
                    Description = 'Controls the Windows game recording and broadcasting feature'
                    Settings    = @(
                        @{
                            Name          = 'Disable Game Recording and Broadcasting'
                            Description   = 'Turns off Game DVR capture and broadcasting within Windows Game Bar'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
                            ValueName     = 'AllowGameDVR'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Game Recording and Broadcasting > Enables or disables Windows Game Recording and Broadcasting'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Windows Media Player --
                @{
                    Name        = 'Windows Media Player'
                    Description = 'Controls network access by Windows Media Player for metadata and DRM'
                    Settings    = @(
                        @{
                            Name          = 'Disable Windows Media DRM Internet Access'
                            Description   = 'Prevents Windows Media DRM clients from going online to acquire licenses'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\WMDRM'
                            ValueName     = 'DisableOnline'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Windows Components > Windows Media Digital Rights Management > Prevent Windows Media DRM Internet Access'
                            GPOState      = 'Enabled'
                            Caution       = 'Protected content requiring a new DRM license will not play.'
                        }
                        @{
                            Name          = 'Disable CD and DVD Media Information Retrieval'
                            Description   = 'Prevents Windows Media Player from retrieving CD and DVD metadata online'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
                            ValueName     = 'PreventCDDVDMetadataRetrieval'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Windows Media Player > Prevent CD and DVD Media Information Retrieval'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Music File Media Information Retrieval'
                            Description   = 'Prevents Windows Media Player from retrieving music file metadata online'
                            Path          = 'HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
                            ValueName     = 'PreventMusicFileMetadataRetrieval'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'User Configuration > Administrative Templates > Windows Components > Windows Media Player > Prevent Music File Media Information Retrieval'
                            GPOState      = 'Enabled'
                        }
                    )
                }

            ) # End Windows Applications Sections
        }

    ) # End Categories
}
