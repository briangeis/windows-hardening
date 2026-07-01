#
# windows-hardening
# https://github.com/briangeis/windows-hardening
#
# Policy Definitions: Edge
# Hardens the Microsoft Edge browser.
#
# Source:    Microsoft Edge policy reference
# URL:       https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies
# Reference: definitions/reference/Policy-Edge.md
#
# Author:  Brian Geis
# License: GPL-3.0-or-later
#

@{
    Meta = @{
        Component   = 'Policy'
        Name        = 'Edge'
        Description = 'Hardens the Microsoft Edge browser.'
        Target      = 'Microsoft Edge 148'
        Reviewed    = '2026-06-01'
    }

    Categories = @(

        # ===== Category: Privacy & Telemetry =====
        @{
            Name        = 'Privacy & Telemetry'
            Description = 'Settings controlling what Edge sends to Microsoft'
            Sections    = @(

                # -- Section: Diagnostic Data --
                @{
                    Name        = 'Diagnostic Data'
                    Description = 'Controls diagnostic data and browser usage reporting to Microsoft'
                    Settings    = @(
                        @{
                            Name          = 'Disable Browser Diagnostic Data'
                            Description   = 'Sets diagnostic data collection to Off'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DiagnosticData'
                            ValueType     = 'DWord'
                            HardenedValue = 0  # 0 = Off
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Send required and optional diagnostic data about browser usage'
                            GPOState      = 'Enabled (Off)'
                            Note          = 'Microsoft marks the Off setting as not recommended.'
                        }
                        @{
                            Name          = 'Disable URL Reporting in Diagnostic Data'
                            Description   = 'Excludes URLs from Edge crash and diagnostic reports'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'UrlDiagnosticDataEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > URL reporting in Edge diagnostic data enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Edge 3P SERP Telemetry'
                            Description   = 'Turns off telemetry for third-party search engine result pages'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'Edge3PSerpTelemetryEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Edge 3P SERP Telemetry Enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable DNS Interception Checks'
                            Description   = 'Turns off network probes used to detect DNS interception'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DNSInterceptionChecksEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > DNS interception checks enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable User Feedback'
                            Description   = 'Prevents users from submitting feedback to Microsoft through Edge'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'UserFeedbackAllowed'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow user feedback'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Personalization & Profiling --
                @{
                    Name        = 'Personalization & Profiling'
                    Description = 'Controls personalization data and cloud-delivered content in Edge'
                    Settings    = @(
                        @{
                            Name          = 'Disable Personalization Reporting'
                            Description   = 'Prevents browsing data from being sent to Microsoft for personalization'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'PersonalizationReportingEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow personalization of ads, Microsoft Edge, search, news and other Microsoft services by sending browsing history, favorites and collections, usage and other browsing data to Microsoft'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Asset Delivery Service'
                            Description   = 'Prevents Edge from downloading dynamic content from Microsoft'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EdgeAssetDeliveryServiceEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow features to download assets from the Asset Delivery Service'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable AI Theme Generation'
                            Description   = 'Turns off AI-generated browser themes powered by DALL-E'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AIGenThemesEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enables DALL-E themes generation'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Tracking Prevention --
                @{
                    Name        = 'Tracking Prevention'
                    Description = 'Controls tracking prevention, cookie blocking, and Do Not Track'
                    Settings    = @(
                        @{
                            Name          = 'Enable Strict Tracking Prevention'
                            Description   = 'Sets tracking prevention to Strict mode'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'TrackingPrevention'
                            ValueType     = 'DWord'
                            HardenedValue = 3  # 3 = Strict
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Block tracking of users'' web-browsing activity'
                            GPOState      = 'Enabled (Strict)'
                            Note          = 'Strict mode may cause some sites to break due to tracker blocking.'
                        }
                        @{
                            Name          = 'Block Third Party Cookies'
                            Description   = 'Prevents third-party cookies from being set'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'BlockThirdPartyCookies'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Block third party cookies'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Enable Do Not Track'
                            Description   = 'Sends Do Not Track requests with browsing traffic'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ConfigureDoNotTrack'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Configure Do Not Track'
                            GPOState      = 'Enabled'
                            Note          = 'Most websites do not honor Do Not Track requests.'
                        }
                    )
                }

                # -- Section: Copilot & AI Data Access --
                @{
                    Name        = 'Copilot & AI Data Access'
                    Description = 'Controls what Microsoft AI services can access in the browser'
                    Settings    = @(
                        @{
                            Name          = 'Disable Browsing with Copilot'
                            Description   = 'Turns off Copilot access to the browser and browsing context'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AllowBrowsingWithCopilot'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Controls the availability of browsing with Copilot in Microsoft Edge.'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Copilot Toolbar Button'
                            Description   = 'Removes the Microsoft 365 Copilot Chat button from the toolbar'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'Microsoft365CopilotChatIconEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Control whether Microsoft 365 Copilot Chat shows in the Microsoft Edge for Business toolbar'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Copilot Page Context Access'
                            Description   = 'Prevents Copilot from accessing the content of the current page'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'CopilotPageContext'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Control Copilot access to page context for Microsoft Entra ID profiles'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Built-In AI APIs for Pages'
                            Description   = 'Prevents web pages from accessing the built-in AI APIs in Edge'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'BuiltInAIAPIsEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow pages to use the built-in AI APIs.'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Browsing History Sharing with Copilot Search'
                            Description   = 'Prevents browsing history from being shared with Copilot Search'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ShareBrowsingHistoryWithCopilotSearchAllowed'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow sharing tenant-approved browsing history with Microsoft 365 Copilot Search'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable AI-Enhanced History Search'
                            Description   = 'Turns off AI-powered analysis of browsing history'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EdgeHistoryAISearchEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Control access to AI-enhanced search in History'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Experimentation --
                @{
                    Name        = 'Experimentation'
                    Description = 'Controls remote configuration and feature experiment programs'
                    Settings    = @(
                        @{
                            Name          = 'Disable Experimentation Service'
                            Description   = 'Turns off all communication with the Experimentation service'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ExperimentationAndConfigurationServiceControl'
                            ValueType     = 'DWord'
                            HardenedValue = 0  # 0 = Restricted Mode
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Control communication with the Experimentation and Configuration Service'
                            GPOState      = 'Enabled (Restricted Mode)'
                            Note          = 'Prevents Microsoft from pushing remote configuration changes to Edge.'
                        }
                        @{
                            Name          = 'Disable Edge Update Experimentation Service'
                            Description   = 'Prevents Microsoft from pushing configuration to the Edge Update service'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
                            ValueName     = 'UpdaterExperimentationAndConfigurationServiceControl'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge Update > Control updater''s communication with the Experimentation and Configuration Service'
                            GPOState      = 'Enabled (0)'
                        }
                        @{
                            Name          = 'Disable WebView2 Experimentation Service'
                            Description   = 'Prevents Microsoft from pushing configuration to the WebView2 runtime'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebView2'
                            ValueName     = 'ExperimentationAndConfigurationServiceControl'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge WebView2 > Control communication with the Experimentation and Configuration Service'
                            GPOState      = 'Enabled (0)'
                        }
                        @{
                            Name          = 'Prevent Feature Flag Overrides'
                            Description   = 'Prevents users from overriding experimental feature flags'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'FeatureFlagOverridesControl'
                            ValueType     = 'DWord'
                            HardenedValue = 0  # 0 = Overrides Disabled
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Experimentation > Configure users ability to override feature flags'
                            GPOState      = 'Enabled (Overrides Disabled)'
                        }
                    )
                }

            ) # End Privacy & Telemetry Sections
        }

        # ===== Category: Identity & Data =====
        @{
            Name        = 'Identity & Data'
            Description = 'Settings controlling what Edge knows about user identity and activity'
            Sections    = @(

                # -- Section: Sign-In & Sync --
                @{
                    Name        = 'Sign-In & Sync'
                    Description = 'Controls browser sign-in, Microsoft account sync, and SSO features'
                    Settings    = @(
                        @{
                            Name          = 'Disable Browser Sign-In'
                            Description   = 'Prevents users from signing in to the browser with a Microsoft account'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'BrowserSignin'
                            ValueType     = 'DWord'
                            HardenedValue = 0  # 0 = Disable browser sign-in
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Browser sign-in settings'
                            GPOState      = 'Enabled (Disable browser sign-in)'
                        }
                        @{
                            Name          = 'Disable Microsoft Sync'
                            Description   = 'Prevents synchronization of browsing data to Microsoft cloud services'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SyncDisabled'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Disable synchronization of data using Microsoft sync services'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Work Account SSO for Websites'
                            Description   = 'Prevents automatic sign-in to work and school websites via this profile'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AADWebSiteSSOUsingThisProfileEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Single sign-on for work or school sites using this profile enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Microsoft Personal Account SSO'
                            Description   = 'Prevents automatic sign-in to Microsoft personal sites via this profile'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'MSAWebSiteSSOUsingThisProfileAllowed'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow single sign-on for Microsoft personal sites using this profile'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Guided Profile Switch'
                            Description   = 'Prevents Edge from prompting users to switch profiles for specific sites'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'GuidedSwitchEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Identity and sign-in > Guided Switch Enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Seamless Web-to-Browser Sign-In'
                            Description   = 'Prevents websites from silently signing the user into the browser'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SeamlessWebToBrowserSignInEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Identity and sign-in > Seamless Web To Browser Sign-in Enabled'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Autofill & Credentials --
                @{
                    Name        = 'Autofill & Credentials'
                    Description = 'Controls browser-managed credentials, autofill forms, and payment data'
                    Settings    = @(
                        @{
                            Name          = 'Disable Password Manager'
                            Description   = 'Prevents Edge from saving passwords to the built-in password manager'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'PasswordManagerEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Password manager and protection > Enable saving passwords to the password manager'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Password Autofill'
                            Description   = 'Sets the password manager autofill mode to Off'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'PrimaryPasswordSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 3  # 3 = Autofill Off
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Password manager and protection > Configures a setting that asks users to enter their device password while using password autofill'
                            GPOState      = 'Enabled (Autofill Off)'
                            Note          = 'Only applies when the password manager is enabled.'
                        }
                        @{
                            Name          = 'Disable Payment Autofill'
                            Description   = 'Turns off AutoFill for payment instruments'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AutofillCreditCardEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable AutoFill for payment instruments'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Payment Method Query'
                            Description   = 'Prevents websites from checking for available payment methods'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'PaymentMethodQueryEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow websites to query for available payment methods'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Address Autofill'
                            Description   = 'Turns off AutoFill for addresses'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AutofillAddressEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable AutoFill for addresses'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Membership Autofill'
                            Description   = 'Turns off AutoFill for loyalty cards and membership IDs'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AutofillMembershipsEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Save and fill memberships'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Import Settings --
                @{
                    Name        = 'Import Settings'
                    Description = 'Controls automatic imports from other browsers at first run and launch'
                    Settings    = @(
                        @{
                            Name          = 'Disable First-Run Auto-Import'
                            Description   = 'Prevents automatic data import from other browsers at first launch'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AutoImportAtFirstRun'
                            ValueType     = 'DWord'
                            HardenedValue = 4  # 4 = Disabled Auto Import
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Automatically import another browser''s data and settings at first run'
                            GPOState      = 'Enabled (Disabled Auto Import)'
                        }
                        @{
                            Name          = 'Disable Repeated Imports on Launch'
                            Description   = 'Prevents re-importing data from other browsers on every Edge launch'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ImportOnEachLaunch'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow import of data from other browsers on each Microsoft Edge launch'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Import of Saved Passwords'
                            Description   = 'Prevents importing saved passwords from other browsers'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ImportSavedPasswords'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow importing of saved passwords'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Import of Payment Info'
                            Description   = 'Prevents importing payment information from other browsers'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ImportPaymentInfo'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow importing of payment info'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Import of Autofill Data'
                            Description   = 'Prevents importing autofill form data from other browsers'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ImportAutofillFormData'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow importing of autofill form data'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Import of Browser Settings'
                            Description   = 'Prevents importing browser settings from other browsers'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ImportBrowserSettings'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow importing of browser settings'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Import of Home Page Settings'
                            Description   = 'Prevents importing home page settings from other browsers'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ImportHomepage'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow importing of home page settings'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Import of Search Engine Settings'
                            Description   = 'Prevents importing search engine settings from other browsers'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ImportSearchEngine'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow importing of search engine settings'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Browsing Data --
                @{
                    Name        = 'Browsing Data'
                    Description = 'Controls browsing data retention, deletion on exit, and history'
                    Settings    = @(
                        @{
                            Name          = 'Clear Browsing Data on Exit'
                            Description   = 'Deletes all browsing data each time Edge closes'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ClearBrowsingDataOnExit'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Clear browsing data when Microsoft Edge closes'
                            GPOState      = 'Enabled'
                            Note          = 'Logs the user out of all websites by clearing cookies on every close.'
                        }
                        @{
                            Name          = 'Clear Cached Images on Exit'
                            Description   = 'Deletes cached images and files each time Edge closes'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ClearCachedImagesAndFilesOnExit'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Clear cached images and files when Microsoft Edge closes'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Saving Browser History'
                            Description   = 'Prevents Edge from saving browsing history'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SavingBrowserHistoryDisabled'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Disable saving browser history'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Delete Browser Data on Migration'
                            Description   = 'Removes legacy browser data when migrating to a new Edge version'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DeleteDataOnMigration'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Delete old browser data on migration'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Windows Search Access to Edge Data'
                            Description   = 'Prevents Windows Search from indexing local Edge browsing data'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'LocalBrowserDataShareEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable Windows to search local Microsoft Edge browsing data'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Ephemeral Profiles --
                @{
                    Name        = 'Ephemeral Profiles'
                    Description = 'Controls whether Edge uses a temporary profile deleted on close'
                    Settings    = @(
                        @{
                            Name          = 'Enable Ephemeral Profiles'
                            Description   = 'Uses a temporary profile directory that is deleted when Edge closes'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ForceEphemeralProfiles'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable use of ephemeral profiles'
                            GPOState      = 'Enabled'
                            Warning       = 'All profile data deleted on close: bookmarks, extensions, and settings.'
                        }
                    )
                }

            ) # End Identity & Data Sections
        }

        # ===== Category: Security =====
        @{
            Name        = 'Security'
            Description = 'Settings hardening browser security and web content access controls'
            Sections    = @(

                # -- Section: SmartScreen --
                @{
                    Name        = 'SmartScreen'
                    Description = 'Controls Microsoft Defender SmartScreen and scareware protection'
                    Settings    = @(
                        @{
                            Name          = 'Disable Microsoft Defender SmartScreen'
                            Description   = 'Turns off Microsoft Defender SmartScreen URL and download checking'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SmartScreenEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > SmartScreen settings > Configure Microsoft Defender SmartScreen'
                            GPOState      = 'Disabled'
                            Caution       = 'Removes phishing and malware protection from Microsoft Edge.'
                        }
                        @{
                            Name          = 'Disable SmartScreen Checks for Trusted Downloads'
                            Description   = 'Turns off SmartScreen reputation checks on trusted source downloads'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SmartScreenForTrustedDownloadsEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > SmartScreen settings > Force Microsoft Defender SmartScreen checks on downloads from trusted sources'
                            GPOState      = 'Disabled'
                            Caution       = 'Removes SmartScreen reputation checks on downloads from trusted sources.'
                        }
                        @{
                            Name          = 'Disable SmartScreen PUA Protection'
                            Description   = 'Turns off SmartScreen protection against potentially unwanted apps'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SmartScreenPuaEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > SmartScreen settings > Configure Microsoft Defender SmartScreen to block potentially unwanted apps'
                            GPOState      = 'Disabled'
                            Caution       = 'Removes PUA protection from SmartScreen download checks.'
                        }
                        @{
                            Name          = 'Disable SmartScreen DNS Requests'
                            Description   = 'Turns off DNS-based URL lookups performed by SmartScreen'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SmartScreenDnsRequestsEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > SmartScreen settings > Enable Microsoft Defender SmartScreen DNS requests'
                            GPOState      = 'Disabled'
                            Caution       = 'Removes DNS-based threat detection from SmartScreen URL checks.'
                        }
                        @{
                            Name          = 'Disable Scareware Blocker'
                            Description   = 'Turns off the on-device tech support scam page detection feature'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ScarewareBlockerProtectionEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Scareware Blocker settings > Configure Microsoft Edge Scareware blocker protection'
                            GPOState      = 'Disabled'
                            Caution       = 'Removes protection against tech support scam and browser-lock pages.'
                        }
                    )
                }

                # -- Section: Process & Memory Protection --
                @{
                    Name        = 'Process & Memory Protection'
                    Description = 'Controls browser security mode, process isolation, and memory protection'
                    Settings    = @(
                        @{
                            Name          = 'Enable Strict Enhanced Security Mode'
                            Description   = 'Enables Enhanced Security Mode at Strict level for maximum hardening'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EnhanceSecurityMode'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Strict Mode
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enhance the security state in Microsoft Edge'
                            GPOState      = 'Enabled (Strict Mode)'
                            Caution       = 'Strict mode may affect site compatibility due to enhanced mitigations.'
                        }
                        @{
                            Name          = 'Enable Site Isolation'
                            Description   = 'Isolates each site in a dedicated process to prevent cross-site leaks'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SitePerProcess'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable site isolation for every site'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Enable Browser Code Integrity'
                            Description   = 'Enforces code integrity guard in the browser process'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'BrowserCodeIntegritySetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Enforcement Mode
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Configure browser process code integrity guard setting'
                            GPOState      = 'Enabled (Enforcement)'
                        }
                        @{
                            Name          = 'Enable Dynamic Code Protection'
                            Description   = 'Prevents the browser process from creating dynamic code'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DynamicCodeSettings'
                            ValueType     = 'DWord'
                            HardenedValue = 1  # 1 = Enabled for Browser Process
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Dynamic Code Settings'
                            GPOState      = 'Enabled (Enabled for Browser)'
                        }
                        @{
                            Name          = 'Block External Extensions'
                            Description   = 'Blocks installation of extensions via sideloading mechanisms'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'BlockExternalExtensions'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Extensions > Blocks external extensions from being installed'
                            GPOState      = 'Enabled'
                            Note          = 'Does not prevent extensions installed from the Edge Add-ons store.'
                        }
                        @{
                            Name          = 'Enable Network Service Sandbox'
                            Description   = 'Sandboxes the network service to limit browser process system access'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'NetworkServiceSandboxEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable the network service sandbox'
                            GPOState      = 'Enabled'
                        }
                    )
                }

                # -- Section: Content Security --
                @{
                    Name        = 'Content Security'
                    Description = 'Controls security restrictions on content execution and rendering'
                    Settings    = @(
                        @{
                            Name          = 'Block JavaScript JIT'
                            Description   = 'Turns off JavaScript JIT compilation to reduce memory attack risk'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultJavaScriptJitSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Block JIT
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Content settings > Control use of JavaScript JIT'
                            GPOState      = 'Enabled (Do not allow)'
                            Caution       = 'Disabling JIT may reduce performance on JavaScript-heavy sites.'
                        }
                        @{
                            Name          = 'Block Insecure Content Exceptions'
                            Description   = 'Prevents exceptions that would allow mixed content on HTTPS pages'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultInsecureContentSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Do Not Allow
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Content settings > Control use of insecure content exceptions'
                            GPOState      = 'Enabled (Do not allow)'
                            Note          = 'May block HTTP resources on HTTPS admin pages for local network devices.'
                        }
                        @{
                            Name          = 'Disable Internet Explorer Mode'
                            Description   = 'Turns off IE mode, preventing the Trident rendering engine from loading'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'InternetExplorerIntegrationLevel'
                            ValueType     = 'DWord'
                            HardenedValue = 0  # 0 = None
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Configure Internet Explorer integration'
                            GPOState      = 'Enabled (None)'
                        }
                    )
                }

                # -- Section: Connection Security --
                @{
                    Name        = 'Connection Security'
                    Description = 'Controls how Edge establishes and secures network connections'
                    Settings    = @(
                        @{
                            Name          = 'Require OCSP/CRL Checks for Local Trust Anchors'
                            Description   = 'Enforces online OCSP and CRL checks for locally trusted certificates'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'RequireOnlineRevocationChecksForLocalAnchors'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Specify if online OCSP/CRL checks are required for local trust anchors'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Enable Encrypted Client Hello'
                            Description   = 'Encrypts the TLS ClientHello SNI field to reduce network-level tracking'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EncryptedClientHelloEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > TLS Encrypted ClientHello Enabled'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Disable Basic Authentication over HTTP'
                            Description   = 'Prevents Basic authentication over plain HTTP connections'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'BasicAuthOverHttpEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > HTTP authentication > Allow Basic authentication for HTTP'
                            GPOState      = 'Disabled'
                            Note          = 'Basic authentication transmits credentials in plain text.'
                        }
                        @{
                            Name          = 'Disable Network Prediction'
                            Description   = 'Prevents speculative DNS, connection, and page prerender requests'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'NetworkPredictionOptions'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Do not predict network actions
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable network prediction'
                            GPOState      = 'Enabled (Do not predict network actions)'
                            Note          = 'May slightly slow page loads by disabling preconnect and prerender.'
                        }
                    )
                }

            ) # End Security Sections
        }

        # ===== Category: Content Permissions =====
        @{
            Name        = 'Content Permissions'
            Description = 'Settings controlling what websites can access on this device'
            Sections    = @(

                # -- Section: Media Capture --
                @{
                    Name        = 'Media Capture'
                    Description = 'Controls media capture access including audio, video, and screen'
                    Settings    = @(
                        @{
                            Name          = 'Block Audio Capture'
                            Description   = 'Prevents websites from accessing the microphone by default'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AudioCaptureAllowed'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow or block audio capture'
                            GPOState      = 'Disabled'
                            Caution       = 'Blocks every site from the microphone, breaking web conferencing.'
                        }
                        @{
                            Name          = 'Block Video Capture'
                            Description   = 'Prevents websites from accessing the camera by default'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'VideoCaptureAllowed'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow or block video capture'
                            GPOState      = 'Disabled'
                            Caution       = 'Blocks every site from the camera, breaking video conferencing.'
                        }
                        @{
                            Name          = 'Block Screen Capture'
                            Description   = 'Prevents websites from capturing screen content by default'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ScreenCaptureAllowed'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow or deny screen capture'
                            GPOState      = 'Disabled'
                            Caution       = 'Blocks every site from screen capture, breaking screen sharing.'
                        }
                    )
                }

                # -- Section: Sensors & Location --
                @{
                    Name        = 'Sensors & Location'
                    Description = 'Controls website access to device location and environmental sensors'
                    Settings    = @(
                        @{
                            Name          = 'Block Geolocation Access'
                            Description   = 'Prevents websites from accessing location data by default'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultGeolocationSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Do Not Allow
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Content settings > Default geolocation setting'
                            GPOState      = 'Enabled (Do not allow)'
                        }
                        @{
                            Name          = 'Block Sensor Access'
                            Description   = 'Prevents websites from accessing device sensors by default'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultSensorsSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Do Not Allow
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Default sensors setting'
                            GPOState      = 'Enabled (Do not allow)'
                        }
                    )
                }

                # -- Section: Hardware APIs --
                @{
                    Name        = 'Hardware APIs'
                    Description = 'Controls website access to hardware interfaces via browser APIs'
                    Settings    = @(
                        @{
                            Name          = 'Block Serial API Access'
                            Description   = 'Prevents websites from accessing serial port devices by default'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultSerialGuardSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Do Not Allow
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Control use of the Serial API'
                            GPOState      = 'Enabled (Do not allow)'
                        }
                        @{
                            Name          = 'Block Web Bluetooth Access'
                            Description   = 'Prevents websites from accessing Bluetooth devices by default'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultWebBluetoothGuardSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Do Not Allow
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Content settings > Control use of the Web Bluetooth API'
                            GPOState      = 'Enabled (Do not allow)'
                        }
                        @{
                            Name          = 'Block WebHID Access'
                            Description   = 'Prevents websites from accessing HID devices by default'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultWebHidGuardSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Do Not Allow
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Content settings > Control use of the WebHID API'
                            GPOState      = 'Enabled (Do not allow)'
                        }
                        @{
                            Name          = 'Block WebUSB Access'
                            Description   = 'Prevents websites from accessing USB devices by default'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultWebUsbGuardSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Do Not Allow
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Content settings > Control use of the WebUSB API'
                            GPOState      = 'Enabled (Do not allow)'
                        }
                    )
                }

                # -- Section: Files & Storage --
                @{
                    Name        = 'Files & Storage'
                    Description = 'Controls website access to local files, automatic downloads, and storage'
                    Settings    = @(
                        @{
                            Name          = 'Block File System API (Read)'
                            Description   = 'Prevents websites from reading local files via the File System API'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultFileSystemReadGuardSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Do Not Allow
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Content settings > Control use of the File System API for reading'
                            GPOState      = 'Enabled (Do not allow)'
                        }
                        @{
                            Name          = 'Block File System API (Write)'
                            Description   = 'Prevents websites from writing to local files via the File System API'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultFileSystemWriteGuardSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Do Not Allow
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Content settings > Control use of the File System API for writing'
                            GPOState      = 'Enabled (Do not allow)'
                        }
                        @{
                            Name          = 'Block Automatic Downloads'
                            Description   = 'Prevents websites from performing automatic multiple file downloads'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultAutomaticDownloadsSetting'
                            ValueType     = 'DWord'
                            HardenedValue = 2  # 2 = Block Automatic Downloads
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Content settings > Default automatic downloads setting'
                            GPOState      = 'Enabled (Block Automatic Downloads)'
                        }
                    )
                }

                # -- Section: WebRTC --
                @{
                    Name        = 'WebRTC'
                    Description = 'Controls WebRTC behavior and local network address exposure'
                    Settings    = @(
                        @{
                            Name          = 'Restrict WebRTC Local IP Exposure'
                            Description   = 'Prevents WebRTC from exposing the local IP address to websites'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'WebRtcLocalhostIpHandling'
                            ValueType     = 'String'
                            HardenedValue = 'default_public_interface_only'
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > WebRtc settings > Restrict exposure of local IP address by WebRTC'
                            GPOState      = 'Enabled (Allow Public Interface Only)'
                            Note          = 'Prevents WebRTC from leaking the real IP address through a VPN tunnel.'
                        }
                    )
                }

            ) # End Content Permissions Sections
        }

        # ===== Category: Microsoft Features =====
        @{
            Name        = 'Microsoft Features'
            Description = 'Settings controlling Microsoft cloud service integrations in Edge'
            Sections    = @(

                # -- Section: AI & Cloud Services --
                @{
                    Name        = 'AI & Cloud Services'
                    Description = 'Controls Microsoft AI services and cloud-powered features in Edge'
                    Settings    = @(
                        @{
                            Name          = 'Disable Translate'
                            Description   = 'Turns off the built-in page translation service'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'TranslateEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable Translate'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Online Text-to-Speech'
                            Description   = 'Turns off cloud-powered text-to-speech in Edge'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ConfigureOnlineTextToSpeech'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Configure Online Text To Speech'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Speech Recognition'
                            Description   = 'Turns off web speech recognition in Edge'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SpeechRecognitionEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Configure Speech Recognition'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Live Captions'
                            Description   = 'Prevents live caption generation from audio and video content'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'LiveCaptionsAllowed'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Live captions allowed'
                            GPOState      = 'Disabled'
                            Note          = 'Removes live captions, an accessibility aid for audio and video.'
                        }
                        @{
                            Name          = 'Disable Microsoft Editor Spell Check'
                            Description   = 'Turns off the Microsoft Editor cloud-powered spell checker'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'MicrosoftEditorProofingEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Spell checking provided by Microsoft Editor'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Microsoft Editor Synonyms'
                            Description   = 'Turns off synonym suggestions from Microsoft Editor'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'MicrosoftEditorSynonymsEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Synonyms are provided when using Microsoft Editor spell checker'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Tab Organization Suggestions'
                            Description   = 'Turns off AI-powered tab grouping suggestions'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'TabServicesEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable tab organization suggestions'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Image Descriptions from Microsoft'
                            Description   = 'Prevents screen readers from fetching image descriptions from Microsoft'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AccessibilityImageLabelsEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Let screen reader users get image descriptions from Microsoft'
                            GPOState      = 'Disabled'
                            Note          = 'Screen readers lose Microsoft-provided descriptions for images.'
                        }
                    )
                }

                # -- Section: Sidebar & Collaboration --
                @{
                    Name        = 'Sidebar & Collaboration'
                    Description = 'Controls the Edge sidebar, sharing, and collaborative features'
                    Settings    = @(
                        @{
                            Name          = 'Disable Hubs Sidebar'
                            Description   = 'Turns off the Hubs sidebar that integrates Microsoft services'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'HubsSidebarEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Show Hubs Sidebar'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Standalone Sidebar'
                            Description   = 'Turns off the standalone sidebar feature in Edge'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'StandaloneHubsSidebarEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Standalone Sidebar Enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Collections'
                            Description   = 'Turns off the Collections feature for saving web content'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EdgeCollectionsEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable the Collections feature'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Drop Feature'
                            Description   = 'Turns off the Drop feature for sharing files between devices'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EdgeEDropEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable Drop feature in Microsoft Edge'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Share Experience'
                            Description   = 'Prevents using the Share experience to share browser content'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ConfigureShare'
                            ValueType     = 'DWord'
                            HardenedValue = 1  # 1 = Share Disallowed
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Configure the Share experience'
                            GPOState      = 'Enabled (Share Disallowed)'
                        }
                        @{
                            Name          = 'Disable In-App Support'
                            Description   = 'Prevents Edge from connecting to Microsoft''s in-browser support service'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'InAppSupportEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > In-app support Enabled'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Search & Address Bar --
                @{
                    Name        = 'Search & Address Bar'
                    Description = 'Controls address bar suggestions and search integrations with Bing'
                    Settings    = @(
                        @{
                            Name          = 'Disable Search Suggestions'
                            Description   = 'Prevents address bar keystrokes from being sent to the search engine'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SearchSuggestEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable search suggestions'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Local Provider Suggestions'
                            Description   = 'Turns off address bar suggestions from local browser data'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'LocalProvidersEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow suggestions from local providers'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Similar Page Suggestions'
                            Description   = 'Turns off similar page suggestions when a website cannot be loaded'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AlternateErrorPagesEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Suggest similar pages when a webpage can''t be found'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Navigation Error Web Service'
                            Description   = 'Prevents Edge from using a web service to help resolve navigation errors'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ResolveNavigationErrorsUseWebService'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable resolution of navigation errors using a web service'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Bing Trending Suggestions'
                            Description   = 'Turns off Microsoft Bing trending topic suggestions in the address bar'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'AddressBarTrendingSuggestEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable Microsoft Bing trending suggestions in the address bar'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Typo Protection'
                            Description   = 'Turns off Microsoft typosquatting protection for mistyped URLs'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'TyposquattingCheckerEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Edge Website Typo Protection settings > Configure Edge Website Typo Protection'
                            GPOState      = 'Disabled'
                            Caution       = 'Removes protection against typosquatting and lookalike sites.'
                        }
                        @{
                            Name          = 'Disable Edge Search Bar'
                            Description   = 'Turns off the floating Edge search bar feature'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SearchbarAllowed'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable the Search bar'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Address Bar Search --
                @{
                    Name        = 'Address Bar Search'
                    Description = 'Controls whether searches can be performed from the address bar'
                    Settings    = @(
                        @{
                            Name          = 'Disable Address Bar Search'
                            Description   = 'Turns off address bar search by removing the default search provider'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultSearchProviderEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Default search provider > Enable the default search provider'
                            GPOState      = 'Disabled'
                            Caution       = 'Non-URL queries in the address bar produce navigation errors.'
                        }
                    )
                }

                # -- Section: Shopping & Commerce --
                @{
                    Name        = 'Shopping & Commerce'
                    Description = 'Controls Microsoft shopping integrations and wallet features'
                    Settings    = @(
                        @{
                            Name          = 'Disable Shopping Assistant'
                            Description   = 'Turns off the Microsoft Edge shopping assistant and price tracking'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EdgeShoppingAssistantEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Shopping in Microsoft Edge Enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Wallet Checkout'
                            Description   = 'Turns off the Microsoft Wallet checkout feature in Edge'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EdgeWalletCheckoutEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable Wallet Checkout feature'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Wallet E-Tree'
                            Description   = 'Turns off the Edge Wallet tree-planting campaign feature'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EdgeWalletEtreeEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Edge Wallet E-Tree Enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Wallet Donations'
                            Description   = 'Turns off donation features integrated into the Microsoft Wallet'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'WalletDonationEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Wallet Donation Enabled'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Rewards & Promotions --
                @{
                    Name        = 'Rewards & Promotions'
                    Description = 'Controls Microsoft promotional features and browser campaigns'
                    Settings    = @(
                        @{
                            Name          = 'Disable Microsoft Rewards'
                            Description   = 'Hides Microsoft Rewards experiences and promotions in Edge'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ShowMicrosoftRewards'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Show Microsoft Rewards experiences'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Insider Promotion'
                            Description   = 'Removes Microsoft Edge Insider program promotion from the browser'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'MicrosoftEdgeInsiderPromotionEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Microsoft Edge Insider Promotion Enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Default Browser Campaigns'
                            Description   = 'Prevents Edge from prompting users to set it as the default browser'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'DefaultBrowserSettingsCampaignEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enables default browser settings campaigns'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Feature Recommendations'
                            Description   = 'Turns off Edge feature recommendations and in-browser assistance prompts'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'ShowRecommendationsEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow feature recommendations and browser assistance notifications from Microsoft Edge'
                            GPOState      = 'Disabled'
                        }
                    )
                }

            ) # End Microsoft Features Sections
        }

        # ===== Category: Browser UI & Performance =====
        @{
            Name        = 'Browser UI & Performance'
            Description = 'Settings configuring browser interface and resource behavior'
            Sections    = @(

                # -- Section: Startup & New Tab Page --
                @{
                    Name        = 'Startup & New Tab Page'
                    Description = 'Controls browser startup behavior and new tab page content'
                    Settings    = @(
                        @{
                            Name          = 'Hide First-Run Experience'
                            Description   = 'Suppresses the first-run experience and splash screen on Edge launch'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'HideFirstRunExperience'
                            ValueType     = 'DWord'
                            HardenedValue = 1
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Hide the First-run experience and splash screen'
                            GPOState      = 'Enabled'
                        }
                        @{
                            Name          = 'Open New Tab on Startup'
                            Description   = 'Opens a new tab on startup instead of restoring the previous session'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'RestoreOnStartup'
                            ValueType     = 'DWord'
                            HardenedValue = 5
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Startup, home page and new tab page > Action to take on Microsoft Edge startup'
                            GPOState      = 'Enabled (Open a new tab)'
                        }
                        @{
                            Name          = 'Set New Tab Page to Blank'
                            Description   = 'Sets the new tab page URL to about:blank'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'NewTabPageLocation'
                            ValueType     = 'String'
                            HardenedValue = 'about:blank'
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Startup, home page and new tab page > Configure the new tab page URL'
                            GPOState      = 'Enabled (about:blank)'
                        }
                        @{
                            Name          = 'Disable Microsoft Content on New Tab'
                            Description   = 'Prevents Microsoft content from appearing on the new tab page'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'NewTabPageContentEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Startup, home page and new tab page > Allow Microsoft content on the new tab page'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Quick Links on New Tab'
                            Description   = 'Removes quick links and most visited sites from the new tab page'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'NewTabPageQuickLinksEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Startup, home page and new tab page > Allow quick links on the new tab page'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Copilot on New Tab Page'
                            Description   = 'Removes the Bing Copilot entry point from the new tab page'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'NewTabPageBingChatEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Startup, home page and new tab page > Disable Bing chat entry-points on Microsoft Edge Enterprise new tab page'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable New Tab App Launcher'
                            Description   = 'Removes the Microsoft 365 App Launcher from the new tab page'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'NewTabPageAppLauncherEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Startup, home page and new tab page > Hide App Launcher on Microsoft Edge new tab page'
                            GPOState      = 'Disabled'
                            Note          = 'Counterintuitive: the Disabled state hides the new tab App Launcher.'
                        }
                        @{
                            Name          = 'Disable New Tab Page Preload'
                            Description   = 'Prevents Edge from preloading the new tab page for faster rendering'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'NewTabPagePrerenderEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Startup, home page and new tab page > Enable preload of the new tab page for faster rendering'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Search Bar at Windows Startup'
                            Description   = 'Prevents the Edge search bar from appearing at Windows startup'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SearchbarIsEnabledOnStartup'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Allow the Search bar at Windows startup'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: UI Features --
                @{
                    Name        = 'UI Features'
                    Description = 'Controls browser interface features and visual elements'
                    Settings    = @(
                        @{
                            Name          = 'Disable Favorites Bar'
                            Description   = 'Turns off the favorites bar in the browser toolbar'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'FavoritesBarEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable favorites bar'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Split Screen'
                            Description   = 'Turns off the split screen tab feature'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SplitScreenEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable split screen feature in Microsoft Edge'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable QR Code Generator'
                            Description   = 'Turns off the built-in QR code generator in Edge'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'QRCodeGeneratorEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable QR Code Generator'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Mobile File Upload'
                            Description   = 'Turns off the feature for uploading files from a mobile device to Edge'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'UploadFromPhoneEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Enable upload files from mobile in Microsoft Edge desktop'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Google Cast'
                            Description   = 'Turns off Google Cast, preventing browser content from being cast'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EnableMediaRouter'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Cast > Enable Google Cast'
                            GPOState      = 'Disabled'
                        }
                    )
                }

                # -- Section: Performance & Background --
                @{
                    Name        = 'Performance & Background'
                    Description = 'Controls background app behavior and performance optimization features'
                    Settings    = @(
                        @{
                            Name          = 'Disable Background Mode'
                            Description   = 'Prevents Edge processes from continuing to run after the browser closes'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'BackgroundModeEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Continue running background apps after Microsoft Edge closes'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Startup Boost'
                            Description   = 'Prevents Edge from pre-launching processes at Windows startup'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'StartupBoostEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Performance > Enable startup boost'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Efficiency Mode'
                            Description   = 'Turns off Edge''s efficiency mode resource optimization'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'EfficiencyModeEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Performance > Efficiency mode enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Sleeping Tabs'
                            Description   = 'Turns off the sleeping tabs feature for inactive tab throttling'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'SleepingTabsEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Sleeping tabs settings > Configure sleeping tabs'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Performance Detector'
                            Description   = 'Turns off the performance detector that monitors browser resource usage'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'PerformanceDetectorEnabled'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Performance > Performance Detector Enabled'
                            GPOState      = 'Disabled'
                        }
                        @{
                            Name          = 'Disable Pin Toolbar Button'
                            Description   = 'Prevents the browser essentials toolbar button from being pinned'
                            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                            ValueName     = 'PinBrowserEssentialsToolbarButton'
                            ValueType     = 'DWord'
                            HardenedValue = 0
                            DefaultValue  = $null
                            GPOPath       = 'Computer Configuration > Administrative Templates > Microsoft Edge > Performance > Pin browser essentials toolbar button'
                            GPOState      = 'Disabled'
                        }
                    )
                }

            ) # End Browser UI & Performance Sections
        }

    ) # End Categories
}
