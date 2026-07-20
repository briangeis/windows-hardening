#
# windows-hardening
# https://github.com/briangeis/windows-hardening
#
# Policy Profile: Edge Base
# A curated privacy and security baseline for Microsoft Edge.
#
# Reference: profiles/reference/Policy-Edge.md
#
# Author:  Brian Geis
# License: GPL-3.0-or-later
#

@{
    Meta = @{
        Component   = 'Policy'
        Name        = 'Edge Base'
        Description = 'A curated privacy and security baseline for Microsoft Edge.'
        Target      = 'Microsoft Edge 148'
        Reviewed    = '2026-06-30'
        Source      = @(
            @{ Name = 'Edge'; File = 'Policy-Edge.psd1'; Target = 'Microsoft Edge 148'; Reviewed = '2026-06-01' }
        )
    }
    Settings = @(
        @{
            Name      = 'Disable Browser Diagnostic Data'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DiagnosticData'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable URL Reporting in Diagnostic Data'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'UrlDiagnosticDataEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Edge 3P SERP Telemetry'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'Edge3PSerpTelemetryEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable DNS Interception Checks'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DNSInterceptionChecksEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable User Feedback'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'UserFeedbackAllowed'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Personalization Reporting'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'PersonalizationReportingEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Asset Delivery Service'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'EdgeAssetDeliveryServiceEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable AI Theme Generation'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AIGenThemesEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Enable Strict Tracking Prevention'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'TrackingPrevention'
            ValueType = 'DWord'
            Value     = 3
        }
        @{
            Name      = 'Block Third Party Cookies'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'BlockThirdPartyCookies'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Enable Do Not Track'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ConfigureDoNotTrack'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Disable Browsing with Copilot'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AllowBrowsingWithCopilot'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Copilot Toolbar Button'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'Microsoft365CopilotChatIconEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Copilot Page Context Access'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'CopilotPageContext'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Built-In AI APIs for Pages'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'BuiltInAIAPIsEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Browsing History Sharing with Copilot Search'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ShareBrowsingHistoryWithCopilotSearchAllowed'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable AI-Enhanced History Search'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'EdgeHistoryAISearchEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Experimentation Service'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ExperimentationAndConfigurationServiceControl'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Edge Update Experimentation Service'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
            ValueName = 'UpdaterExperimentationAndConfigurationServiceControl'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable WebView2 Experimentation Service'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebView2'
            ValueName = 'ExperimentationAndConfigurationServiceControl'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Prevent Feature Flag Overrides'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'FeatureFlagOverridesControl'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Browser Sign-In'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'BrowserSignin'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Microsoft Sync'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SyncDisabled'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Disable Work Account SSO for Websites'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AADWebSiteSSOUsingThisProfileEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Microsoft Personal Account SSO'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'MSAWebSiteSSOUsingThisProfileAllowed'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Guided Profile Switch'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'GuidedSwitchEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Seamless Web-to-Browser Sign-In'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SeamlessWebToBrowserSignInEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Password Manager'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'PasswordManagerEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Password Autofill'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'PrimaryPasswordSetting'
            ValueType = 'DWord'
            Value     = 3
        }
        @{
            Name      = 'Disable Payment Autofill'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AutofillCreditCardEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Payment Method Query'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'PaymentMethodQueryEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Address Autofill'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AutofillAddressEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Membership Autofill'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AutofillMembershipsEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable First-Run Auto-Import'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AutoImportAtFirstRun'
            ValueType = 'DWord'
            Value     = 4
        }
        @{
            Name      = 'Disable Repeated Imports on Launch'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ImportOnEachLaunch'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Import of Saved Passwords'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ImportSavedPasswords'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Import of Payment Info'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ImportPaymentInfo'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Import of Autofill Data'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ImportAutofillFormData'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Import of Browser Settings'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ImportBrowserSettings'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Import of Home Page Settings'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ImportHomepage'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Import of Search Engine Settings'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ImportSearchEngine'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Clear Browsing Data on Exit'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ClearBrowsingDataOnExit'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Clear Cached Images on Exit'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ClearCachedImagesAndFilesOnExit'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Disable Saving Browser History'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SavingBrowserHistoryDisabled'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Delete Browser Data on Migration'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DeleteDataOnMigration'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Disable Windows Search Access to Edge Data'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'LocalBrowserDataShareEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Microsoft Defender SmartScreen'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SmartScreenEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable SmartScreen Checks for Trusted Downloads'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SmartScreenForTrustedDownloadsEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable SmartScreen PUA Protection'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SmartScreenPuaEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable SmartScreen DNS Requests'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SmartScreenDnsRequestsEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Scareware Blocker'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ScarewareBlockerProtectionEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Enable Strict Enhanced Security Mode'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'EnhanceSecurityMode'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Enable Site Isolation'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SitePerProcess'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Enable Browser Code Integrity'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'BrowserCodeIntegritySetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Enable Dynamic Code Protection'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DynamicCodeSettings'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Block External Extensions'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'BlockExternalExtensions'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Enable Network Service Sandbox'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'NetworkServiceSandboxEnabled'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Block JavaScript JIT'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultJavaScriptJitSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Block Insecure Content Exceptions'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultInsecureContentSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Disable Internet Explorer Mode'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'InternetExplorerIntegrationLevel'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Require OCSP/CRL Checks for Local Trust Anchors'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'RequireOnlineRevocationChecksForLocalAnchors'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Enable Encrypted Client Hello'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'EncryptedClientHelloEnabled'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Disable Basic Authentication over HTTP'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'BasicAuthOverHttpEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Network Prediction'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'NetworkPredictionOptions'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Block Geolocation Access'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultGeolocationSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Block Sensor Access'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultSensorsSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Block Serial API Access'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultSerialGuardSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Block Web Bluetooth Access'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultWebBluetoothGuardSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Block WebHID Access'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultWebHidGuardSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Block WebUSB Access'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultWebUsbGuardSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Block File System API (Read)'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultFileSystemReadGuardSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Block File System API (Write)'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultFileSystemWriteGuardSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Block Automatic Downloads'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultAutomaticDownloadsSetting'
            ValueType = 'DWord'
            Value     = 2
        }
        @{
            Name      = 'Restrict WebRTC Local IP Exposure'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'WebRtcLocalhostIpHandling'
            ValueType = 'String'
            Value     = 'default_public_interface_only'
        }
        @{
            Name      = 'Disable Translate'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'TranslateEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Online Text-to-Speech'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ConfigureOnlineTextToSpeech'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Speech Recognition'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SpeechRecognitionEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Live Captions'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'LiveCaptionsAllowed'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Microsoft Editor Spell Check'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'MicrosoftEditorProofingEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Microsoft Editor Synonyms'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'MicrosoftEditorSynonymsEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Tab Organization Suggestions'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'TabServicesEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Image Descriptions from Microsoft'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AccessibilityImageLabelsEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Hubs Sidebar'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'HubsSidebarEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Standalone Sidebar'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'StandaloneHubsSidebarEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Collections'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'EdgeCollectionsEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Drop Feature'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'EdgeEDropEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Share Experience'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ConfigureShare'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Disable In-App Support'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'InAppSupportEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Search Suggestions'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SearchSuggestEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Similar Page Suggestions'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AlternateErrorPagesEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Navigation Error Web Service'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ResolveNavigationErrorsUseWebService'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Bing Trending Suggestions'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AddressBarTrendingSuggestEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Typo Protection'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'TyposquattingCheckerEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Edge Search Bar'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SearchbarAllowed'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Shopping Assistant'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'EdgeShoppingAssistantEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Wallet Checkout'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'EdgeWalletCheckoutEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Wallet E-Tree'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'EdgeWalletEtreeEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Wallet Donations'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'WalletDonationEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Microsoft Rewards'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ShowMicrosoftRewards'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Insider Promotion'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'MicrosoftEdgeInsiderPromotionEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Default Browser Campaigns'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'DefaultBrowserSettingsCampaignEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Feature Recommendations'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ShowRecommendationsEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Hide First-Run Experience'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'HideFirstRunExperience'
            ValueType = 'DWord'
            Value     = 1
        }
        @{
            Name      = 'Open New Tab on Startup'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'RestoreOnStartup'
            ValueType = 'DWord'
            Value     = 5
        }
        @{
            Name      = 'Set New Tab Page to Blank'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'NewTabPageLocation'
            ValueType = 'String'
            Value     = 'about:blank'
        }
        @{
            Name      = 'Disable Microsoft Content on New Tab'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'NewTabPageContentEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Quick Links on New Tab'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'NewTabPageQuickLinksEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Copilot on New Tab Page'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'NewTabPageBingChatEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable New Tab App Launcher'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'NewTabPageAppLauncherEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable New Tab Page Preload'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'NewTabPagePrerenderEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Search Bar at Windows Startup'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'SearchbarIsEnabledOnStartup'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Mobile File Upload'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'UploadFromPhoneEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Google Cast'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'EnableMediaRouter'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Background Mode'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'BackgroundModeEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Startup Boost'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'StartupBoostEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Performance Detector'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'PerformanceDetectorEnabled'
            ValueType = 'DWord'
            Value     = 0
        }
        @{
            Name      = 'Disable Pin Toolbar Button'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'PinBrowserEssentialsToolbarButton'
            ValueType = 'DWord'
            Value     = 0
        }
    )
}
