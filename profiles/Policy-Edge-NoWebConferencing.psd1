#
# windows-hardening
# https://github.com/briangeis/windows-hardening
#
# Policy Profile: Edge No Web Conferencing
# Additive layer for devices that do not use web conferencing.
#
# Reference: profiles/reference/Policy-Edge.md
#
# Author:  Brian Geis
# License: GPL-3.0-or-later
#

@{
    Meta = @{
        Component   = 'Policy'
        Name        = 'Edge No Web Conferencing'
        Description = 'Additive layer for devices that do not use web conferencing.'
        Target      = 'Microsoft Edge 148'
        Reviewed    = '2026-06-30'
        Source      = @(
            @{ Name = 'Edge'; File = 'Policy-Edge.psd1'; Target = 'Microsoft Edge 148'; Reviewed = '2026-06-01' }
        )
    }
    Settings = @(
        @{
            Name      = 'Block Audio Capture'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'AudioCaptureAllowed'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Block Video Capture'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'VideoCaptureAllowed'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
        @{
            Name      = 'Block Screen Capture'
            Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'ScreenCaptureAllowed'
            ValueType = 'DWord'
            Value     = 0
            Exists    = $true
        }
    )
}
