BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Get-METRuleScope.ps1"

    # Stub EXO cmdlets so Pester's Mock can override them
    function Get-SafeLinksPolicy               { [CmdletBinding()] param() }
    function Get-SafeLinksRule                 { [CmdletBinding()] param() }
    function Get-SafeAttachmentPolicy          { [CmdletBinding()] param() }
    function Get-SafeAttachmentRule            { [CmdletBinding()] param() }
    function Get-AtpPolicyForO365              { [CmdletBinding()] param() }
    function Get-AntiPhishPolicy               { [CmdletBinding()] param() }
    function Get-MalwareFilterPolicy           { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy     { [CmdletBinding()] param() }
    function Get-HostedContentFilterRule       { [CmdletBinding()] param() }
    function Get-HostedOutboundSpamFilterPolicy { [CmdletBinding()] param() }
}

Describe 'MET-MDO001 Safe Links' {

    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO001-SafeLinks.ps1'
    }

    Context 'When all Safe Links settings are correctly configured' {
        BeforeAll {
            Mock Get-SafeLinksRule   { @() }
            Mock Get-SafeLinksPolicy {
                [PSCustomObject]@{
                    Name                      = 'Built-In Protection Policy'
                    EnableSafeLinksForEmail   = $true
                    EnableSafeLinksForOffice  = $true
                    TrackClicks               = $true
                    EnableForInternalSenders  = $true
                    ScanUrls                  = $true
                    DeliverMessageAfterScan   = $true
                    AllowClickThrough         = $false
                }
            }
        }

        It 'Returns a Pass result' {
            $results = & $checkFile
            $results | Should -Not -BeNullOrEmpty
            $results[0].Result | Should -Be 'Pass'
            $results[0].CheckId | Should -Be 'MET-MDO001'
        }
    }

    Context 'When Safe Links for email is disabled' {
        BeforeAll {
            Mock Get-SafeLinksRule   { @() }
            Mock Get-SafeLinksPolicy {
                [PSCustomObject]@{
                    Name                      = 'Built-In Protection Policy'
                    EnableSafeLinksForEmail   = $false
                    EnableSafeLinksForOffice  = $true
                    TrackClicks               = $true
                    EnableForInternalSenders  = $true
                    ScanUrls                  = $true
                    DeliverMessageAfterScan   = $true
                    AllowClickThrough         = $false
                }
            }
        }

        It 'Returns a Fail result' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }

        It 'Finding mentions email being disabled' {
            $results = & $checkFile
            $results[0].Finding | Should -Match 'email'
        }
    }

    Context 'When no Safe Links policies exist' {
        BeforeAll {
            Mock Get-SafeLinksPolicy { @() }
        }

        It 'Returns a Fail result' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'When Get-SafeLinksPolicy throws' {
        BeforeAll {
            Mock Get-SafeLinksPolicy { throw 'Unauthorized' }
        }

        It 'Returns a Fail result with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'MET-MDO002 Safe Attachments' {

    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO002-SafeAttachments.ps1'
    }

    Context 'Policy enabled with Block action' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Policy enabled with Allow action' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Allow' }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
        It 'Finding mentions Allow' {
            $results = & $checkFile
            $results[0].Finding | Should -Match 'Allow'
        }
    }

    Context 'Policy is disabled' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $false; Action = 'Block' }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }
}

Describe 'MET-MDO009 ZAP' {

    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO009-ZAP.ps1'
    }

    Context 'ZAP fully enabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name            = 'Default'
                    IsDefault       = $true
                    ZapEnabled      = $true
                    SpamZapEnabled  = $true
                    PhishZapEnabled = $true
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'ZAP globally disabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name            = 'Default'
                    IsDefault       = $true
                    ZapEnabled      = $false
                    SpamZapEnabled  = $true
                    PhishZapEnabled = $true
                }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'Phish ZAP disabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name            = 'Default'
                    IsDefault       = $true
                    ZapEnabled      = $true
                    SpamZapEnabled  = $true
                    PhishZapEnabled = $false
                }
            }
        }
        It 'Returns Fail and mentions phishing' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'phish'
        }
    }
}
