BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Get-METRuleScope.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METEffectivePolicy.ps1"
    . "$root/Private/New-METEffectivePolicyCoverageResult.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"

    function Get-EXOMailbox           { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets,[string[]]$Properties,[string]$Filter) }
    function Get-MalwareFilterRule    { [CmdletBinding()] param() }
    function Get-MalwareFilterPolicy  { [CmdletBinding()] param() }
    function Get-EOPProtectionPolicyRule { [CmdletBinding()] param([string]$Identity) }
}

Describe 'MET-MDO005 Anti-Malware' {

    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO005-AntiMalware.ps1'
        $script:METContext = $null
        Mock Get-EXOMailbox { [PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com'; RecipientTypeDetails = 'UserMailbox' } }
        Mock Get-EOPProtectionPolicyRule { @() }
    }

    Context 'Everything present and secure' {
        BeforeAll {
            Mock Get-MalwareFilterRule   { @() }
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{
                    Name             = 'Default'
                    IsDefault        = $true
                    ZapEnabled       = $true
                    EnableFileFilter = $true
                    FileTypeAction   = 'Reject'
                    QuarantineTag    = 'AdminOnlyAccessPolicy'
                }
            }
        }

        It 'Returns Pass with the sentence unchanged' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    # ZapEnabled is read with -not. An absent property used to be indistinguishable from
    # an explicit $false; the check now branches on absence first.
    Context 'ZapEnabled absent vs. present and false' {
        It 'Produces different Findings for the same Fail verdict' {
            Mock Get-MalwareFilterRule   { @() }
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $true; FileTypeAction = 'Reject'; QuarantineTag = 'AdminOnlyAccessPolicy' }
            }
            $absent = (& $checkFile)[0]
            $absent.Result | Should -Be 'Fail'
            $absent.Finding | Should -Match 'ZapEnabled was not returned'
            $absent.Finding | Should -Not -Match 'ZAP for malware is disabled'

            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $false; EnableFileFilter = $true; FileTypeAction = 'Reject'; QuarantineTag = 'AdminOnlyAccessPolicy' }
            }
            $present = (& $checkFile)[0]
            $present.Result | Should -Be 'Fail'
            $present.Finding | Should -Match 'ZAP for malware is disabled'
            $present.Finding | Should -Not -Match 'ZapEnabled was not returned'
        }
    }

    # EnableFileFilter is read with -not. Same absence gap as ZapEnabled.
    Context 'EnableFileFilter absent vs. present and false' {
        It 'Produces different Findings for the same Fail verdict' {
            Mock Get-MalwareFilterRule   { @() }
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true; QuarantineTag = 'AdminOnlyAccessPolicy' }
            }
            $absent = (& $checkFile)[0]
            $absent.Result | Should -Be 'Fail'
            $absent.Finding | Should -Match 'EnableFileFilter was not returned'
            $absent.Finding | Should -Not -Match 'Common attachment filter is disabled'

            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true; EnableFileFilter = $false; QuarantineTag = 'AdminOnlyAccessPolicy' }
            }
            $present = (& $checkFile)[0]
            $present.Result | Should -Be 'Fail'
            $present.Finding | Should -Match 'Common attachment filter is disabled'
            $present.Finding | Should -Not -Match 'EnableFileFilter was not returned'
        }
    }

    # FileTypeAction is compared with -ne 'Reject'. An absent value used to read as "not
    # Reject" and report the recommended-Reject sentence with an empty quoted value - the
    # same empty-quoted-value tell as MET-MDO002's Action property.
    Context 'FileTypeAction absent vs. present and not Reject, with the filter enabled' {
        It 'Produces different Findings for the same Fail verdict' {
            Mock Get-MalwareFilterRule   { @() }
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true; EnableFileFilter = $true; QuarantineTag = 'AdminOnlyAccessPolicy' }
            }
            $absent = (& $checkFile)[0]
            $absent.Result | Should -Be 'Fail'
            $absent.Finding | Should -Match 'FileTypeAction was not returned'
            $absent.Finding | Should -Not -Match "Common attachment action is ''"

            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true; EnableFileFilter = $true; FileTypeAction = 'Allow'; QuarantineTag = 'AdminOnlyAccessPolicy' }
            }
            $present = (& $checkFile)[0]
            $present.Result | Should -Be 'Fail'
            $present.Finding | Should -Match "Common attachment action is 'Allow'"
            $present.Finding | Should -Not -Match 'FileTypeAction was not returned'
        }
    }

    # QuarantineTag is already guarded with `$policy.QuarantineTag -and ...` - an absent
    # value is falsy and short-circuits the whole test, so it never reaches Pass on an
    # unobserved quarantine tag. Confirms that guard is undisturbed by this change.
    Context 'QuarantineTag is absent while every other setting is secure' {
        BeforeAll {
            Mock Get-MalwareFilterRule   { @() }
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true; EnableFileFilter = $true; FileTypeAction = 'Reject' }
            }
        }

        It 'Still returns Pass, because the guard already excludes an absent QuarantineTag from being read as a bad value' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }
}
