BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METEndUserQuarantinePermission.ps1"

    function Get-TeamsProtectionPolicy     { [CmdletBinding()] param() }
    function Get-TeamsProtectionPolicyRule { [CmdletBinding()] param() }
    function Get-QuarantinePolicy          { [CmdletBinding()] param([string]$Identity,[string]$QuarantinePolicyType) }
}

Describe 'MET-Teams004 ZAP for Teams - quarantine release permission observation' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams004-ZAPForTeams.ps1'
    }

    Context 'Malware tag: EndUserQuarantinePermissions absent entirely' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'ContosoMalwareTag'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
            Mock Get-QuarantinePolicy { [PSCustomObject]@{ Name = 'ContosoMalwareTag' } }
        }
        It 'Returns Warning, not a claim that self-release is prevented' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Malware'
            $results[0].Finding | Should -Match 'not returned'
            $results[0].Finding | Should -Not -Match 'quarantine policies do not allow user self-release'
        }
    }

    Context 'Malware tag: EndUserQuarantinePermissions present without a PermissionToRelease member' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'ContosoMalwareTag'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoMalwareTag'; EndUserQuarantinePermissions = [PSCustomObject]@{} }
            }
        }
        It 'Returns Warning, not a claim that self-release is prevented' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Malware'
            $results[0].Finding | Should -Match 'not returned'
            $results[0].Finding | Should -Not -Match 'quarantine policies do not allow user self-release'
        }
    }

    Context 'Malware tag: PermissionToRelease is $true' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'ContosoMalwareTag'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                          = 'ContosoMalwareTag'
                    EndUserQuarantinePermissions  = "[PermissionToRelease: True`nPermissionToDelete: True]"
                }
            }
        }
        It 'Returns Fail, unchanged existing finding' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'allows users to self-release quarantined messages'
        }
    }

    Context 'Malware tag: PermissionToRelease is $false' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'ContosoMalwareTag'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                          = 'ContosoMalwareTag'
                    EndUserQuarantinePermissions  = "[PermissionToRelease: False`nPermissionToDelete: True]"
                }
            }
        }
        It 'Returns Pass, unchanged existing behaviour' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'High-Confidence Phish tag: EndUserQuarantinePermissions absent entirely' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'AdminOnlyAccessPolicy'
                    HighConfidencePhishQuarantineTag  = 'ContosoHcpTag'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
            Mock Get-QuarantinePolicy { [PSCustomObject]@{ Name = 'ContosoHcpTag' } }
        }
        It 'Returns Warning, not a claim that self-release is prevented' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'High-confidence phish'
            $results[0].Finding | Should -Match 'not returned'
            $results[0].Finding | Should -Not -Match 'quarantine policies do not allow user self-release'
        }
    }

    Context 'High-Confidence Phish tag: EndUserQuarantinePermissions present without a PermissionToRelease member' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'AdminOnlyAccessPolicy'
                    HighConfidencePhishQuarantineTag  = 'ContosoHcpTag'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoHcpTag'; EndUserQuarantinePermissions = [PSCustomObject]@{} }
            }
        }
        It 'Returns Warning, not a claim that self-release is prevented' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'High-confidence phish'
            $results[0].Finding | Should -Match 'not returned'
            $results[0].Finding | Should -Not -Match 'quarantine policies do not allow user self-release'
        }
    }

    Context 'High-Confidence Phish tag: PermissionToRelease is $true' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'AdminOnlyAccessPolicy'
                    HighConfidencePhishQuarantineTag  = 'ContosoHcpTag'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                          = 'ContosoHcpTag'
                    EndUserQuarantinePermissions  = "[PermissionToRelease: True`nPermissionToDelete: True]"
                }
            }
        }
        It 'Returns Fail, unchanged existing finding' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'allows users to self-release quarantined messages'
        }
    }

    Context 'High-Confidence Phish tag: PermissionToRelease is $false' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'AdminOnlyAccessPolicy'
                    HighConfidencePhishQuarantineTag  = 'ContosoHcpTag'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                          = 'ContosoHcpTag'
                    EndUserQuarantinePermissions  = "[PermissionToRelease: False`nPermissionToDelete: True]"
                }
            }
        }
        It 'Returns Pass, unchanged existing behaviour' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Both tags have an unconfirmed permission and a rule exception also exists' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'ContosoMalwareTag'
                    HighConfidencePhishQuarantineTag  = 'ContosoHcpTag'
                }
            }
            Mock Get-TeamsProtectionPolicyRule {
                [PSCustomObject]@{
                    Name                       = 'DefaultRule'
                    State                      = 'Enabled'
                    ExceptIfSentTo             = @('user1@contoso.com')
                    ExceptIfSentToMemberOf     = @()
                    ExceptIfRecipientDomainIs  = @()
                }
            }
            Mock Get-QuarantinePolicy {
                param($Identity)
                [PSCustomObject]@{ Name = $Identity }
            }
        }
        It 'Returns Warning naming both unconfirmed tags, not the rule-exception recommendation' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Malware'
            $results[0].Finding | Should -Match 'High-confidence phish'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }

    # A confirmed failure on one tag must not silently drop an unconfirmed permission
    # on the other - the reader still needs to know that tag's state was never
    # established, distinct from the confirmed failure so it is not mistaken for one.
    Context 'Malware tag is a confirmed Fail, High-Confidence Phish tag has an unconfirmed release permission' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'ContosoMalwareTag'
                    HighConfidencePhishQuarantineTag  = 'ContosoHcpTag'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
            Mock Get-QuarantinePolicy {
                param($Identity)
                if ($Identity -eq 'ContosoMalwareTag') {
                    return [PSCustomObject]@{
                        Name                          = 'ContosoMalwareTag'
                        EndUserQuarantinePermissions  = "[PermissionToRelease: True`nPermissionToDelete: True]"
                    }
                }
                return [PSCustomObject]@{ Name = 'ContosoHcpTag' }
            }
        }
        It 'Returns Fail and names both the confirmed failure and the unconfirmed tag, with Error populated' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Malware quarantine policy'
            $results[0].Finding | Should -Match 'allows users to self-release quarantined messages'
            $results[0].Finding | Should -Match 'High-confidence phish'
            $results[0].Finding | Should -Match 'not returned'
            $results[0].Finding | Should -Match 'unconfirmed release permission rather than a confirmed failure'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'ContosoHcpTag'
        }
    }

    # The Fail branch, and separately the permissionWarnings Warning branch, previously
    # built their Finding without $ruleRetrievalError - the same asymmetry commit
    # f91583d already closed for $permissionWarnings in these same two files.
    Context 'Malware tag is a confirmed Fail and the Teams protection policy rules failed to retrieve' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'ContosoMalwareTag'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { throw 'Run Connect-MicrosoftTeams before running this cmdlet.' }
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                          = 'ContosoMalwareTag'
                    EndUserQuarantinePermissions  = "[PermissionToRelease: True`nPermissionToDelete: True]"
                }
            }
        }

        It 'Returns Fail and names both the confirmed failure and the rule retrieval failure, with Error populated' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'allows users to self-release quarantined messages'
            $results[0].Finding | Should -Match 'could not be retrieved'
            $results[0].Finding | Should -Match 'rather than a confirmed failure'
            $results[0].Finding | Should -Match 'Connect-MicrosoftTeams'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Connect-MicrosoftTeams'
        }
    }

    Context 'Both tags have an unconfirmed permission and the Teams protection policy rules also failed to retrieve' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'ContosoMalwareTag'
                    HighConfidencePhishQuarantineTag  = 'ContosoHcpTag'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { throw 'Run Connect-MicrosoftTeams before running this cmdlet.' }
            Mock Get-QuarantinePolicy {
                param($Identity)
                [PSCustomObject]@{ Name = $Identity }
            }
        }

        It 'Returns Warning naming both unconfirmed tags and the rule retrieval failure, with Error populated' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Malware'
            $results[0].Finding | Should -Match 'High-confidence phish'
            $results[0].Finding | Should -Match 'could not be retrieved'
            $results[0].Finding | Should -Match 'Connect-MicrosoftTeams'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Connect-MicrosoftTeams'
        }
    }
}
