BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METSafeLinksEffectivePolicy.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"
    . "$root/Private/New-METEffectivePolicyCoverageResult.ps1"

    function Get-EXOMailbox { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets) }
    function Get-SafeLinksRule { [CmdletBinding()] param() }
    function Get-SafeLinksPolicy { [CmdletBinding()] param() }
    function Get-ATPProtectionPolicyRule { [CmdletBinding()] param() }
    function Get-MgGroup { [CmdletBinding()] param([string]$Filter) }
    function Get-DistributionGroupMember { [CmdletBinding()] param([string]$Identity) }

    function New-TestSafeLinksForTeamsPolicy {
        param([string] $Name, [bool] $Compliant)
        [PSCustomObject]@{
            Name = $Name
            EnableSafeLinksForTeams = $Compliant
            EnableSafeLinksForEmail = $true
            EnableSafeLinksForOffice = $true
        }
    }

    function New-TestSafeLinksRule {
        param([string]$Name,[string]$Policy,[int]$Priority,[string[]]$Domains)
        [PSCustomObject]@{
            Name = $Name; SafeLinksPolicy = $Policy; Priority = $Priority; State = 'Enabled'
            SentTo = $null; SentToMemberOf = $null; RecipientDomainIs = $Domains
            ExceptIfSentTo = $null; ExceptIfSentToMemberOf = $null; ExceptIfRecipientDomainIs = $null
        }
    }
}

Describe 'MET-Teams001 effective recipient coverage' {
    BeforeEach {
        $script:METContext = $null
        $script:checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams001-SafeLinks.ps1'
        Mock Get-EXOMailbox {
            [PSCustomObject]@{ PrimarySmtpAddress = 'alice@thoor.tech' }
            [PSCustomObject]@{ PrimarySmtpAddress = 'bob@thoorsec.onmicrosoft.com' }
        }
        Mock Get-ATPProtectionPolicyRule { @() }
    }

    It 'warns when a compliant priority-zero catch-all shadows a weaker lower policy' {
        Mock Get-SafeLinksRule {
            @(
                New-TestSafeLinksRule -Name 'Teams enabled custom' -Policy 'Teams enabled custom' -Priority 0
                New-TestSafeLinksRule -Name 'Teams disabled old' -Policy 'Teams disabled old' -Priority 1
            )
        }
        Mock Get-SafeLinksPolicy {
            @(
                New-TestSafeLinksForTeamsPolicy -Name 'Teams enabled custom' -Compliant $true
                New-TestSafeLinksForTeamsPolicy -Name 'Teams disabled old' -Compliant $false
            )
        }

        $results = @(& $script:checkFile)

        $results | Should -HaveCount 1
        $results[0].Result | Should -Be 'Warning'
        $results[0].Metadata.TotalRecipients | Should -Be 2
        ($results[0].Metadata.Policies | Where-Object PolicyName -eq 'Teams disabled old').EffectiveRecipientCount | Should -Be 0
        $results[0].Finding | Should -Match 'shadowed for all current subjects'
        # Regression: zero affected recipients + a Warning-severity ordering observation must not
        # produce a headline that falsely claims full compliance.
        $results[0].Finding | Should -Match 'ordering issue worth reviewing'
        $results[0].Finding | Should -Not -Match 'Teams protection enabled\.\r?\nPolicy coverage'
    }

    It 'fails only the recipient whose effective policy has Teams disabled, even though a rule assigns it' {
        Mock Get-SafeLinksRule {
            @(
                New-TestSafeLinksRule -Name 'Teams domain policy' -Policy 'Teams domain policy' -Priority 0 -Domains @('thoor.tech')
                New-TestSafeLinksRule -Name 'Teams disabled fallback' -Policy 'Teams disabled fallback' -Priority 1
            )
        }
        Mock Get-SafeLinksPolicy {
            @(
                New-TestSafeLinksForTeamsPolicy -Name 'Teams domain policy' -Compliant $true
                New-TestSafeLinksForTeamsPolicy -Name 'Teams disabled fallback' -Compliant $false
            )
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Fail'
        $result.Metadata.CompliantRecipients | Should -Be 1
        $result.Metadata.AffectedRecipients | Should -Be @('bob@thoorsec.onmicrosoft.com')
        $result.Finding | Should -Match 'bob@thoorsec.onmicrosoft.com'
        $result.Finding | Should -Match 'Safe Links for Teams is disabled'
    }

    It 'catches a policy that is Teams-enabled and assigned by a rule, but shadowed by a higher-precedence policy with Teams disabled' {
        # This is exactly the precedence-blind spot the old rule-assignment-only check could not see:
        # an assigning rule existing is not the same as the policy actually being the effective one.
        Mock Get-SafeLinksRule {
            @(
                New-TestSafeLinksRule -Name 'Teams disabled catch-all' -Policy 'Teams disabled catch-all' -Priority 0
                New-TestSafeLinksRule -Name 'Teams enabled but shadowed' -Policy 'Teams enabled but shadowed' -Priority 1
            )
        }
        Mock Get-SafeLinksPolicy {
            @(
                New-TestSafeLinksForTeamsPolicy -Name 'Teams disabled catch-all' -Compliant $false
                New-TestSafeLinksForTeamsPolicy -Name 'Teams enabled but shadowed' -Compliant $true
            )
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Fail'
        $result.Metadata.AffectedRecipients | Should -HaveCount 2
        ($result.Metadata.Policies | Where-Object PolicyName -eq 'Teams enabled but shadowed').EffectiveRecipientCount | Should -Be 0
    }

    It 'returns NotApplicable when no assessable mailboxes remain' {
        Mock Get-EXOMailbox {
            [PSCustomObject]@{ PrimarySmtpAddress = 'DiscoverySearchMailbox@contoso.com'; RecipientTypeDetails = 'DiscoveryMailbox' }
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'NotApplicable'
    }

    It 'returns Warning when mailbox inventory retrieval fails' {
        Mock Get-EXOMailbox { throw 'mailbox access denied' }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Warning'
        $result.Error | Should -Match 'mailbox access denied'
    }

    It 'returns Pass when the Built-In Protection Policy has Teams enabled and no custom policy exists' {
        Mock Get-SafeLinksRule { @() }
        Mock Get-SafeLinksPolicy {
            @(New-TestSafeLinksForTeamsPolicy -Name 'Built-In Protection Policy' -Compliant $true)
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Pass'
    }

    It 'reuses a Safe Links resolution cached in $METContext by MET-MDO001 without throwing on AddRange' {
        # Regression: Invoke-METTriage runs MET-MDO001 before MET-Teams001 in the same $METContext.
        # MET-MDO001 caches its RetrievalErrors list back into $METContext as a plain `@()` array,
        # which PowerShell types as System.Object[] even though every element is a string. Passing
        # that straight to List[string].AddRange() throws, because Object[] does not satisfy
        # IEnumerable<string> - regardless of whether the array is empty or populated.
        $mailbox = 'alice@thoor.tech'
        $script:METContext = @{
            AllMailboxes        = @([PSCustomObject]@{ PrimarySmtpAddress = $mailbox })
            SafeLinksResolution = [PSCustomObject]@{
                RecipientAssignments = @([PSCustomObject]@{
                    Recipient = $mailbox; PolicyName = 'Built-In Protection Policy'; PolicyType = 'BuiltIn'
                    Tier = 'BuiltIn'; Priority = $null; ScopeDescription = 'Microsoft-managed fallback'
                    Policy = (New-TestSafeLinksForTeamsPolicy -Name 'Built-In Protection Policy' -Compliant $true)
                    Rule = $null
                })
                PolicySummaries      = @()
            }
            SafeLinksRetrievalErrors = @('Unable to retrieve Safe Links rules. simulated failure')
        }

        { $script:result = & $script:checkFile } | Should -Not -Throw
        $script:result.Result | Should -Be 'Warning'
        $script:result.Error | Should -Match 'simulated failure'
    }
}
