[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Intra-Organization Spam Filtering'
    Severity       = 'Medium'
    Description    = 'Checks IntraOrgFilterState on the default and enabled custom anti-spam policies, which controls whether spam and phishing verdicts are acted on for mail sent between internal users.'
    RequiresModule = @('ExchangeOnlineManagement')
}

$referenceUrl = 'https://learn.microsoft.com/en-us/defender-office-365/anti-spam-protection-about#anti-spam-policies'

try {
    $spamRules    = @(Get-HostedContentFilterRule   -ErrorAction Stop)
    $spamPolicies = @(Get-HostedContentFilterPolicy -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-MDO015' -Category MDO -Name 'Intra-Organization Spam Filtering' `
        -Result Fail -Severity Medium -AffectedObject 'Hosted Content Filter Policies' `
        -Finding 'Unable to retrieve anti-spam policies, so whether internal mail is spam and phish filtered was not assessed.' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl $referenceUrl -ErrorMessage $_.ToString()
    return
}

$ruleByPolicy = @{}
foreach ($r in $spamRules) { $ruleByPolicy[$r.HostedContentFilterPolicy] = $r }

$inScope = [System.Collections.Generic.List[object]]::new()
foreach ($policy in $spamPolicies) {
    $isDefault = $policy.IsDefault -eq $true
    $rule = $ruleByPolicy[$policy.Name]
    if (-not $isDefault -and (-not $rule -or $rule.State -ne 'Enabled')) { continue }
    if (Get-METPresetSecurityPolicyTier -Name $policy.Name) { continue }

    $scope = if ($isDefault) { 'catch-all (default - applies to all uncovered recipients)' } else { Get-METRuleScope -Rule $rule }
    $state = $null
    if ($policy.PSObject.Properties['IntraOrgFilterState'] -and $null -ne $policy.IntraOrgFilterState) {
        $state = $policy.IntraOrgFilterState.ToString()
        if ($state -eq '') { $state = $null }
    }
    $inScope.Add([PSCustomObject]@{ Name = $policy.Name; Label = "$($policy.Name) [$scope]"; State = $state })
}

if ($inScope.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO015' -Category MDO -Name 'Intra-Organization Spam Filtering' `
        -Result NotApplicable -Severity Medium -AffectedObject 'Hosted Content Filter Policies' `
        -Finding 'No default or enabled custom anti-spam policy was returned, so intra-organization filtering was not assessed.' `
        -ReferenceUrl $referenceUrl
    return
}

if (@($inScope | Where-Object { $null -ne $_.State }).Count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO015' -Category MDO -Name 'Intra-Organization Spam Filtering' `
        -Result NotApplicable -Severity Medium -AffectedObject 'Hosted Content Filter Policies' `
        -Finding 'No in-scope anti-spam policy returned an IntraOrgFilterState property, so whether spam and phishing verdicts are acted on for internal mail was not established. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a tenant filtering internal phishing from one that has switched it off.' `
        -Recommendation 'Confirm the state directly (Get-HostedContentFilterPolicy | Format-List Name, IntraOrgFilterState). If the property is absent there too, update the ExchangeOnlineManagement module and re-run this check.' `
        -ReferenceUrl $referenceUrl `
        -ErrorMessage 'The IntraOrgFilterState property was not returned by Get-HostedContentFilterPolicy - the installed ExchangeOnlineManagement module version may not expose it.'
    return
}

# Microsoft documents that Default behaves as None in U.S. Government clouds. GCC High and DoD
# connect to their own Exchange endpoints (outlook.office365.us, webmail.apps.mil) and are
# detectable here; GCC uses the commercial endpoint and is not, so its caveat stays in the Finding.
$isUsGovernmentCloud = $false
if (Get-Command -Name 'Get-ConnectionInformation' -ErrorAction SilentlyContinue) {
    $isUsGovernmentCloud = @(Get-ConnectionInformation -ErrorAction SilentlyContinue |
            Where-Object { "$($_.ConnectionUri)" -match '^https?://[^/:]+\.(us|mil)(?=[:/]|$)' }).Count -gt 0
}

$compromiseRisk = 'Internal mail is the route a compromised account uses to phish colleagues, and it arrives from a trusted internal sender.'

foreach ($entry in $inScope) {
    $label = $entry.Label
    $state = $entry.State

    if ($null -eq $state) {
        New-METCheckResult -CheckId 'MET-MDO015' -Category MDO -Name 'Intra-Organization Spam Filtering' `
            -Result Warning -Severity Medium -AffectedObject $label `
            -Finding 'The IntraOrgFilterState property was not returned for this policy, so whether spam and phishing verdicts are acted on for internal mail to its recipients was not established. An unconfirmed state is reported as a gap rather than a pass, because nothing here distinguishes a policy filtering internal phishing from one with it switched off.' `
            -Recommendation "Confirm the value directly: Get-HostedContentFilterPolicy -Identity '$($entry.Name)' | Format-List IntraOrgFilterState." `
            -ReferenceUrl $referenceUrl
        continue
    }

    switch ($state) {
        'Disabled' {
            New-METCheckResult -CheckId 'MET-MDO015' -Category MDO -Name 'Intra-Organization Spam Filtering' `
                -Result Fail -Severity Medium -AffectedObject $label `
                -Finding "Intra-organization spam filtering is turned off (IntraOrgFilterState is Disabled) - no spam or phishing verdict, not even high confidence phishing, is acted on for mail sent between internal users. $compromiseRisk" `
                -Recommendation "Run: Set-HostedContentFilterPolicy -Identity '$($entry.Name)' -IntraOrgFilterState HighConfidencePhish (equivalent to Default, Microsoft's Standard and Strict value, in commercial clouds - and unlike Default also effective in U.S. Government clouds, where Default behaves as None). Consider Phish or broader to also act on ordinary phishing between internal users." `
                -ReferenceUrl $referenceUrl
        }
        { $_ -eq 'Default' -and $isUsGovernmentCloud } {
            New-METCheckResult -CheckId 'MET-MDO015' -Category MDO -Name 'Intra-Organization Spam Filtering' `
                -Result Fail -Severity Medium -AffectedObject $label `
                -Finding "IntraOrgFilterState is Default and this session is connected to a U.S. Government Exchange Online endpoint, where Microsoft documents that Default currently behaves as None - no spam or phishing verdict, not even high confidence phishing, is acted on for mail sent between internal users. $compromiseRisk" `
                -Recommendation "Run: Set-HostedContentFilterPolicy -Identity '$($entry.Name)' -IntraOrgFilterState HighConfidencePhish. Consider Phish or broader to also act on ordinary phishing between internal users." `
                -ReferenceUrl $referenceUrl
            break
        }
        { $_ -in @('Default', 'HighConfidencePhish') } {
            $govCaveat = if ($_ -eq 'Default') { ' In Microsoft 365 GCC, GCC High and DoD, Microsoft documents that Default currently behaves as None - a GCC tenant (which shares the commercial Exchange endpoint and so cannot be told apart here) should set HighConfidencePhish or broader explicitly.' } else { '' }
            New-METCheckResult -CheckId 'MET-MDO015' -Category MDO -Name 'Intra-Organization Spam Filtering' `
                -Result Pass -Severity Medium -AffectedObject $label `
                -Finding "Intra-organization filtering acts on high confidence phishing between internal users (IntraOrgFilterState is $state), the scope Microsoft uses in the Standard and Strict preset policies.$govCaveat" `
                -ReferenceUrl $referenceUrl
        }
        { $_ -in @('Phish', 'HighConfidenceSpam', 'Spam') } {
            New-METCheckResult -CheckId 'MET-MDO015' -Category MDO -Name 'Intra-Organization Spam Filtering' `
                -Result Pass -Severity Medium -AffectedObject $label `
                -Finding "Intra-organization filtering acts on phishing and broader verdicts between internal users (IntraOrgFilterState is $state), wider than the high confidence phishing scope Microsoft uses in the Standard and Strict presets." `
                -ReferenceUrl $referenceUrl
        }
        default {
            New-METCheckResult -CheckId 'MET-MDO015' -Category MDO -Name 'Intra-Organization Spam Filtering' `
                -Result Warning -Severity Medium -AffectedObject $label `
                -Finding "IntraOrgFilterState returned the unrecognized value '$state', so whether spam and phishing verdicts are acted on for internal mail was not established. An unrecognized value is reported as a gap rather than a pass." `
                -Recommendation "Review the value (Get-HostedContentFilterPolicy -Identity '$($entry.Name)' | Format-List IntraOrgFilterState) and set it explicitly to Default, HighConfidencePhish, Phish, HighConfidenceSpam or Spam." `
                -ReferenceUrl $referenceUrl
        }
    }
}
