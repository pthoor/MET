[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Per-User External Access Policy Drift'
    Severity       = 'Medium'
    Description    = 'Enumerates non-Global Get-CsExternalAccessPolicy instances and flags EnableFederationAccess/EnablePublicCloudAccess re-opening access under a restrictive tenant baseline, and EnableTeamsConsumerAccess/EnableTeamsConsumerInbound re-opening unmanaged-account chat that the Global policy closes.'
    RequiresModule = @('MicrosoftTeams')
}

$results = [System.Collections.Generic.List[object]]::new()

try {
    $policies = @(Get-CsExternalAccessPolicy -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-Teams010' -Category Teams -Name 'Per-User External Access Policy Drift' `
        -Result Fail -Severity Medium -AffectedObject 'Teams External Access Policies' `
        -Finding 'Unable to retrieve external access policies.' `
        -Recommendation 'Ensure the account has Teams administrator or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csexternalaccesspolicy' -ErrorMessage $_.ToString()
    return
}

$referenceUrl = 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csexternalaccesspolicy'
$globalPolicy = $policies | Where-Object { $_.Identity -eq 'Global' } | Select-Object -First 1
$nonGlobal = @($policies | Where-Object { $_.Identity -ne 'Global' })

$consumerProperties = @('EnableTeamsConsumerAccess', 'EnableTeamsConsumerInbound')
$closedAtGlobal = [System.Collections.Generic.List[string]]::new()
$unestablishedAtGlobal = [System.Collections.Generic.List[string]]::new()
if ($nonGlobal.Count -gt 0) {
    foreach ($property in $consumerProperties) {
        $globalProperty = if ($globalPolicy) { $globalPolicy.PSObject.Properties[$property] } else { $null }
        if (-not $globalProperty -or $null -eq $globalProperty.Value) { $unestablishedAtGlobal.Add($property) }
        elseif ($globalProperty.Value -eq $false) { $closedAtGlobal.Add($property) }
    }
}

foreach ($policy in $nonGlobal) {
    $federationFlags = [System.Collections.Generic.List[string]]::new()
    if ($policy.EnableFederationAccess -eq $true) { $federationFlags.Add('EnableFederationAccess') }
    if ($policy.EnablePublicCloudAccess -eq $true) { $federationFlags.Add('EnablePublicCloudAccess') }

    $consumerFlags = [System.Collections.Generic.List[string]]::new()
    $consumerUnknown = [System.Collections.Generic.List[string]]::new()
    foreach ($property in $closedAtGlobal) {
        if ($property -eq 'EnableTeamsConsumerInbound' -and $policy.EnableTeamsConsumerAccess -eq $false) { continue }
        $policyProperty = $policy.PSObject.Properties[$property]
        if (-not $policyProperty -or $null -eq $policyProperty.Value) { $consumerUnknown.Add($property) }
        elseif ($policyProperty.Value -eq $true) { $consumerFlags.Add($property) }
    }

    if ($federationFlags.Count -eq 0 -and $consumerFlags.Count -eq 0 -and $consumerUnknown.Count -eq 0) { continue }

    $findings = [System.Collections.Generic.List[string]]::new()
    $recommendations = [System.Collections.Generic.List[string]]::new()

    if ($federationFlags.Count -gt 0) {
        $findings.Add("Non-Global external access policy '$($policy.Identity)' re-opens federation/public-cloud access ($($federationFlags -join ', ') enabled) for whoever it is assigned to, undoing any tenant-wide federation restriction set on the Global policy")
        $recommendations.Add("Review non-Global external access policies and disable EnableFederationAccess/EnablePublicCloudAccess unless there's a specific business need for that user set to bypass tenant-wide federation restrictions.")
    }
    if ($consumerFlags.Count -gt 0) {
        $inboundNote = if ($consumerFlags -contains 'EnableTeamsConsumerInbound') { ' - with EnableTeamsConsumerInbound on, unmanaged accounts can also discover these users and start the conversation, the first-contact path most personal-account phishing and vishing lures rely on' } else { '' }
        $findings.Add("Non-Global external access policy '$($policy.Identity)' re-opens Teams communication with unmanaged (personal) Microsoft accounts ($($consumerFlags -join ', ') enabled) that the Global policy closes$inboundNote. This takes effect wherever AllowTeamsConsumer is enabled at the tenant level (see MET-Teams006)")
        $recommendations.Add("If the user set has no specific need to chat with personal accounts, run: Set-CsExternalAccessPolicy -Identity '$($policy.Identity)' $(($consumerFlags | ForEach-Object { "-$_ `$false" }) -join ' '). Where outbound chat is needed, keep EnableTeamsConsumerInbound `$false so personal accounts cannot initiate contact.")
    }
    if ($consumerUnknown.Count -gt 0) {
        $findings.Add("Non-Global external access policy '$($policy.Identity)' did not return $($consumerUnknown -join ', '), so whether it re-opens unmanaged-account access that the Global policy closes was not established - an unconfirmed state is reported as a gap rather than a pass")
        $recommendations.Add("Confirm directly: Get-CsExternalAccessPolicy -Identity '$($policy.Identity)' | Format-List $($consumerUnknown -join ', ').")
    }
    $recommendations.Add("Run: Get-CsOnlineUser -Filter `"ExternalAccessPolicy -eq '$($policy.Identity)'`" to identify affected users before changing scope.")

    $results.Add((New-METCheckResult -CheckId 'MET-Teams010' -Category Teams -Name 'Per-User External Access Policy Drift' `
                -Result Warning -Severity Medium -AffectedObject $policy.Identity `
                -Finding ($findings -join '; ') `
                -Recommendation ($recommendations -join ' ') `
                -ReferenceUrl $referenceUrl))
}

if ($unestablishedAtGlobal.Count -gt 0) {
    $results.Add((New-METCheckResult -CheckId 'MET-Teams010' -Category Teams -Name 'Per-User External Access Policy Drift' `
                -Result NotApplicable -Severity Medium -AffectedObject 'Global' `
                -Finding "The Global external access policy did not return $($unestablishedAtGlobal -join ', '), so the tenant baseline for Teams communication with unmanaged (personal) accounts was not established and non-Global policies could not be compared against it. An unconfirmed baseline is reported as unassessed rather than a pass, because nothing here distinguishes a custom policy that re-opens personal-account access from one that matches the baseline." `
                -Recommendation "Confirm directly: Get-CsExternalAccessPolicy | Format-List Identity, $($consumerProperties -join ', '). If the properties are absent there too, update the MicrosoftTeams module and re-run this check." `
                -ReferenceUrl $referenceUrl `
                -ErrorMessage "$($unestablishedAtGlobal -join ', ') not returned for the Global policy by Get-CsExternalAccessPolicy - the installed MicrosoftTeams module version may not expose it."))
}

if (@($results | Where-Object { $_.Result -eq 'Warning' }).Count -eq 0) {
    New-METCheckResult -CheckId 'MET-Teams010' -Category Teams -Name 'Per-User External Access Policy Drift' `
        -Result Pass -Severity Medium -AffectedObject 'External Access Policies' `
        -Finding 'No non-Global external access policy re-opens federation or public-cloud access, or Teams communication with unmanaged accounts that the Global policy closes' `
        -ReferenceUrl $referenceUrl
}
$results
