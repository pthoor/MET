[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Per-User External Access Policy Drift'
    Severity       = 'Medium'
    Description    = 'Enumerates non-Global Get-CsExternalAccessPolicy instances and flags EnableFederationAccess, EnableTeamsConsumerAccess or EnableTeamsConsumerInbound turned on where the Global policy turns it off.'
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

$baselineProperties = @('EnableFederationAccess', 'EnableTeamsConsumerAccess', 'EnableTeamsConsumerInbound')
$closedAtGlobal = [System.Collections.Generic.List[string]]::new()
$unestablishedAtGlobal = [System.Collections.Generic.List[string]]::new()
if ($nonGlobal.Count -gt 0) {
    foreach ($property in $baselineProperties) {
        $globalProperty = if ($globalPolicy) { $globalPolicy.PSObject.Properties[$property] } else { $null }
        if (-not $globalProperty -or $null -eq $globalProperty.Value) { $unestablishedAtGlobal.Add($property) }
        elseif ($globalProperty.Value -eq $false) { $closedAtGlobal.Add($property) }
    }
}

foreach ($policy in $nonGlobal) {
    $reopened = [System.Collections.Generic.List[string]]::new()
    $unknown = [System.Collections.Generic.List[string]]::new()
    foreach ($property in $closedAtGlobal) {
        if ($property -eq 'EnableTeamsConsumerInbound' -and $policy.EnableTeamsConsumerAccess -eq $false) { continue }
        $policyProperty = $policy.PSObject.Properties[$property]
        if (-not $policyProperty -or $null -eq $policyProperty.Value) { $unknown.Add($property) }
        elseif ($policyProperty.Value -eq $true) { $reopened.Add($property) }
    }

    if ($reopened.Count -eq 0 -and $unknown.Count -eq 0) { continue }

    $federationFlags = @($reopened | Where-Object { $_ -eq 'EnableFederationAccess' })
    $consumerFlags = @($reopened | Where-Object { $_ -ne 'EnableFederationAccess' })
    $findings = [System.Collections.Generic.List[string]]::new()
    $recommendations = [System.Collections.Generic.List[string]]::new()

    if ($federationFlags.Count -gt 0) {
        $findings.Add("Non-Global external access policy '$($policy.Identity)' re-opens federation with external organizations (EnableFederationAccess enabled) that the Global policy closes, for whoever it is assigned to")
        $recommendations.Add("Unless that user set has a specific need to bypass the Global restriction, run: Set-CsExternalAccessPolicy -Identity '$($policy.Identity)' -EnableFederationAccess `$false.")
    }
    if ($consumerFlags.Count -gt 0) {
        $inboundNote = if ($consumerFlags -contains 'EnableTeamsConsumerInbound') { ' - with EnableTeamsConsumerInbound on, unmanaged accounts can also discover these users and start the conversation, the first-contact path most personal-account phishing and vishing lures rely on' } else { '' }
        $findings.Add("Non-Global external access policy '$($policy.Identity)' re-opens Teams communication with unmanaged (personal) Microsoft accounts ($($consumerFlags -join ', ') enabled) that the Global policy closes$inboundNote. This takes effect wherever AllowTeamsConsumer is enabled at the tenant level (see MET-Teams006)")
        $recommendations.Add("If the user set has no specific need to chat with personal accounts, run: Set-CsExternalAccessPolicy -Identity '$($policy.Identity)' $(($consumerFlags | ForEach-Object { "-$_ `$false" }) -join ' '). Where outbound chat is needed, keep EnableTeamsConsumerInbound `$false so personal accounts cannot initiate contact.")
    }
    if ($unknown.Count -gt 0) {
        $findings.Add("Non-Global external access policy '$($policy.Identity)' did not return $($unknown -join ', '), so whether it re-opens access that the Global policy closes was not established - an unconfirmed state is reported as a gap rather than a pass")
        $recommendations.Add("Confirm directly: Get-CsExternalAccessPolicy -Identity '$($policy.Identity)' | Format-List $($unknown -join ', ').")
    }
    $recommendations.Add("Run: Get-CsOnlineUser -Filter `"ExternalAccessPolicy -eq '$($policy.Identity)'`" to identify affected users before changing scope.")

    $results.Add((New-METCheckResult -CheckId 'MET-Teams010' -Category Teams -Name 'Per-User External Access Policy Drift' `
                -Result Warning -Severity Medium -AffectedObject $policy.Identity `
                -Finding ($findings -join '; ') `
                -Recommendation ($recommendations -join ' ') `
                -ReferenceUrl $referenceUrl))
}

if ($unestablishedAtGlobal.Count -gt 0) {
    $globalLabel = if ($globalPolicy) { "The Global external access policy did not return $($unestablishedAtGlobal -join ', ')" } else { 'No Global external access policy was returned' }
    $results.Add((New-METCheckResult -CheckId 'MET-Teams010' -Category Teams -Name 'Per-User External Access Policy Drift' `
                -Result NotApplicable -Severity Medium -AffectedObject 'Global' `
                -Finding "$globalLabel, so the tenant baseline for $($unestablishedAtGlobal -join ', ') was not established and non-Global policies could not be compared against it. An unconfirmed baseline is reported as unassessed rather than a pass, because nothing here distinguishes a custom policy that re-opens access from one that matches the baseline." `
                -Recommendation "Confirm directly: Get-CsExternalAccessPolicy | Format-List Identity, $($baselineProperties -join ', '). If the properties are absent there too, update the MicrosoftTeams module and re-run this check." `
                -ReferenceUrl $referenceUrl `
                -ErrorMessage "$($unestablishedAtGlobal -join ', ') not established for the Global policy from Get-CsExternalAccessPolicy - the policy or the property was not returned by the installed MicrosoftTeams module version."))
}

if (@($results | Where-Object { $_.Result -eq 'Warning' }).Count -eq 0) {
    New-METCheckResult -CheckId 'MET-Teams010' -Category Teams -Name 'Per-User External Access Policy Drift' `
        -Result Pass -Severity Medium -AffectedObject 'External Access Policies' `
        -Finding 'No non-Global external access policy re-opens federation, or Teams communication with unmanaged accounts, that the Global policy closes' `
        -ReferenceUrl $referenceUrl
}
$results
