$allMailboxes = $null
if ($METContext -and $METContext.AllMailboxes) {
    $allMailboxes = @($METContext.AllMailboxes)
}
else {
    try {
        $allMailboxes = @(Get-METAssessableMailboxes)
        if ($METContext) { $METContext.AllMailboxes = $allMailboxes }
    }
    catch {
        New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links Effective Coverage' `
            -Result Warning -Severity High -AffectedObject 'All Mailboxes' `
            -Finding 'Unable to determine effective Safe Links coverage because the mailbox list could not be retrieved.' `
            -Recommendation 'Ensure the account has Exchange View-Only Recipients permission and rerun the assessment.' `
            -ReferenceUrl 'https://aka.ms/mdo-safelinks' -ErrorMessage $_.ToString()
        return
    }
}

if ($allMailboxes.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links Effective Coverage' `
        -Result NotApplicable -Severity High -AffectedObject 'Tenant (0 mailboxes)' `
        -Finding 'No assessable mailboxes were found in the tenant.' `
        -ReferenceUrl 'https://aka.ms/mdo-safelinks'
    return
}

function Add-METSafeLinksPropertyIssue {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]] $Issues,
        [Parameter(Mandatory)] [object] $Policy,
        [Parameter(Mandatory)] [string] $PropertyName,
        [Parameter(Mandatory)] [string] $NotEstablishedText,
        [Parameter(Mandatory)] [string] $FalseText,
        [switch] $InsecureWhenTrue
    )

    # A property that is absent, or present but $null, was never observed. Reading
    # it as $false (or, for the insecure-when-true properties, as $true) would
    # fabricate a verdict this check did not establish.
    $property = $Policy.PSObject.Properties[$PropertyName]
    if (-not $property -or $null -eq $property.Value) {
        $Issues.Add($NotEstablishedText)
        return
    }

    $isIssue = if ($InsecureWhenTrue) { [bool]$property.Value } else { -not $property.Value }
    if ($isIssue) { $Issues.Add($FalseText) }
}

$evaluate = {
    param($Policy, $PolicyType)
    $issues = [System.Collections.Generic.List[string]]::new()
    if (-not $Policy) {
        $issues.Add('Policy settings could not be retrieved')
        return $issues.ToArray()
    }

    Add-METSafeLinksPropertyIssue -Issues $issues -Policy $Policy -PropertyName 'EnableSafeLinksForEmail' `
        -NotEstablishedText 'EnableSafeLinksForEmail was not returned for this policy, so whether Safe Links is enabled for email was not established' `
        -FalseText 'Safe Links for email is disabled'
    Add-METSafeLinksPropertyIssue -Issues $issues -Policy $Policy -PropertyName 'EnableSafeLinksForOffice' `
        -NotEstablishedText 'EnableSafeLinksForOffice was not returned for this policy, so whether Safe Links is enabled for Office apps was not established' `
        -FalseText 'Safe Links for Office apps is disabled'
    Add-METSafeLinksPropertyIssue -Issues $issues -Policy $Policy -PropertyName 'TrackClicks' `
        -NotEstablishedText 'TrackClicks was not returned for this policy, so whether click tracking is enabled was not established' `
        -FalseText 'Click tracking is disabled'
    Add-METSafeLinksPropertyIssue -Issues $issues -Policy $Policy -PropertyName 'EnableForInternalSenders' `
        -NotEstablishedText 'EnableForInternalSenders was not returned for this policy, so whether the policy applies to internal senders was not established' `
        -FalseText 'Not applied to internal senders'
    Add-METSafeLinksPropertyIssue -Issues $issues -Policy $Policy -PropertyName 'ScanUrls' `
        -NotEstablishedText 'ScanUrls was not returned for this policy, so whether real-time URL scanning is enabled was not established' `
        -FalseText 'Real-time URL scanning is disabled'
    Add-METSafeLinksPropertyIssue -Issues $issues -Policy $Policy -PropertyName 'DeliverMessageAfterScan' `
        -NotEstablishedText 'DeliverMessageAfterScan was not returned for this policy, so whether messages are held until the URL scan completes was not established' `
        -FalseText 'Messages delivered before URL scan completes'
    Add-METSafeLinksPropertyIssue -Issues $issues -Policy $Policy -PropertyName 'AllowClickThrough' `
        -NotEstablishedText 'AllowClickThrough was not returned for this policy, so whether users can click through to blocked URLs was not established' `
        -FalseText 'Users can click through to blocked URLs' -InsecureWhenTrue

    if ($PolicyType -ne 'BuiltIn') {
        Add-METSafeLinksPropertyIssue -Issues $issues -Policy $Policy -PropertyName 'DisableURLRewrite' `
            -NotEstablishedText 'DisableURLRewrite was not returned for this policy, so whether URL rewriting is disabled was not established' `
            -FalseText 'URL rewriting is disabled' -InsecureWhenTrue
    }

    $issues.ToArray()
}

$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }
$retrievalErrors = [System.Collections.Generic.List[string]]::new()

if ($METContext -and $METContext.SafeLinksResolution) {
    $resolution = $METContext.SafeLinksResolution
    $retrievalErrors.AddRange([string[]]@($METContext.SafeLinksRetrievalErrors))
}
else {
    $resolution = Resolve-METSafeLinksEffectivePolicy -AllMailboxes $allMailboxes `
        -GroupCache $groupCache -RetrievalErrors $retrievalErrors
    if ($METContext) {
        $METContext.SafeLinksResolution = $resolution
        $METContext.SafeLinksRetrievalErrors = @($retrievalErrors)
    }
}

New-METEffectivePolicyCoverageResult -CheckId 'MET-MDO001' -Name 'Safe Links Effective Coverage' `
    -ProtectionType 'Safe Links' -Severity High -Subjects $allMailboxes -Resolution $resolution `
    -GetPolicyIssues $evaluate -RetrievalErrors $retrievalErrors -ReferenceUrl 'https://aka.ms/mdo-safelinks' `
    -Recommendation 'Assign recipients to a Standard/Strict preset or a compliant custom Safe Links policy. Fix the effective policy for each affected recipient; unused shadowed policies do not affect this result.'
