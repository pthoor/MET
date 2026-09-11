[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'ARC Trusted Sealers Review'
    Severity       = 'Low'
    Description    = 'Lists ArcTrustedSealers on Get-ArcConfig, the domains trusted to vouch for message authentication results via Authenticated Received Chain.'
    RequiresModule = @('ExchangeOnlineManagement')
}

try {
    $arcConfig = Get-ArcConfig -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO016' -Category EXO -Name 'ARC Trusted Sealers Review' `
        -Result Fail -Severity Low -AffectedObject 'ARC Trusted Sealers' `
        -Finding 'Unable to retrieve ARC configuration' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure' `
        -ErrorMessage $_.ToString()
    return
}

# Get-ArcConfig returns no output at all when no trusted ARC sealers are configured -
# Microsoft documents this: "If no trusted ARC sealers are configured, the command
# returns no results." That is a genuine "none configured" observation, not an unreadable
# state. A real retrieval failure throws and is caught above, so an empty return here is
# unambiguous.
if (-not $arcConfig) {
    New-METCheckResult -CheckId 'MET-EXO016' -Category EXO -Name 'ARC Trusted Sealers Review' `
        -Result Info -Severity Low -AffectedObject 'ARC Trusted Sealers' `
        -Finding 'Get-ArcConfig returned no configuration, which is how Exchange Online reports that no trusted ARC sealers are configured - nothing to review' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure'
    return
}

# An object was returned but ArcTrustedSealers is absent, or present but $null - distinct
# from the empty-return case above and from an empty list. Reading it the same as an empty
# list would report "nothing to review" about a property this check could not read, when
# ARC sealers can bypass DMARC/DKIM checks for anything they seal.
$sealersProperty = $arcConfig.PSObject.Properties['ArcTrustedSealers']

if (-not $sealersProperty -or $null -eq $sealersProperty.Value) {
    New-METCheckResult -CheckId 'MET-EXO016' -Category EXO -Name 'ARC Trusted Sealers Review' `
        -Result NotApplicable -Severity Low -AffectedObject 'ARC Trusted Sealers' `
        -Finding 'Get-ArcConfig did not return a value for ArcTrustedSealers, so whether any ARC trusted sealers are configured was not established. An unconfirmed state is reported as unassessed rather than a pass, because ARC sealers can bypass DMARC/DKIM checks for anything they seal, and nothing here distinguishes a tenant with none configured from one whose sealers this check could not read.' `
        -Recommendation 'Confirm the setting directly with: Get-ArcConfig | Format-List ArcTrustedSealers. An absent property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure' `
        -ErrorMessage 'Get-ArcConfig did not return an ArcTrustedSealers value.'
}
elseif ($sealersProperty.Value.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO016' -Category EXO -Name 'ARC Trusted Sealers Review' `
        -Result Info -Severity Low -AffectedObject 'ARC Trusted Sealers' `
        -Finding 'No ARC trusted sealers configured - nothing to review' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure'
}
else {
    $joinedList = $sealersProperty.Value -join ', '
    New-METCheckResult -CheckId 'MET-EXO016' -Category EXO -Name 'ARC Trusted Sealers Review' `
        -Result Info -Severity Low -AffectedObject 'ARC Trusted Sealers' `
        -Finding "$($sealersProperty.Value.Count) ARC trusted sealer(s) configured: $joinedList" `
        -Recommendation 'Each listed domain is trusted to vouch for a message''s authentication results via Authenticated Received Chain (ARC), which can bypass normal DMARC/DKIM checks for anything it seals. Verify each domain is a mail-modifying service (security gateway, mailing list manager, etc.) you still actively use - remove any that are no longer in use. The listed value is the vendor''s DKIM signing domain (the d= value), not your own tenant domain.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure'
}
