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

if (-not $arcConfig.ArcTrustedSealers -or $arcConfig.ArcTrustedSealers.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO016' -Category EXO -Name 'ARC Trusted Sealers Review' `
        -Result Info -Severity Low -AffectedObject 'ARC Trusted Sealers' `
        -Finding 'No ARC trusted sealers configured — nothing to review' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure'
}
else {
    $joinedList = $arcConfig.ArcTrustedSealers -join ', '
    New-METCheckResult -CheckId 'MET-EXO016' -Category EXO -Name 'ARC Trusted Sealers Review' `
        -Result Info -Severity Low -AffectedObject 'ARC Trusted Sealers' `
        -Finding "$($arcConfig.ArcTrustedSealers.Count) ARC trusted sealer(s) configured: $joinedList" `
        -Recommendation 'Each listed domain is trusted to vouch for a message''s authentication results via Authenticated Received Chain (ARC), which can bypass normal DMARC/DKIM checks for anything it seals. Verify each domain is a mail-modifying service (security gateway, mailing list manager, etc.) you still actively use — remove any that are no longer in use. The listed value is the vendor''s DKIM signing domain (the d= value), not your own tenant domain.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure'
}
