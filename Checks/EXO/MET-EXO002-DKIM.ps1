try {
    $dkimConfigs = Get-DkimSigningConfig -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO002' -Category EXO -Name 'DKIM' `
        -Result Fail -Severity High -AffectedObject 'DKIM Signing Configs' `
        -Finding 'Unable to retrieve DKIM signing configurations' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/dkim' -ErrorMessage $_.ToString()
    return
}

if (-not $dkimConfigs) {
    New-METCheckResult -CheckId 'MET-EXO002' -Category EXO -Name 'DKIM' `
        -Result Fail -Severity High -AffectedObject 'DKIM' `
        -Finding 'No DKIM signing configurations found' `
        -Recommendation 'Enable DKIM signing for all accepted domains in the Microsoft 365 Defender portal.' `
        -ReferenceUrl 'https://aka.ms/dkim'
    return
}

foreach ($config in $dkimConfigs) {
    $issues = [System.Collections.Generic.List[string]]::new()

    if (-not $config.Enabled) {
        $issues.Add('DKIM signing is disabled for this domain')
    }

    if ($config.KeySize -and $config.KeySize -lt 2048) {
        $issues.Add("DKIM key size is $($config.KeySize) bits — minimum recommended is 2048 bits")
    }

    if ($config.Status -ne 'Valid') {
        $issues.Add("DKIM record status is '$($config.Status)' — CNAME records may not be published in DNS")
    }

    $cnames = @()
    if ($config.Selector1CNAME) { $cnames += "selector1: $($config.Selector1CNAME)" }
    if ($config.Selector2CNAME) { $cnames += "selector2: $($config.Selector2CNAME)" }
    $cnameDetail = if ($cnames.Count -gt 0) { " | $($cnames -join ', ')" } else { '' }

    if ($issues.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO002' -Category EXO -Name 'DKIM' `
            -Result Fail -Severity High -AffectedObject $config.Domain `
            -Finding "$($issues -join '; ')$cnameDetail" `
            -Recommendation 'Enable DKIM signing, rotate keys to 2048-bit if needed, and publish the provided CNAME records in DNS.' `
            -ReferenceUrl 'https://aka.ms/dkim'
    }
    else {
        $keyInfo = if ($config.KeySize) { "$($config.KeySize)-bit key" } else { 'key (size not reported by API)' }
        New-METCheckResult -CheckId 'MET-EXO002' -Category EXO -Name 'DKIM' `
            -Result Pass -Severity High -AffectedObject $config.Domain `
            -Finding "DKIM signing is enabled with $keyInfo and status '$($config.Status)'$cnameDetail" `
            -ReferenceUrl 'https://aka.ms/dkim'
    }
}
