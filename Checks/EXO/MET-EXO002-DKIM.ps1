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

    # Key size is reported per selector (Selector1KeySize/Selector2KeySize), never as a
    # flat KeySize property - KeySize exists only as an input parameter on New-/Rotate-.
    # Only the currently-signing selector is asserted: raising the key size applies to
    # the next active selector at the following rotation, so a domain legitimately mid-
    # migration has one 1024-bit and one 2048-bit selector and must not be failed for it.
    $activeSelector = if ($config.RotateOnDate -and ([datetime]::UtcNow -ge $config.RotateOnDate)) {
        $config.SelectorAfterRotateOnDate
    } else {
        $config.SelectorBeforeRotateOnDate
    }

    $selectorSizes = @{
        selector1 = $config.Selector1KeySize
        selector2 = $config.Selector2KeySize
    }

    $activeKeySize = $null
    if ($activeSelector -and $selectorSizes.ContainsKey([string]$activeSelector)) {
        $activeKeySize = $selectorSizes[[string]$activeSelector]
    }
    if ($null -eq $activeKeySize) {
        $reported = @($selectorSizes.Values | Where-Object { $_ })
        if ($reported.Count -gt 0) {
            $activeKeySize = ($reported | Measure-Object -Minimum).Minimum
        }
    }

    if ($null -ne $activeKeySize -and $activeKeySize -lt 2048) {
        $issues.Add("DKIM key size is $activeKeySize bits - minimum recommended is 2048 bits")
    }

    $inactiveNote = @()
    foreach ($sel in @('selector1', 'selector2')) {
        $size = $selectorSizes[$sel]
        if ($null -ne $size -and $sel -ne [string]$activeSelector -and $size -lt 2048) {
            $inactiveNote += "$sel is $size-bit and will sign after the next key rotation"
        }
    }

    # Microsoft documents three PowerShell-facing Status values. NoDKIMKeys and
    # CnameMissing are distinct problems with distinct fixes, so they are reported
    # separately rather than under one CNAME-flavoured message.
    switch ([string]$config.Status) {
        'Valid'        { }
        'NoDKIMKeys'   { $issues.Add('No DKIM keypair has been generated for this domain') }
        'CnameMissing' { $issues.Add('DKIM CNAME records are not published in DNS') }
        ''             { $issues.Add('DKIM status was not reported by Exchange Online') }
        default        { $issues.Add("DKIM record status is '$($config.Status)'") }
    }

    $cnames = @()
    if ($config.Selector1CNAME) { $cnames += "selector1: $($config.Selector1CNAME)" }
    if ($config.Selector2CNAME) { $cnames += "selector2: $($config.Selector2CNAME)" }
    $cnameDetail = if ($cnames.Count -gt 0) { " | $($cnames -join ', ')" } else { '' }

    $domainLabel = if ($config.Domain) { $config.Domain } else { $config.Name }

    if ($issues.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO002' -Category EXO -Name 'DKIM' `
            -Result Fail -Severity High -AffectedObject $domainLabel `
            -Finding "$($issues -join '; ')$cnameDetail" `
            -Recommendation 'Enable DKIM signing, rotate keys to 2048-bit if needed, and publish the provided CNAME records in DNS.' `
            -ReferenceUrl 'https://aka.ms/dkim'
    }
    elseif ($null -eq $activeKeySize) {
        New-METCheckResult -CheckId 'MET-EXO002' -Category EXO -Name 'DKIM' `
            -Result Warning -Severity High -AffectedObject $domainLabel `
            -Finding "DKIM signing is enabled and status is '$($config.Status)', but neither Selector1KeySize nor Selector2KeySize was reported, so the key length could not be verified against the 2048-bit minimum$cnameDetail" `
            -Recommendation 'Verify the DKIM key length in the Defender portal, and rotate to 2048-bit with Rotate-DkimSigningConfig -Identity <domain> -KeySize 2048 if it is still 1024-bit.' `
            -ReferenceUrl 'https://aka.ms/dkim'
    }
    else {
        $rotationNote = if ($inactiveNote.Count -gt 0) { " (note: $($inactiveNote -join '; '))" } else { '' }
        New-METCheckResult -CheckId 'MET-EXO002' -Category EXO -Name 'DKIM' `
            -Result Pass -Severity High -AffectedObject $domainLabel `
            -Finding "DKIM signing is enabled with a $activeKeySize-bit key on the active selector and status '$($config.Status)'$rotationNote$cnameDetail" `
            -ReferenceUrl 'https://aka.ms/dkim'
    }
}
