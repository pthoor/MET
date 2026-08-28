try {
    $policies = @(Get-HostedConnectionFilterPolicy -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-EXO020' -Category EXO -Name 'Connection Filter Policy Hygiene' `
        -Result Fail -Severity High -AffectedObject 'Connection Filter Policies' `
        -Finding 'Unable to retrieve connection filter policies' `
        -Recommendation 'Ensure the account has Security Reader or Exchange View-Only Configuration or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure' -ErrorMessage $_.ToString()
    return
}

if ($policies.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO020' -Category EXO -Name 'Connection Filter Policy Hygiene' `
        -Result Info -Severity High -AffectedObject 'Connection Filter Policies' `
        -Finding 'No connection filter policies were returned by the tenant' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure'
    return
}

foreach ($policy in $policies) {
    $policyName = [string]$policy.Name
    if ([string]::IsNullOrWhiteSpace($policyName)) {
        $policyName = 'Unnamed connection filter policy'
    }

    $affectedObject = $policyName
    if ($policy.IsDefault -eq $true) {
        $affectedObject = "$policyName (default)"
    }

    $allowList = @(@($policy.IPAllowList) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $blockList = @(@($policy.IPBlockList) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $safeListEnabled = ($policy.EnableSafeList -eq $true)

    $broadEntries = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $allowList) {
        $entryText = ([string]$entry).Trim()
        $parts = $entryText.Split('/')
        if ($parts.Count -ne 2) { continue }

        [System.Net.IPAddress] $parsedAddress = $null
        if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref] $parsedAddress)) { continue }
        if ($parsedAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }

        [int] $prefixLength = 0
        if (-not [int]::TryParse($parts[1], [ref] $prefixLength)) { continue }
        if ($prefixLength -lt 0 -or $prefixLength -gt 32) { continue }

        if ($prefixLength -lt 24) {
            $broadEntries.Add($entryText)
        }
    }

    $issues = [System.Collections.Generic.List[string]]::new()

    if ($allowList.Count -gt 0) {
        $shown = @($allowList | Select-Object -First 10) -join ', '
        if ($allowList.Count -gt 10) {
            $shown = "$shown (+$($allowList.Count - 10) more)"
        }
        $issues.Add("The IP allow list contains $($allowList.Count) entr$(if ($allowList.Count -eq 1) { 'y' } else { 'ies' }): $shown - mail arriving from a listed IP skips spam filtering and spoof intelligence entirely, so an attacker able to relay through any listed host inherits a trusted path into every mailbox")
    }

    if ($broadEntries.Count -gt 0) {
        $issues.Add("$($broadEntries.Count) of those allow-list entries are broad CIDR ranges shorter than /24: $($broadEntries -join ', ') - a single range of this size covers hundreds or thousands of hosts the tenant does not own or control, and every one of them inherits the same filtering bypass")
    }

    if ($safeListEnabled) {
        $issues.Add('The third-party safe list (EnableSafeList) is enabled - it is an externally sourced allow list that cannot be enumerated or audited from PowerShell, so the set of senders currently bypassing filtering through it cannot be reviewed')
    }

    $recommendation = "Empty the allow list with: Set-HostedConnectionFilterPolicy -Identity '$policyName' -IPAllowList @(). Disable the safe list with: Set-HostedConnectionFilterPolicy -Identity '$policyName' -EnableSafeList `$false. Re-home genuinely trusted senders onto an authenticated inbound connector with a certificate or IP-plus-TLS binding (assessed by MET-EXO011) so the sender is authenticated rather than merely allow-listed."

    if ($allowList.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO020' -Category EXO -Name 'Connection Filter Policy Hygiene' `
            -Result Fail -Severity High -AffectedObject $affectedObject `
            -Finding ($issues -join '; ') `
            -Recommendation $recommendation `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure' `
            -Metadata @{ IPAllowListCount = $allowList.Count; BroadAllowEntryCount = $broadEntries.Count; IPBlockListCount = $blockList.Count; EnableSafeList = $safeListEnabled }
    }
    elseif ($safeListEnabled) {
        New-METCheckResult -CheckId 'MET-EXO020' -Category EXO -Name 'Connection Filter Policy Hygiene' `
            -Result Warning -Severity High -AffectedObject $affectedObject `
            -Finding ($issues -join '; ') `
            -Recommendation $recommendation `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure' `
            -Metadata @{ IPAllowListCount = 0; BroadAllowEntryCount = 0; IPBlockListCount = $blockList.Count; EnableSafeList = $true }
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO020' -Category EXO -Name 'Connection Filter Policy Hygiene' `
            -Result Pass -Severity High -AffectedObject $affectedObject `
            -Finding "The IP allow list is empty and the third-party safe list is disabled, so no sender bypasses spam filtering and spoof intelligence through this policy (IP block list entries: $($blockList.Count))" `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure' `
            -Metadata @{ IPAllowListCount = 0; BroadAllowEntryCount = 0; IPBlockListCount = $blockList.Count; EnableSafeList = $false }
    }
}
