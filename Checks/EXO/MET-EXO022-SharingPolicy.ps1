try {
    $policies = @(Get-SharingPolicy -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-EXO022' -Category EXO -Name 'Calendar and Contact Sharing Policies' `
        -Result Fail -Severity Medium -AffectedObject 'Sharing Policies' `
        -Finding 'Unable to retrieve sharing policies' `
        -Recommendation 'Ensure the account has Exchange View-Only Configuration or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies' -ErrorMessage $_.ToString()
    return
}

if ($policies.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO022' -Category EXO -Name 'Calendar and Contact Sharing Policies' `
        -Result Info -Severity Medium -AffectedObject 'Sharing Policies' `
        -Finding 'No sharing policies are configured in this tenant, so no organization-wide calendar or contact sharing relationship is defined' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies'
    return
}

foreach ($policy in $policies) {
    $policyName = [string]$policy.Name
    if ([string]::IsNullOrWhiteSpace($policyName)) {
        $policyName = 'Unnamed sharing policy'
    }

    $affectedObject = $policyName
    if ($policy.Default -eq $true) {
        $affectedObject = "$policyName (default)"
    }

    if ($policy.Enabled -ne $true) {
        New-METCheckResult -CheckId 'MET-EXO022' -Category EXO -Name 'Calendar and Contact Sharing Policies' `
            -Result Info -Severity Medium -AffectedObject $affectedObject `
            -Finding 'This sharing policy exists but is disabled, so none of its sharing rules currently apply to any mailbox' `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies'
        continue
    }

    $domainEntries = @(@($policy.Domains) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

    $permissiveEntries = [System.Collections.Generic.List[string]]::new()
    $freeBusyOnlyEntries = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in $domainEntries) {
        $entryText = ([string]$entry).Trim()
        $separatorIndex = $entryText.IndexOf(':')
        if ($separatorIndex -lt 0) {
            $domainPart = $entryText
            $actionPart = ''
        }
        else {
            $domainPart = $entryText.Substring(0, $separatorIndex).Trim()
            $actionPart = $entryText.Substring($separatorIndex + 1).Trim()
        }

        if ($domainPart -ne '*' -and $domainPart -ne 'Anonymous') { continue }

        if ($actionPart -match 'Reviewer|Detail|ContactsSharing') {
            $permissiveEntries.Add($entryText)
        }
        else {
            $freeBusyOnlyEntries.Add($entryText)
        }
    }

    $recommendation = "Scope sharing to named partner domains with: Set-SharingPolicy -Identity '$policyName' -Domains 'partner.example:CalendarSharingFreeBusySimple'. Where a wildcard or anonymous entry is genuinely required, downgrade it to CalendarSharingFreeBusySimple rather than a Reviewer, Detail, or ContactsSharing level."

    if ($permissiveEntries.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO022' -Category EXO -Name 'Calendar and Contact Sharing Policies' `
            -Result Warning -Severity Medium -AffectedObject $affectedObject `
            -Finding "This enabled sharing policy shares more than simple free/busy with every domain or anonymously: $($permissiveEntries -join ', ') - calendar detail and contact sharing at this scope hands an attacker an org chart, meeting subjects, attendee lists and internal addresses, which is exactly the reconnaissance an internal-impersonation phish is built from" `
            -Recommendation $recommendation `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies' `
            -Metadata @{ DomainEntryCount = $domainEntries.Count; PermissiveEntryCount = $permissiveEntries.Count }
    }
    elseif ($freeBusyOnlyEntries.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO022' -Category EXO -Name 'Calendar and Contact Sharing Policies' `
            -Result Pass -Severity Medium -AffectedObject $affectedObject `
            -Finding "This enabled sharing policy has wildcard or anonymous entries, but they share simple free/busy only: $($freeBusyOnlyEntries -join ', ') - no calendar detail, attendee list, or contact data is exposed" `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies' `
            -Metadata @{ DomainEntryCount = $domainEntries.Count; PermissiveEntryCount = 0 }
    }
    elseif ($domainEntries.Count -eq 0) {
        New-METCheckResult -CheckId 'MET-EXO022' -Category EXO -Name 'Calendar and Contact Sharing Policies' `
            -Result Pass -Severity Medium -AffectedObject $affectedObject `
            -Finding 'This enabled sharing policy defines no sharing domain entries, so it grants no external calendar or contact sharing' `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies' `
            -Metadata @{ DomainEntryCount = 0; PermissiveEntryCount = 0 }
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO022' -Category EXO -Name 'Calendar and Contact Sharing Policies' `
            -Result Pass -Severity Medium -AffectedObject $affectedObject `
            -Finding "This enabled sharing policy has no wildcard or anonymous entries - all $($domainEntries.Count) sharing relationship(s) are scoped to named domains" `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies' `
            -Metadata @{ DomainEntryCount = $domainEntries.Count; PermissiveEntryCount = 0 }
    }
}
