try {
    $globalPolicy = Get-QuarantinePolicy -QuarantinePolicyType GlobalQuarantinePolicy -ErrorAction Stop | Select-Object -First 1
}
catch {
    New-METCheckResult -CheckId 'MET-EXO017' -Category EXO -Name 'Quarantine Notification Cadence' `
        -Result Fail -Severity Low -AffectedObject 'Global Quarantine Notification Settings' `
        -Finding 'Unable to retrieve global quarantine notification settings' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies#configure-global-quarantine-notification-settings-in-the-microsoft-defender-portal' `
        -ErrorMessage $_.ToString()
    return
}

$frequency = $globalPolicy.EndUserSpamNotificationFrequency

$cadenceLabel = switch ($frequency) {
    { $_ -eq [TimeSpan]::Parse('04:00:00') } { '4 hours'; break }
    { $_ -eq [TimeSpan]::Parse('1.00:00:00') } { '1 day'; break }
    { $_ -eq [TimeSpan]::Parse('7.00:00:00') } { '7 days (1 week)'; break }
    default { $null }
}

if (-not $frequency -or -not $cadenceLabel) {
    New-METCheckResult -CheckId 'MET-EXO017' -Category EXO -Name 'Quarantine Notification Cadence' `
        -Result Info -Severity Informational -AffectedObject 'Global Quarantine Notification Settings' `
        -Finding 'Quarantine end-user notification cadence could not be determined' `
        -Recommendation 'Review the global quarantine notification frequency in the Microsoft Defender portal (Email & collaboration > Policies & rules > Quarantine policies > Global settings) and set it to a cadence appropriate for your organization (4 hours, 1 day, or 7 days). Faster cadence means more prompt awareness of a legitimate email that got misclassified; slower cadence means fewer interruption emails. Change via: Get-QuarantinePolicy -QuarantinePolicyType GlobalQuarantinePolicy | Set-QuarantinePolicy -EndUserSpamNotificationFrequency <04:00:00|1.00:00:00|7.00:00:00>' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies#configure-global-quarantine-notification-settings-in-the-microsoft-defender-portal'
}
else {
    New-METCheckResult -CheckId 'MET-EXO017' -Category EXO -Name 'Quarantine Notification Cadence' `
        -Result Info -Severity Informational -AffectedObject 'Global Quarantine Notification Settings' `
        -Finding "End-user quarantine notification emails are currently sent every $cadenceLabel" `
        -Recommendation 'This is a timeliness/UX trade-off, not a security control - Microsoft does not publish a recommended value. Faster cadence (4 hours) gives users more prompt awareness of a legitimate email that got misclassified into quarantine; slower cadence (1 day or 7 days) means fewer interruption emails. Review whether the current cadence fits your organization. Change via: Get-QuarantinePolicy -QuarantinePolicyType GlobalQuarantinePolicy | Set-QuarantinePolicy -EndUserSpamNotificationFrequency <04:00:00|1.00:00:00|7.00:00:00>' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies#configure-global-quarantine-notification-settings-in-the-microsoft-defender-portal'
}
