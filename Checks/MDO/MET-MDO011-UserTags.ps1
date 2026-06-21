New-METCheckResult -CheckId 'MET-MDO011' -Category MDO -Name 'User Tags' `
    -Result Info -Severity Low -AffectedObject 'User Tags' `
    -Finding 'User tag configuration cannot be assessed via Exchange Online PowerShell — no cmdlets exist for custom tag enumeration, and alert policy queries require a Security and Compliance session' `
    -Recommendation 'Verify custom user tags and tag-aware alert policies manually in the Microsoft 365 Defender portal under Settings > Email & collaboration > User tags. To set the built-in Priority account tag via PowerShell use: Set-User -Identity <UPN> -VIP $true' `
    -ReferenceUrl 'https://aka.ms/mdo-usertags'
