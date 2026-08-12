try {
    $connectors = Get-InboundConnector -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO011' -Category EXO -Name 'Mail Flow Connector Hygiene' `
        -Result Fail -Severity High -AffectedObject 'Inbound Connectors' `
        -Finding 'Unable to retrieve inbound connectors' `
        -Recommendation 'Ensure the account has Exchange View-Only Configuration or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector' -ErrorMessage $_.ToString()
    return
}

$enabledConnectors = @($connectors) | Where-Object { $_.Enabled -eq $true }
$enabledCount = @($enabledConnectors).Count

if ($enabledCount -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO011' -Category EXO -Name 'Mail Flow Connector Hygiene' `
        -Result Info -Severity High -AffectedObject 'Inbound Connectors' `
        -Finding 'No enabled inbound connectors found' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector'
    return
}

$issues = [System.Collections.Generic.List[string]]::new()

foreach ($connector in $enabledConnectors) {
    if ($connector.RequireTls -ne $true) {
        $issues.Add("'$($connector.Name)' does not require TLS — accepts unencrypted or opportunistic-TLS inbound mail")
    }

    if (@($connector.SenderIPAddresses).Count -eq 0 -and @($connector.SenderDomains).Count -eq 0) {
        $issues.Add("'$($connector.Name)' has no sender IP or domain restriction — accepts mail from any source")
    }
}

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO011' -Category EXO -Name 'Mail Flow Connector Hygiene' `
        -Result Warning -Severity High -AffectedObject "Inbound Connectors ($enabledCount enabled)" `
        -Finding ($issues -join '; ') `
        -Recommendation 'Review flagged connectors. Inbound connectors that accept unencrypted mail or have no sender restriction can be abused to make external mail appear internally authenticated, undermining anti-spoofing and anti-phishing checks downstream. Set RequireTls to $true and restrict SenderIPAddresses/SenderDomains to only the specific partner or on-premises infrastructure that legitimately needs this connector. Run: Set-InboundConnector -Identity <name> -RequireTls $true' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector'
}
else {
    New-METCheckResult -CheckId 'MET-EXO011' -Category EXO -Name 'Mail Flow Connector Hygiene' `
        -Result Pass -Severity High -AffectedObject "Inbound Connectors ($enabledCount enabled)" `
        -Finding 'All enabled inbound connectors require TLS and restrict senders by IP or domain' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector'
}
