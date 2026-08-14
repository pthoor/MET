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
        $issues.Add("'$($connector.Name)' does not require TLS - accepts unencrypted or opportunistic-TLS inbound mail")
    }

    $senderIpCount = @($connector.SenderIPAddresses).Count
    $hasIpBinding = $senderIpCount -gt 0 -and $connector.RestrictDomainsToIPAddresses -eq $true
    $hasCertificateBinding = $connector.RequireTls -eq $true -and -not [string]::IsNullOrWhiteSpace([string]$connector.TlsSenderCertificateName)

    if (-not $hasIpBinding -and -not $hasCertificateBinding) {
        if ($senderIpCount -gt 0 -and $connector.RestrictDomainsToIPAddresses -ne $true) {
            $issues.Add("'$($connector.Name)' lists sender IP addresses but does not enable RestrictDomainsToIPAddresses - the IP list is not bound to connector authentication")
        }
        elseif ($connector.RestrictDomainsToCertificate -eq $true -and [string]::IsNullOrWhiteSpace([string]$connector.TlsSenderCertificateName)) {
            $issues.Add("'$($connector.Name)' enables certificate restriction but has no TLS sender certificate name configured")
        }
        elseif (@($connector.SenderDomains).Count -gt 0) {
            $issues.Add("'$($connector.Name)' is scoped only by sender domain - SenderDomains does not authenticate the sending infrastructure")
        }
        else {
            $issues.Add("'$($connector.Name)' has no authenticated sender IP or TLS certificate restriction - accepts mail without validating the source infrastructure")
        }
    }
}

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO011' -Category EXO -Name 'Mail Flow Connector Hygiene' `
        -Result Warning -Severity High -AffectedObject "Inbound Connectors ($enabledCount enabled)" `
        -Finding ($issues -join '; ') `
        -Recommendation 'Review flagged connectors. Require TLS and authenticate the source using either sender IP addresses bound with RestrictDomainsToIPAddresses, or a specific TlsSenderCertificateName. SenderDomains limits connector scope but does not authenticate the sending infrastructure. Run: Set-InboundConnector -Identity <name> -RequireTls $true and configure the appropriate IP or certificate restriction.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector'
}
else {
    New-METCheckResult -CheckId 'MET-EXO011' -Category EXO -Name 'Mail Flow Connector Hygiene' `
        -Result Pass -Severity High -AffectedObject "Inbound Connectors ($enabledCount enabled)" `
        -Finding 'All enabled inbound connectors require TLS and authenticate their source by bound IP addresses or a TLS sender certificate' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector'
}
