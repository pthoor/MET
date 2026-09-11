[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Mail Flow Connector Hygiene'
    Severity       = 'High'
    Description    = 'Flags enabled inbound connectors with RequireTls off or no effective source-IP/TLS-certificate authentication binding.'
    RequiresModule = @('ExchangeOnlineManagement')
}

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

$allConnectors = @($connectors)

# A connector whose Enabled property is absent, or present but $null, was never observed
# as active or inactive - treating it as disabled would silently drop it from every
# hygiene assertion below (TLS, IP binding, certificate binding) about a connector this
# check did receive. It is assessed alongside explicitly-enabled connectors instead.
$enabledConnectors = @($allConnectors | Where-Object {
    $enabledProperty = $_.PSObject.Properties['Enabled']
    $enabledProperty -and $null -ne $enabledProperty.Value -and $enabledProperty.Value -eq $true
})
$unknownStateConnectors = @($allConnectors | Where-Object {
    $enabledProperty = $_.PSObject.Properties['Enabled']
    -not $enabledProperty -or $null -eq $enabledProperty.Value
})

$enabledCount = @($enabledConnectors).Count
$unknownCount = @($unknownStateConnectors).Count

if ($enabledCount -eq 0 -and $unknownCount -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO011' -Category EXO -Name 'Mail Flow Connector Hygiene' `
        -Result Info -Severity High -AffectedObject 'Inbound Connectors' `
        -Finding 'No enabled inbound connectors found' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector'
    return
}

$issues = [System.Collections.Generic.List[string]]::new()
$assessedConnectors = @($enabledConnectors) + @($unknownStateConnectors)

foreach ($connector in $assessedConnectors) {
    $enabledProperty = $connector.PSObject.Properties['Enabled']
    if (-not $enabledProperty -or $null -eq $enabledProperty.Value) {
        $issues.Add("'$($connector.Name)' - the Enabled property was not returned, so whether this connector is currently active was not established; it is assessed rather than skipped, and reported as a gap rather than a pass, because an unconfirmed connector is not assumed inactive")
    }

    if ($connector.RequireTls -ne $true) {
        $issues.Add("'$($connector.Name)' does not require TLS - accepts unencrypted or opportunistic-TLS inbound mail")
    }

    $senderIpCount = @($connector.SenderIPAddresses).Count
    $hasIpBinding = $senderIpCount -gt 0 -and $connector.RestrictDomainsToIPAddresses -eq $true
    $hasCertificateBinding = $connector.RequireTls -eq $true -and $connector.RestrictDomainsToCertificate -eq $true -and -not [string]::IsNullOrWhiteSpace([string]$connector.TlsSenderCertificateName)

    if (-not $hasIpBinding -and -not $hasCertificateBinding) {
        if ($senderIpCount -gt 0 -and $connector.RestrictDomainsToIPAddresses -ne $true) {
            $issues.Add("'$($connector.Name)' lists sender IP addresses but does not enable RestrictDomainsToIPAddresses - the IP list is not bound to connector authentication")
        }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$connector.TlsSenderCertificateName) -and $connector.RestrictDomainsToCertificate -ne $true) {
            $issues.Add("'$($connector.Name)' sets TlsSenderCertificateName but does not enable RestrictDomainsToCertificate - the certificate name is not bound to connector authentication")
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

$unknownSuffix = if ($unknownCount -gt 0) { ", $unknownCount with enabled state not established" } else { '' }
$affectedObjectLabel = "Inbound Connectors ($enabledCount enabled$unknownSuffix)"
$unknownErrorMessage = if ($unknownCount -gt 0) { "Get-InboundConnector did not return an Enabled value for $unknownCount connector(s)." } else { $null }

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO011' -Category EXO -Name 'Mail Flow Connector Hygiene' `
        -Result Warning -Severity High -AffectedObject $affectedObjectLabel `
        -Finding ($issues -join '; ') `
        -Recommendation 'Review flagged connectors. Require TLS and authenticate the source using either sender IP addresses bound with RestrictDomainsToIPAddresses, or a specific TlsSenderCertificateName. SenderDomains limits connector scope but does not authenticate the sending infrastructure. Run: Set-InboundConnector -Identity <name> -RequireTls $true and configure the appropriate IP or certificate restriction. For a connector whose Enabled state was not returned, confirm it directly with: Get-InboundConnector -Identity <name> | Format-List Enabled.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector' `
        -ErrorMessage $unknownErrorMessage
}
else {
    New-METCheckResult -CheckId 'MET-EXO011' -Category EXO -Name 'Mail Flow Connector Hygiene' `
        -Result Pass -Severity High -AffectedObject $affectedObjectLabel `
        -Finding 'All enabled inbound connectors require TLS and authenticate their source by bound IP addresses or a TLS sender certificate' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector'
}
