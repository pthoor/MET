function Get-METCertificateByThumbprint {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [string] $Thumbprint
    )

    $normalized = $Thumbprint -replace '[^0-9A-Fa-f]', ''

    foreach ($location in @('CurrentUser', 'LocalMachine')) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $location)
        try {
            $store.Open('ReadOnly')
            $match = $store.Certificates | Where-Object { $_.Thumbprint -eq $normalized }
            if ($match) {
                return $match | Select-Object -First 1
            }
        }
        catch {
            Write-Verbose "Could not open the $location certificate store: $_"
        }
        finally {
            $store.Dispose()
        }
    }

    throw "No certificate with thumbprint '$Thumbprint' was found in the CurrentUser or LocalMachine 'My' store."
}
