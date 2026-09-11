function Test-METExoSupportsDisableWam {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # WAM became Connect-ExchangeOnline's default authentication broker in
    # ExchangeOnlineManagement 3.7.0; the -DisableWAM switch itself shipped in 3.7.2. Passing it to an
    # older module produces a raw parameter-binding error rather than a usable message.
    # Probed rather than version-compared, matching the Teams leg's existing pattern.
    $command = Get-Command -Name 'Connect-ExchangeOnline' -ErrorAction SilentlyContinue
    if (-not $command) { return $false }

    return [bool] $command.Parameters.ContainsKey('DisableWAM')
}
