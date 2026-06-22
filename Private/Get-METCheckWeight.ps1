function Get-METCheckWeight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Critical','High','Medium','Low','Informational')] [string] $Severity
    )

    @{
        Critical      = 40
        High          = 20
        Medium        = 10
        Low           = 5
        Informational = 0
    }[$Severity]
}
