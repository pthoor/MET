function New-METCheckResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [ValidateSet('MDO','EXO','Teams')] [string] $Category,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('Pass','Fail','Warning','Info','NotApplicable')] [string] $Result,
        [Parameter(Mandatory)] [ValidateSet('Critical','High','Medium','Low','Informational')] [string] $Severity,
        [Parameter(Mandatory)] [string] $AffectedObject,
        [Parameter(Mandatory)] [string] $Finding,
        [string] $Recommendation = '',
        [string] $ReferenceUrl   = '',
        [string] $ErrorMessage   = $null
    )

    if ($ReferenceUrl -and $ReferenceUrl -notmatch '^https?://') {
        throw "ReferenceUrl must begin with 'https://' or 'http://': '$ReferenceUrl'"
    }

    $scoreMap = @{ Pass = 100; Fail = 0; Warning = 50; Info = $null; NotApplicable = $null }

    [PSCustomObject]@{
        CheckId        = $CheckId
        Category       = $Category
        Name           = $Name
        Result         = $Result
        Severity       = $Severity
        Score          = $scoreMap[$Result]
        AffectedObject = $AffectedObject
        Finding        = $Finding
        Recommendation = $Recommendation
        ReferenceUrl   = $ReferenceUrl
        Timestamp      = [datetime]::UtcNow
        Error          = $ErrorMessage
    }
}
