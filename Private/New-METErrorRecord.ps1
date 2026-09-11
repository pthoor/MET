function New-METErrorRecord {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [Parameter(Mandatory)] [string] $ErrorId,
        [Parameter()] [System.Management.Automation.ErrorCategory] $Category = [System.Management.Automation.ErrorCategory]::InvalidOperation,
        [Parameter()] [object] $TargetObject = $null
    )

    # A bare `throw '<string>'` makes the FullyQualifiedErrorId the message text, so no
    # caller can catch by id and every wording change is a breaking change for them.
    [System.Management.Automation.ErrorRecord]::new(
        [System.InvalidOperationException]::new($Message),
        $ErrorId,
        $Category,
        $TargetObject)
}
