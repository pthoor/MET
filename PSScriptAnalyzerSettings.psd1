@{
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # PS7+ uses UTF-8 without BOM by default — BOM is not required
        'PSUseBOMForUnicodeEncodedFile'

        # Write-Host is intentional in Get-METReport and Test-METPrerequisites
        # for coloured, formatted console output — these are display functions, not scripts
        'PSAvoidUsingWriteHost'

        # False positives: parameters used inside switch($PSCmdlet.ParameterSetName) blocks
        # and parameters intentionally declared for future use (DelegatedOrganization in Invoke-METTriage)
        'PSReviewUnusedParameter'

        # Our noun plurals are intentional and follow Microsoft's own naming patterns
        # (Test-METPrerequisites, Measure-SpfLookups)
        'PSUseSingularNouns'

        # New- factory functions that build in-memory PSCustomObjects do not change
        # system state and do not need SupportsShouldProcess
        'PSUseShouldProcessForStateChangingFunctions'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('7.4', '7.6')
        }
    }
}
