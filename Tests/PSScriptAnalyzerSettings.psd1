@{
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        'PSUseBOMForUnicodeEncodedFile'
        'PSAvoidUsingWriteHost'
        'PSReviewUnusedParameter'
        'PSUseSingularNouns'
        'PSUseShouldProcessForStateChangingFunctions'
        'PSShouldProcess'
        'PSUseDeclaredVarsMoreThanAssignments'
        'PSAvoidUsingConvertToSecureStringWithPlainText'
    )

    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('7.4', '7.6')
        }
    }
}
