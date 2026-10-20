@{
    ModuleVersion        = '0.13.0'
    GUID                 = '52cfd4a5-c6d6-4691-a195-ae0b24ac912b'
    Author               = 'Pierre Thoor'
    CompanyName          = 'Community'
    Copyright            = '(c) 2026 Pierre Thoor. MIT License.'
    Description          = 'Security Posture Scanner for MDO, EXO and Teams - assesses MDO, EXO/EOP, and Teams protection posture.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    RequiredModules      = @()
    # Dependencies are checked at runtime by Test-METPrerequisites and Connect-METSession.
    # Declaring them in RequiredModules causes a hard import failure when they aren't installed,
    # which prevents Test-METPrerequisites from running and guiding the user.
    # Required: ExchangeOnlineManagement 3.7.2+
    # Optional: Microsoft.Graph.Identity.SignIns 2.x / Microsoft.Graph.Groups 2.x - group expansion
    #           falls back to Exchange Online cmdlets when Graph is missing or fails to connect.
    # Optional: MicrosoftTeams 6.x+ (latest: 7.x) - Teams checks skip gracefully if not present.
    RootModule           = 'MET.psm1'
    FormatsToProcess     = @('MET.Format.ps1xml')
    FunctionsToExport    = @(
        'Connect-METSession'
        'Disconnect-METSession'
        'Invoke-METAssessment'
        'Get-METCheck'
        'Get-METReport'
        'Import-METReport'
        'Test-METPrerequisites'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @('Invoke-METTriage')
    PrivateData          = @{
        PSData = @{
            Tags         = @('MDO', 'Microsoft365', 'Defender', 'ExchangeOnline', 'Teams', 'Security', 'Posture', 'Assessment')
            LicenseUri   = 'https://github.com/pthoor/MET/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/pthoor/MET'
            IconUri      = 'https://raw.githubusercontent.com/pthoor/MET/main/assets/favicon-180.png'
            ReleaseNotes = 'v0.13.0 - Pre-flight access and module compatibility checks. Test-METPrerequisites -TestConnection checks the live Exchange Online, Microsoft Graph and Teams sessions before an assessment: read access in each service, and every Graph scope MET requests. Test-METPrerequisites now also checks that the installed modules can load together: Graph submodules on the Microsoft.Graph.Authentication version, Graph before 2.41.0 or Teams bundling an MSAL that conflicts with Exchange Online, and an older MSAL already loaded in the session. Connect-METSession no longer requests the unused Organization.Read.All Graph scope, which caused an admin consent prompt in tenants that had consented to the rest; names the cause when the Microsoft Graph Command Line Tools enterprise app blocks sign-in (AADSTS50105, AADSTS65001); no longer starts a Graph sign-in that cannot succeed on Graph before 2.41.0; and no longer prints the Teams account object. See https://github.com/pthoor/MET/blob/main/CHANGELOG.md'
        }
    }
}
