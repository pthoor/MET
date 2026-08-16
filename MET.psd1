@{
    ModuleVersion        = '0.6.1'
    GUID                 = '52cfd4a5-c6d6-4691-a195-ae0b24ac912b'
    Author               = 'Pierre Thoor'
    CompanyName          = 'Community'
    Copyright            = '(c) 2026 Pierre Thoor. MIT License.'
    Description          = 'Security Posture Scanner for MDO, EXO and Teams - assesses MDO, EXO/EOP, and Teams protection posture.'
    PowerShellVersion    = '7.4'
    RequiredModules      = @()
    # Dependencies are checked at runtime by Test-METPrerequisites and Connect-METSession.
    # Declaring them in RequiredModules causes a hard import failure when they aren't installed,
    # which prevents Test-METPrerequisites from running and guiding the user.
    # Required: ExchangeOnlineManagement 3.9+, Microsoft.Graph.Identity.SignIns 2.x, Microsoft.Graph.Groups 2.x
    # Optional: MicrosoftTeams 6.x+ (latest: 7.x) - Teams checks skip gracefully if not present.
    RootModule           = 'MET.psm1'
    FunctionsToExport    = @(
        'Connect-METSession'
        'Invoke-METTriage'
        'Get-METReport'
        'Test-METPrerequisites'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('MDO', 'Microsoft365', 'Defender', 'ExchangeOnline', 'Teams', 'Security', 'Posture', 'Assessment')
            LicenseUri   = 'https://github.com/pthoor/MET/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/pthoor/MET'
            ReleaseNotes = 'v0.6.1 - Fixes Microsoft 365 authentication on Linux and macOS. MicrosoftTeams 7.9.0 made Web Account Manager the default auth broker, which is Windows-only and broke Connect-MicrosoftTeams on Linux and macOS with a kernel32.dll load failure; Connect-METSession now forwards -UseDeviceAuthentication, -UserPrincipalName and -DisableWAM to the Teams leg and disables WAM automatically off Windows. Also corrects two parameter names that do not exist on Connect-MicrosoftTeams: certificate authentication now passes -Certificate (resolved from the thumbprint via X509Store) instead of -CertificateThumbprint, and managed identity now passes -Identity instead of -ManagedIdentity. Teams connection failures no longer hide their cause behind a suppressed import error and a generic warning. Also fixes an assembly load-order defect: Connect-METSession now connects Exchange Online before Microsoft Graph, because each module ships a different Microsoft.Identity.Client build and only the newest can satisfy the others.'
        }
    }
}
