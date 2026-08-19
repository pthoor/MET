@{
    ModuleVersion        = '0.10.0'
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
    # Required: ExchangeOnlineManagement 3.9+
    # Optional: Microsoft.Graph.Identity.SignIns 2.x / Microsoft.Graph.Groups 2.x - group expansion
    #           falls back to Exchange Online cmdlets when Graph is missing or fails to connect.
    # Optional: MicrosoftTeams 6.x+ (latest: 7.x) - Teams checks skip gracefully if not present.
    RootModule           = 'MET.psm1'
    FunctionsToExport    = @(
        'Connect-METSession'
        'Disconnect-METSession'
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
            ReleaseNotes = 'v0.7.0 - Adds MET-MDO014 (Group Reference Audit), which flags groups referenced by enabled EOP/MDO policy rules via SentToMemberOf or ExceptIfSentToMemberOf that are empty (the rule matches nobody) or cannot be resolved at all. Microsoft Graph is now optional: a missing Graph module or a failed Connect-MgGraph no longer aborts Connect-METSession, and Expand-METGroupMembership degrades to Exchange Online cmdlets (Get-DistributionGroupMember, Get-UnifiedGroupLinks). Adds MSAL assembly-conflict pre-flight detection - each Microsoft 365 module ships its own Microsoft.Identity.Client build, and a downgrade request against an already-loaded newer build is now reported with an actionable message instead of an opaque 0x80131040 manifest mismatch. Importing MicrosoftTeams is also non-fatal now, matching the Graph and Teams connection legs. v0.6.1 - Fixes Microsoft 365 authentication on Linux and macOS. MicrosoftTeams 7.9.0 made Web Account Manager the default auth broker, which is Windows-only and broke Connect-MicrosoftTeams on Linux and macOS with a kernel32.dll load failure; Connect-METSession now forwards -UseDeviceAuthentication, -UserPrincipalName and -DisableWAM to the Teams leg and disables WAM automatically off Windows. Also corrects two parameter names that do not exist on Connect-MicrosoftTeams: certificate authentication now passes -Certificate (resolved from the thumbprint via X509Store) instead of -CertificateThumbprint, and managed identity now passes -Identity instead of -ManagedIdentity. Teams connection failures no longer hide their cause behind a suppressed import error and a generic warning. Also fixes an assembly load-order defect: Connect-METSession now connects Exchange Online before Microsoft Graph, because each module ships a different Microsoft.Identity.Client build and only the newest can satisfy the others.'
        }
    }
}
