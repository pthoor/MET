@{
    ModuleVersion        = '0.11.0'
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
            ReleaseNotes = 'v0.11.0 - Mail-flow, authentication-surface and audit coverage. Adds seven checks for control planes MET previously had no visibility into: MET-EXO018 (Remote Domain Automatic Forwarding) closes the third and last automatic-forwarding control plane alongside the outbound spam policy and per-mailbox forwarding, so a tenant whose default remote domain permits forwarding to every external domain is no longer scored clean; MET-EXO019 (SMTP Client Authentication) reports legacy SMTP AUTH tenant-wide and enumerates per-mailbox overrides that re-enable it; MET-EXO020 (Connection Filter Policy Hygiene) reports IP allow-list entries and the third-party safe list, both of which bypass spam filtering and spoof intelligence; MET-EXO021 (Mailbox Audit Logging) and MET-EXO023 (Unified Audit Log Ingestion) report the audit state a compromise investigation depends on, neither of which can be backfilled after the fact; MET-EXO022 (Calendar and Contact Sharing) reports calendar detail and contacts exposed to all domains or anonymously; and MET-Teams015 (Teams Email Integration) reports channel email addresses, a mail ingress path that never traverses the mailbox delivery path and so is unaffected by Exchange transport rules. Also enhances three existing checks: MET-MDO005 now inspects the contents of the common attachment filter rather than only whether it is enabled, MET-MDO003 now covers impersonation protection for named external partner domains, and MET-Teams003 now covers external screen-control requests and anonymous meeting starts. Adds the first automated test coverage of the HTML report, including injection-safety assertions and browser-driven verification of its filtering and risk-acceptance behaviour. v0.10.0 - Connect-METSession security hardening. Fixes a confirmed cross-customer data leak in session reuse: Connect-METSession previously reused any live Exchange Online/Graph/Teams connection without verifying it belonged to the requested tenant, so running MET against two different -DelegatedOrganization customers in the same session without disconnecting in between could return a report labeled for one customer containing another customer''s actual configuration. Adds certificate-file authentication (-CertificatePath/-CertificatePassword) for non-Windows platforms, since -CertificateThumbprint is Windows-only. Scopes device-code authentication down to a documented headless-only fallback, with a warning on every use, per Microsoft''s current guidance to block it wherever possible. Adds Disconnect-METSession for clean session teardown across all three connection legs. Adds MET-MDO014 (Group Reference Audit) and expands MET-EXO014 (Advanced Delivery Policy) coverage. v0.9.0 - Quarantine policy accuracy pass. Fixes two confirmed false-positive bugs: MET-EXO009 previously flagged Microsoft''s own Standard/Strict preset security policies as Fail/Warning for impersonation, spoof, and phish quarantine verdicts, even though Microsoft''s own Strict preset uses full-access quarantine policies for those verdicts by design; corrected to only evaluate the two verdicts (Malware, High-Confidence Phish) that actually have a restrictive floor. MET-EXO004 previously flagged the built-in AdminOnlyAccessPolicy''s by-design "no access" configuration as a misconfiguration on every tenant; narrowed to evaluate only genuinely custom quarantine policies. Adds preset-aware retention handling to MET-EXO008 and a new informational check, MET-EXO017 (Quarantine Notification Cadence). v0.8.0 - Teams attack-surface hardening. Adds five new Teams checks: MET-Teams009 (Trial Tenant Federation Exposure), MET-Teams010 (Per-User External Access Policy Drift), MET-Teams011 (SecOps Blocklist Authority & Blocked Entities), MET-Teams012 (Call Reporting / vishing surface), and MET-Teams014 (Cross-Tenant Guest & External Collaboration, the first check with a direct Microsoft Graph dependency). Also fixes a real gap in MET-Teams003, which previously only evaluated the Global meeting policy and missed custom meeting policies entirely, and adds rule-level exception visibility to MET-Teams001 and MET-Teams004.'
        }
    }
}
