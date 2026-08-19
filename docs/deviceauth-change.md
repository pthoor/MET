MET — Connect-METSession.ps1 hardening

1. Tenant-scoped session reuse (highest priority — cross-customer data leak)

All three legs reuse any live connection without verifying it belongs to the requested tenant. EXO uses Get-ConnectionInformation | Where State -eq 'Connected' | Select -First 1; Graph uses any Get-MgContext; Teams uses any Get-CsTenant. Running MET against customer B while a session to customer A is live produces a report labelled B containing A's configuration.

Compute a $requestedOrg from -DelegatedOrganization / -TenantId.
Reuse a connection only when its Organization / TenantId / DelegatedOrganization matches.
If a connection exists for a different tenant, throw with the actual connected org named and instruct the user to run Disconnect-METSession — do not silently reconnect or disconnect on their behalf.
Apply the same check to Graph ($mgContext.TenantId) and Teams ($teamsConnection.TenantId).
Also verify the auth mode matches: an interactive session must not satisfy a ServicePrincipal/ManagedIdentity request.
Cover with Pester cases in Tests/Unit/Connect-METSession.Tests.ps1: matching tenant reuses, mismatched tenant throws, no session connects.

2. Add Disconnect-METSession

New public function, added to FunctionsToExport in MET.psd1. Disconnects EXO (Disconnect-ExchangeOnline -Confirm:$false), Graph (Disconnect-MgGraph), and Teams (Disconnect-MicrosoftTeams), each in its own try/catch so one failure doesn't block the others. -Verbose reports what was torn down. Referenced by the error message in item 1. Document the tenant-switch workflow in the README.

3. Make app-only auth work on Linux (this is the Codespaces fix)

ServicePrincipal currently accepts only -CertificateThumbprint, and Get-METCertificateByThumbprint opens X509Store('My', CurrentUser/LocalMachine). On Linux that store is empty or unavailable, so cert-based app-only auth is effectively Windows-only today — which is exactly why device code became the Codespaces path.

Add -CertificatePath + -CertificatePassword ([SecureString]) to the ServicePrincipal set, mutually exclusive with -CertificateThumbprint.
Load via X509Certificate2 from file; pass the object to EXO as -Certificate (or -CertificateFilePath/-CertificatePassword), to Graph as -Certificate, and to Teams as -Certificate.
Keep the thumbprint path for Windows; when -CertificateThumbprint is used on non-Windows and the store lookup fails, throw naming -CertificatePath as the alternative rather than suggesting device code.
Extend Get-METCertificateByThumbprint or add Get-METCertificate handling both sources, returning X509Certificate2.

With that, your Codespaces dev loop uses a cert from a Codespaces secret against your own test tenant — no interactive flow, no device code, and it matches the auth mode a customer would use for scheduled runs.

4. Scope the device-code guidance

Four failure paths currently recommend -UseDeviceAuthentication as the generic retry (EXO catch, Graph catch, Teams generic catch, Teams DllNotFoundException catch).

On Windows: recommend -DisableWAM and -UserPrincipalName only. Never suggest device code.
On non-Windows: recommend -DisableWAM first; mention device code only as the headless-host fallback, with a one-line note that the flow is frequently blocked by Conditional Access and is associated with active phishing campaigns.
Emit Write-Warning at connect time whenever -UseDeviceAuthentication is actually used.

5. Record the auth method in the report

Return an object from Connect-METSession (or set module state) carrying auth mode, tenant identity, and which services connected; surface it in the Get-METReport header. Lets a customer see how the data was gathered and lets their SOC reconcile a deviceCodeFlow sign-in with your run instead of triaging it as an incident.

6. Fix the README/code contradiction

The Teams leg already passes -DisableWAM automatically off Windows ($disableWamRequested = $DisableWAM -or -not $IsWindows), which resolves the kernel32.dll P/Invoke. README line ~210 still states -UseDeviceAuthentication is required on Linux/macOS. Re-test with -DisableWAM alone in a Codespace and narrow the doc to the genuine case — headless host with no browser reachable at all — or drop the claim.

Constraint for whoever implements this: don't change check logic, output shape, or the Interactive/ServicePrincipal/ManagedIdentity parameter-set names. Diff-style edits, existing Pester structure, PSScriptAnalyzer clean against the repo's settings file.