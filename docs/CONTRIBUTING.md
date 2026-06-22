# Contributing to MET

Thank you for contributing to MET. This guide explains how to add a new check, run the test suite, and submit a pull request.

---

## Adding a new check

### 1. Choose an ID

Check IDs follow the pattern `MET-<CATEGORY><NNN>`:

- `MET-MDO001` — first MDO check
- `MET-EXO007` — seventh EXO check
- `MET-Teams003` — third Teams check

Look at the existing check inventory in `README.md` and pick the next available ID in the appropriate category.

### 2. Create the check file

Create `Checks/<Category>/MET-<ID>-<ShortName>.ps1`.

Each check script is a standalone `.ps1` file (not a function). It is dot-sourced and executed by `Invoke-METTriage`. The script:

- Has access to all `Private/` helpers (`New-METCheckResult`, `Get-METCheckWeight`)
- Must **not** throw — wrap all EXO/Graph/Teams calls in `try/catch`
- Surfaces errors via the `Error` field of the result object, not as terminating exceptions
- Must output one or more `PSCustomObject` results via `New-METCheckResult`

Minimal check template:

```powershell
try {
    $data = Get-SomeEXOCmdlet -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-XXX999' -Category MDO -Name 'My Check' `
        -Result Fail -Severity High -AffectedObject 'Object Name' `
        -Finding 'Unable to retrieve data' `
        -Recommendation 'Ensure the account has Security Reader permissions.' `
        -ReferenceUrl 'https://aka.ms/...' -ErrorMessage $_.ToString()
    return
}

# ... assessment logic ...

New-METCheckResult -CheckId 'MET-XXX999' -Category MDO -Name 'My Check' `
    -Result Pass -Severity High -AffectedObject $data.Name `
    -Finding 'Setting is correctly configured' `
    -ReferenceUrl 'https://aka.ms/...'
```

### 3. Follow the result schema

| Field | Rules |
|---|---|
| `CheckId` | Must match the filename prefix exactly |
| `Category` | `MDO`, `EXO`, or `Teams` |
| `Result` | `Pass`, `Fail`, `Warning`, `Info`, `NotApplicable` |
| `Severity` | `Critical`, `High`, `Medium`, `Low`, `Informational` |
| `Finding` | Plain English, present tense, factual — no "you should" |
| `Recommendation` | Actionable steps, imperative mood |
| `ReferenceUrl` | `https://aka.ms/...` where possible |

### 4. Write Pester tests

Add tests to the appropriate file in `Tests/Unit/`:

- `Checks.MDO.Tests.ps1` — MDO checks
- `Checks.EXO.Tests.ps1` — EXO checks
- `Checks.Teams.Tests.ps1` — Teams checks

Tests must use `Mock` to simulate EXO/Graph/Teams cmdlets — never connect to a real tenant in unit tests. Define stubs in `BeforeAll` if the cmdlet is not already stubbed.

Minimum test cases per check:

1. All settings correct → `Pass`
2. Primary failure case → `Fail` (assert `Finding` content)
3. API failure (cmdlet throws) → `Fail` with `Error` populated

### 5. Write a check doc

Create `docs/checks/MET-<ID>-<ShortName>.md` using the structure:

```markdown
# MET-XXXNNN — Name

**Category:** MDO/EXO/Teams | **Severity:** High

## What it checks
## Why it matters
## Pass / Fail / Warning  (table)
## Recommendation
## Reference
```

### 6. Update the README

Add the new check to the check inventory table in `README.md`.

---

## Running the tests

Requires **Pester 5.x**:

```powershell
Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser

# Unit tests (no tenant connection required)
$config = New-PesterConfiguration
$config.Run.Path = './Tests/Unit'
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
```

---

## Code conventions

- **Approved verbs only** — `Invoke-`, `Get-`, `Test-`, `New-`, `Resolve-`
- **No inline comments** unless explaining a non-obvious workaround
- **No `Write-Host`** — use `Write-Verbose` for progress, `Write-Warning` for non-fatal issues
- **No positional parameters** on public functions
- **Error handling** — `try/catch` on all remote calls; surface in `Error` field, never throw
- **No plain-text secrets** — all auth through `Connect-METSession`
- **No external HTTP calls inside check scripts** — DNS lookups via `Resolve-DnsName` are allowed for email auth checks

---

## Pull request checklist

- [ ] New check file created with correct naming
- [ ] `New-METCheckResult` used for all output
- [ ] `try/catch` wraps all remote calls
- [ ] Pester tests added (Pass, Fail, and API-error scenarios)
- [ ] Check doc added to `docs/checks/`
- [ ] README check inventory updated
- [ ] All unit tests pass locally (`Invoke-Pester -Configuration $config`)

---

## Questions?

Open an issue at [github.com/pthoor/MET](https://github.com/pthoor/MET).
