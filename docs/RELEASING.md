# Releasing MET

MET releases are published by `.github/workflows/publish.yml`. The workflow runs when a version tag is pushed (or when manually dispatched for an existing tag) and publishes the module to PowerShell Gallery before creating the matching GitHub release.

## One-time repository setup

1. In the GitHub repository, create a `production` environment.
2. Add a PowerShell Gallery API key as an environment secret named `PSGALLERY_API_KEY`. Do not store the key in the repository or pass it as a workflow input.
3. Add required reviewers or deployment branch protection to the `production` environment if release approval is required.

The workflow requests the API key only in the protected publish job. GitHub's built-in `GITHUB_TOKEN` is used separately to create the GitHub release.

## Release procedure

1. Update `ModuleVersion` and `ReleaseNotes` in `MET.psd1` on a branch.
2. Add a matching `## [X.Y.Z] - <headline>` entry to `CHANGELOG.md` in the same branch, describing the same changes as `ReleaseNotes`. `CHANGELOG.md` ships inside the published module (staged and packed alongside `MET.psd1`), so it must stay in sync with every release.
3. Merge the version change to `main` after CI succeeds.
4. Create an annotated tag that exactly matches `v<ModuleVersion>`, then push it:

   ```bash
   git switch main
   git pull --ff-only
   version="$(pwsh -NoLogo -NoProfile -Command '(Import-PowerShellDataFile ./MET.psd1).ModuleVersion')"
   git tag -a "v${version}" -m "Release v${version}"
   git push origin "v${version}"
   ```

5. Approve the `production` deployment, if the environment requires approval.
6. Confirm that the workflow validation (lint, unit tests, integration tests, and HTML report browser tests), PowerShell Gallery publication, build-provenance attestation, and GitHub release creation all complete successfully.

If a tag-triggered run fails before PowerShell Gallery accepts the package, merge the workflow fix to `main` and use **Run workflow** with the existing tag. The manual run checks out and validates that tag; do not move the tag. Once PowerShell Gallery has accepted a version, it cannot be overwritten or published again.

## Packaging and provenance

The publish job copies an explicit list of files into a staging directory, packs it with `Compress-PSResource` into `dist/MET.<version>.nupkg`, attests that file with `actions/attest-build-provenance`, pushes that same file with `Publish-PSResource -NupkgPath`, and attaches it to the GitHub release. Publishing from the staging directory instead would let `Publish-PSResource` build its own package, whose digest would not match the attested one.

When a new file becomes part of the module - anything the manifest references, such as `FormatsToProcess`, or a new top-level directory loaded at runtime - add it to both `Copy-Item` lists in the "Stage and pack module" step. `Tests/Unit/MET.Module.Tests.ps1` ("Release staging") fails if a manifest-referenced file is missing from them.

To verify a release, download the `.nupkg` from its GitHub release and run:

```bash
gh attestation verify MET.<version>.nupkg --repo pthoor/MET
```

The module is not Authenticode-signed yet. If signing is added later, sign the staged files on a Windows runner before `Compress-PSResource`, so the attested package is the signed one.

The publish job imports `Microsoft.PowerShell.PSResourceGet` and calls `Publish-PSResource` with the packed `.nupkg`, the registered `PSGallery` repository, and the masked `PSGALLERY_API_KEY` environment secret. `Publish-PSResource -ApiKey` expects a plain string; converting the key to a `SecureString` causes PowerShell Gallery to reject it as invalid.
Release tags must point to a commit on `main`, and the tag must exactly match the module manifest version. PowerShell Gallery versions are immutable, so never reuse or move a released tag.
