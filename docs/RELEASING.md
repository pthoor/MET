# Releasing MET

MET releases are published by `.github/workflows/publish.yml`. The workflow runs when a version tag is pushed (or when manually dispatched for an existing tag) and publishes the module to PowerShell Gallery before creating the matching GitHub release.

## One-time repository setup

1. In the GitHub repository, create a `production` environment.
2. Add a PowerShell Gallery API key as an environment secret named `PSGALLERY_API_KEY`. Do not store the key in the repository or pass it as a workflow input.
3. Add required reviewers or deployment branch protection to the `production` environment if release approval is required.

The workflow requests the API key only in the protected publish job. GitHub's built-in `GITHUB_TOKEN` is used separately to create the GitHub release.

## Release procedure

1. Update `ModuleVersion` and `ReleaseNotes` in `MET.psd1` on a branch.
2. Merge the version change to `main` after CI succeeds.
3. Create an annotated tag that exactly matches `v<ModuleVersion>`, then push it:

   ```bash
   git switch main
   git pull --ff-only
   git tag -a v0.6.0 -m "Release v0.6.0"
   git push origin v0.6.0
   ```

4. Approve the `production` deployment, if the environment requires approval.
5. Confirm that the workflow validation, PowerShell Gallery publication, build-provenance attestation, and GitHub release creation all complete successfully.

If a tag-triggered run fails before PowerShell Gallery accepts the package, merge the workflow fix to `main` and use **Run workflow** with the existing tag. The manual run checks out and validates that tag; do not move the tag. Once PowerShell Gallery has accepted a version, it cannot be overwritten or published again.

The publish job imports `Microsoft.PowerShell.PSResourceGet`, converts the secret API key to a `SecureString`, and calls `Publish-PSResource` with the staged module directory and the registered `PSGallery` repository. This follows the current PowerShell Gallery publishing guidance while ensuring the plaintext secret is never written to the repository or workflow log.

Release tags must point to a commit on `main`, and the tag must exactly match the module manifest version. PowerShell Gallery versions are immutable, so never reuse or move a released tag.
