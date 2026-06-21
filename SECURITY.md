# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | No — please upgrade |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/pthoor/MET/security/advisories/new).

Include:
- Description of the vulnerability and potential impact
- Steps to reproduce or proof-of-concept (if safe to share)
- Affected version(s)

You will receive an acknowledgement within 5 business days. Critical issues will be patched as soon as possible and coordinated disclosure will be arranged.

## Scope

In scope:
- Credential or secret exposure in module code
- Vulnerabilities introduced via supply-chain dependencies
- Logic flaws that could cause the module to misreport security posture (false negatives on critical checks)

Out of scope:
- Theoretical issues with no practical impact
- Issues in the target M365 tenant being assessed (report those to Microsoft)

## Dependency Security

Dependencies are kept minimal and pinned in CI. GitHub Actions workflows are pinned to commit SHAs and updated via Dependabot. The module itself has no npm/Python/binary dependencies.
