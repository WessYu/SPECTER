# Security Policy

SPECTER is a defensive Application Security project.

## Reporting a vulnerability

Please do not open a public issue for vulnerabilities that could expose users, credentials, tokens, or deployment infrastructure.

Use GitHub's private security reporting for this repository when available. Include:

- affected version or commit;
- reproduction steps using non-destructive inputs;
- expected and observed behavior;
- security impact;
- suggested mitigation, if known.

Do not include real secrets, session cookies, access tokens, or personal data in reports.

## Scope

SPECTER performs passive and low-impact security analysis by default. Reports about behavior that intentionally avoids exploitation, brute force, credential attacks, persistence, lateral movement, exfiltration, or destructive actions are not considered defects unless the defensive boundary can itself be bypassed.

## Supported versions

Until the first stable release, security fixes are applied to the latest commit on `main`.
