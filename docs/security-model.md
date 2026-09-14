# Security model

SPECTER is defensive application-security software for systems the operator owns or is explicitly authorized to test.

It is designed to:

- detect unsafe source/build/runtime conditions;
- confirm selected conditions safely with inert evidence;
- detect security regressions;
- enforce CI policy.

It does not implement:

- brute force, password spraying or credential stuffing;
- authentication or MFA bypass;
- destructive exploitation;
- RCE, shell execution or reverse shells;
- persistence, privilege escalation or lateral movement;
- exfiltration;
- WAF evasion;
- malware or C2;
- automatic CVE exploitation;
- mass scanning, DoS or unbounded fuzzing;
- directory wordlists against guessed administrative paths.

## Passive remote scanning

Passive low-level requests resolve DNS before connecting, reject private/reserved destinations, pin the selected address and revalidate redirect destinations.

## Authorized active scanning

Active scanning is a separate module. A remote URL is not enough to authorize it.

Authorization modes are:

1. localhost / loopback: automatically authorized for local testing;
2. explicitly configured preview hostname;
3. verified remote hostname through `/.well-known/specter-verification.txt`.

Remote authorization is hostname-specific and expires. Redirects to another hostname are not authorized.

Verification tokens are generated with cryptographic randomness. The local and API stores persist token hashes rather than plaintext verification tokens after generation.

Active requests have a hard request budget, request-rate limit, endpoint/parameter caps, timeouts and cancellation. Evidence is passed through central redaction.

## Safe validation contract

SPECTER uses inert markers such as `SPECTER_CANARY_<random>` to detect reflection. It does not send functional XSS payloads.

Open redirect checks use the reserved non-routable destination `https://specter.invalid/` and never follow that redirect.

Host and forwarded-header checks use `specter.invalid` only while the network connection remains DNS-pinned to the authorized target. They are not SSRF probes.

CSRF checks prefer an `inconclusive` result rather than performing an unsafe mutation.

POST requests are limited to observed login/logout flows when the operator has explicitly provided a test account. Passwords, Authorization values, full cookies and session IDs are not stored in reports or audit logs.

`confirmed` means the unsafe condition was reproduced with safe evidence. It does not mean SPECTER exploited the application.

SPECTER cannot prove an application is secure and does not replace a professional manual assessment.
