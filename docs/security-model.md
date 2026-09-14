# Security model

SPECTER is defensive software.

It is designed to:

- find security signals and unsafe configuration;
- detect regressions between releases;
- reduce common application-security risk;
- fail CI according to explicit policy.

It does not:

- prove absence of vulnerabilities;
- replace a professional security assessment;
- execute exploits;
- brute-force credentials or directories;
- bypass authentication or WAF controls;
- establish persistence or lateral movement;
- exfiltrate data;
- automatically exploit CVEs.

Remote scans are passive/low-impact and restricted to observable HTTP(S) behavior. The low-level requester resolves DNS before connecting, rejects non-public destinations, pins the chosen address for the connection and re-runs target policy after redirects. Localhost, private/link-local ranges and cloud metadata endpoints are blocked.

Runtime browser scans are opt-in. Browser networking is harder to pin against DNS rebinding because Chromium owns final resolution; for that reason runtime scanning is not the mechanism used to claim strict SSRF isolation in untrusted multi-tenant environments.
