# Remote scanning

SPECTER has two distinct remote modes.

## Passive

`specter scan https://example.com` performs passive, low-impact observation. It can inspect TLS, headers, cookies, CSP/CORS behavior and routes that the application itself exposes.

The target policy blocks:

- localhost and loopback for passive remote mode;
- RFC1918/private ranges;
- link-local and unspecified addresses;
- common cloud metadata hostnames/addresses;
- URL-embedded credentials;
- non-HTTP(S) schemes.

DNS is resolved before connection and the selected address is pinned. Redirect destinations are independently resolved and revalidated. Requests have timeouts, byte limits and redirect limits.

## Active

`specter pentest` and `specter scan --active` add bounded validation. Localhost becomes allowed only for the active local-test path. Private non-loopback networks and metadata endpoints remain blocked by the same safe-request policy.

Remote active mode additionally requires exact-host authorization. See [Active security](active-security.md).

## Discovery

Both scanners consume legitimate observed surface information. Active discovery is limited to:

- HTML links and forms;
- observed fetch/XHR literals;
- explicitly observed Next/application routes;
- explicitly published OpenAPI/Swagger documents;
- `sitemap.xml`;
- routes already observed by SPECTER;
- explicit API references in referenced JavaScript assets.

SPECTER does not generate `/admin`, `/.git`, `/phpmyadmin` or other guessed paths from wordlists.

## Redirects

Passive requests may follow redirects only after the destination passes target policy.

Active requests additionally enforce the authorized hostname. An external `Location` used for open-redirect validation is recorded without navigation.
