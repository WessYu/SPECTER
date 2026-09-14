# Remote scanning

Remote scans accept only HTTP(S) URLs and are designed to remain passive.

Target policy blocks:

- `localhost` and `.localhost`;
- loopback;
- RFC1918/private ranges;
- link-local and unspecified addresses;
- common cloud metadata hostnames/addresses;
- URL-embedded credentials;
- non-HTTP(S) schemes.

DNS results are checked before connection and the selected address is pinned in the low-level HTTP request. Redirect destinations are resolved and revalidated independently. Requests have per-request and total deadlines, response-byte caps and redirect limits.

The TLS inspector can observe an invalid certificate without treating it as trusted, allowing SPECTER to report chain/hostname/expiry problems. Non-TLS response observations obtained from an invalid certificate must be interpreted with that transport warning in mind.

Route discovery follows observed same-site links and sitemap URLs only. It does not run directory wordlists or exploit endpoints.
