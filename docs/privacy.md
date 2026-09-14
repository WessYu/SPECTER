# Privacy

SPECTER minimizes sensitive collection.

The central redaction layer is applied to scanner evidence before human/machine report output and again before persisted finding evidence. Logs are configured to redact authorization headers, cookies, set-cookie values and common secret fields.

The product should not persist passwords, session-token contents, raw cookie values or submitted form contents. Cookie scanning records security attributes rather than cookie contents. API keys and browser session tokens are stored as SHA-256 hashes; full API keys are shown only once at creation.

Runtime navigation blocks state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`, etc.) rather than submitting forms that could create, purchase, delete or mutate user data.
