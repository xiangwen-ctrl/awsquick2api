# Security Policy

## Security Practices

- **Local binding by default**: The gateway listens on `127.0.0.1:8045` and the OAuth callback server binds to `127.0.0.1:18080`. If you expose the gateway over a network, place it behind a TLS reverse proxy with proper access control.
- **Separate API and Admin keys**: `api_key` (`qk_...`) grants access to inference endpoints only; `admin_key` (`qka_...`) grants access to the Web panel APIs only and requires same-origin requests. Do not share `admin_key` with third-party clients.
- **Encrypted local credentials**: Account tokens in `auths/` are stored with `AES-256-GCM` encryption using `data/encryption.key` (`0600`) or `AWSQUICK_ENCRYPTION_KEY`. Cross-machine migration uses passphrase-protected `AES-256-GCM + scrypt` archives.
- **Sensitive files**: Never commit or share `config.json`, `data/encryption.key`, `auths/`, `data/`, or `*.enc.json`.

## Reporting a Vulnerability

Please do **not** disclose vulnerability details (exploit steps, tokens, account data, logs) in a public issue.

1. **Preferred — private report**: use [GitHub Security Advisories](https://github.com/xiangwen-ctrl/awsquick2api/security/advisories/new) ("Report a vulnerability") if it is enabled for this repository.
2. **If private reporting is unavailable**: open a public [GitHub Issue](https://github.com/xiangwen-ctrl/awsquick2api/issues/new) titled `Security contact request` containing **no technical details**, and ask the repository owner for a private channel. The owner will reply with a way to share the details privately (for example, by enabling a private advisory for you).
3. Non-sensitive hardening suggestions (documentation, defaults, defense-in-depth ideas without a working exploit) may be filed as regular issues.

When reporting, include the affected version (`/healthz` or the startup log line `AWSQuick2API vX.Y.Z`), platform, and a minimal reproduction. Redact all `api_key` / `admin_key` values (`qk_...` / `qka_...`), OAuth tokens, account emails and proxy credentials.

## Supported Versions

Security fixes are released for the latest published release only.
