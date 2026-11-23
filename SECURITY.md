# Security Policy

## Security Practices

- **Local binding by default**: The gateway listens on `127.0.0.1:8045` and the OAuth callback server binds to `127.0.0.1:18080`. If you expose the gateway over a network, place it behind a TLS reverse proxy with proper access control.
- **Separate API and Admin keys**: `api_key` (`qk_...`) grants access to inference endpoints only; `admin_key` (`qka_...`) grants access to the Web panel APIs only and requires same-origin requests. Do not share `admin_key` with third-party clients.
- **Encrypted local credentials**: Account tokens in `auths/` are stored with `AES-256-GCM` encryption using `data/encryption.key` (`0600`) or `AWSQUICK_ENCRYPTION_KEY`. Cross-machine migration uses passphrase-protected `AES-256-GCM + scrypt` archives.
- **Sensitive files**: Never commit or share `config.json`, `data/encryption.key`, `auths/`, `data/`, or `*.enc.json`.

## Reporting a Vulnerability

If you find a security issue, please report it privately via [GitHub Security Advisories](https://github.com/xiangwen-ctrl/awsquick2api/security/advisories/new) instead of opening a public issue.
