# Security

## Threat model

Web-SSH exposes an operating-system shell through a browser. Anyone who authenticates successfully can execute commands as the user running the service. The service does not create per-account OS users and does not sandbox commands.

The self-signed TLS certificate protects transport after the user explicitly trusts it; it does not authenticate the server to a first-time browser visitor. Users should verify the certificate fingerprint or use a VPN/reverse proxy when that distinction matters.

## Controls

- Argon2id password hashing (64 MiB, three iterations, two lanes)
- Rate limiting plus a 15-minute account lock after five failed logins
- Secure, HTTP-only, SameSite=Strict session cookies
- Server-side session revocation, 30-minute idle expiry, and 12-hour absolute expiry
- CSRF and Origin checks for state-changing and WebSocket requests
- Single-use, hashed invitation codes
- No terminal transcript storage
- Security-event audit retention capped at 90 days or 100,000 events

## Reporting

Report vulnerabilities privately to the repository owner. Do not include real credentials, terminal transcripts, database files, or private hostnames in a public issue.
