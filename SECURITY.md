# Security Policy

## Supported versions

Until the first stable release, security fixes are provided only for the latest
version on the default branch.

## Reporting a vulnerability

Please do not open a public issue for vulnerabilities that may expose DNS
write access, credentials, client inventories, or internal network details.

Use GitHub's private vulnerability reporting feature for the repository. If it
is unavailable, contact the repository owner privately before sharing details.

Include:

- affected version or commit;
- impact and prerequisites;
- minimal reproduction steps with sanitized data;
- whether credentials or DNS records may have been exposed.

Do not include real API tokens, SQLite databases, production logs, MAC
addresses, internal domains, or private IP inventories.

## Operational security

- Use dedicated least-privilege Technitium accounts.
- Keep `DRY_RUN=true` until a complete plan has been reviewed.
- Prefer HTTPS with certificate verification.
- Store `/data/state.db` on private persistent storage.
- Back up both managed zones before enabling writes.
- Treat every persistent `CONFLICT` as a manual investigation point.
