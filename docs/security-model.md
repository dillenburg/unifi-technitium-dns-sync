# Security model

- Give the UniFi key read access needed for discovery.
- Use dedicated Technitium tokens with only the required zone permissions.
  For multiple scopes, include all applicable forward and /24 reverse zones.
  Cluster discovery also needs to be permitted by the deployed API/account setup.
- HTTPS and certificate validation default to enabled. Configure the actual
  HTTPS listener port; setting the scheme does not enable TLS on the server.
  Mount a private CA bundle and use `SSL_CERT_FILE` where necessary.
- Plaintext Technitium HTTP needs both `TECHNITIUM_SCHEME=http` and
  `ALLOW_INSECURE_TECHNITIUM_HTTP=true`. Tokens then travel without encryption.
- Infisical bootstrap requires HTTPS and validates certificates. Its machine
  identity remains a bootstrap secret that must be provisioned securely.
- A matching external record is not automatically adopted. Owned records are
  checked against actual DNS before deletion. Unexpected drift blocks writes.
- Persist intent before mutation and verify results before confirming ownership.

The SQLite database and normal logs contain private hostnames, IP/MAC addresses
and operational history. Restrict storage access. Raw HTTP response bodies are
not included in error messages. Never upload runtime state, logs, backups or
.env files to issue reports. Git/Docker ignore rules reduce accidental inclusion;
they are not a replacement for reviewing what is staged.

The journal protects recovery logic; it cannot make remote DNS and local disk
one atomic system. Filesystem durability, external DNS writers, cluster role
changes and the privileges of credentials remain operational assumptions.
