# UniFi → Technitium DNS Sync

A conservative, crash-safe synchronization service that creates forward and
reverse DNS records in Technitium DNS Server from active UniFi Network clients.

The project is designed for operators who prefer **fail-closed automation**:
it never adopts existing external records, never overwrites an RRset, and
records every intended write in SQLite before touching DNS.

> [!WARNING]
> This service can modify and delete DNS records. Start with `DRY_RUN=true`,
> use a dedicated least-privilege Technitium account, and back up both zones
> before the first live run.

## Highlights

- Discovers the current Technitium cluster Primary dynamically.
- Never falls back to writing to a reachable Secondary.
- Manages A and PTR records as one logical pair.
- Uses a persistent SQLite write-ahead journal:
  `RESERVED → A_CREATED → COMPLETE`.
- Rolls incomplete transactions forward after a crash.
- Marks unexplained states as `CONFLICT` and disables further writes.
- Adds records with `overwrite=false`; A and PTR are written separately.
- Deletes only records that exactly match stored ownership.
- Builds the new pair before retiring superseded owned values.
- Uses `clients.last_seen` as the only authority for stale cleanup.
- Supports direct environment-based secrets or an optional Infisical bootstrap.
- Uses only the Python standard library at runtime.

## Non-goals

- It is not a general-purpose DNS reconciliation engine.
- It does not manage records outside the configured subnet and suffix.
- It does not adopt matching records that were created outside this service.
- It does not repair conflicts automatically.
- It does not enable or configure DHCP on Technitium.

## Safety model

```text
UniFi client
    │
    ▼
Read A and PTR, validate exact state
    │
    ▼
Commit RESERVED to SQLite
    │
    ▼
POST A → read and verify
    │
    ▼
Commit A_CREATED
    │
    ▼
POST PTR → read and verify
    │
    ▼
Atomically store A/PTR ownership + COMPLETE
```

Recovery runs after Primary discovery and before each normal sync cycle. See
[Recovery](docs/recovery.md) and [Security model](docs/security-model.md).

## Requirements

- Python 3.11 or newer, or Docker/Compose
- UniFi Network API access
- A Technitium DNS Server cluster or standalone clustered Primary API endpoint
- Existing authoritative forward and reverse zones
- Dedicated Technitium tokens for both configured bootstrap nodes
- Persistent storage for `/data/state.db`

The Technitium account should only have View/Modify/Delete permissions on the
zones managed by this service (all relevant forward and /24 reverse zones
when multiple scopes are configured).

## Quick start with Docker Compose

```bash
cp .env.example .env
cp compose.example.yml compose.yml
```

Edit `.env` and keep:

```dotenv
DRY_RUN=true
```

Create `data/` with write permissions for UID/GID `10001:10001` (see
[deployment](docs/qnap-portainer.md)), then build and start:

```bash
docker compose up --build -d
docker compose logs -f unifi-technitium-dns-sync
```

The first complete cycle should show:

- `SERVICE_START` with `phase=4` and `dry_run=true`
- `TECHNITIUM_PRIMARY`
- `DNS_RECOVERY_START`
- `DNS_RECOVERY_COMPLETE`
- `DNS_WRITES_DISABLED`
- only `DNS_PAIR_WOULD_*` actions

It must not show `DNS_TX_RESERVED`, `DNS_RECORD_ADD`, or
`DNS_RECORD_DELETE` while dry-run is enabled.

## Enabling live writes

1. Complete at least one clean dry-run cycle.
2. Investigate conflicts and agree ownership/names; do not blindly delete external records.
3. Back up the forward zone, reverse zone, and SQLite state.
4. Confirm that the tokens cannot modify unrelated zones.
5. Set `DRY_RUN=false`.
6. Restart the container and observe the full first cycle.

Expected sequence for a new client:

```text
DNS_TX_RESERVED
DNS_RECORD_ADD        record_type=A
DNS_TX_STATE          state=A_CREATED
DNS_RECORD_ADD        record_type=PTR
DNS_TX_COMPLETE
```

Stop and investigate before any further changes if a log contains
`DNS_TX_CONFLICT`, `DNS_RETIREMENT_CONFLICT`, or `DNS_RECOVERY_BLOCKED`.

## Configuration

All deployment-specific values are supplied through environment variables.
There are no private network or DNS defaults in the source.

### Required runtime values

| Variable | Purpose |
|---|---|
| `UNIFI_NETWORK_HOST` | UniFi Network host or address |
| `UNIFI_API_KEY` | Read-only UniFi API credential |
| `TECHNITIUM_DNS01_HOST` | First cluster bootstrap node |
| `TECHNITIUM_DNS02_HOST` | Second cluster bootstrap node |
| `DNS01_TOKEN` | Token valid on the first node |
| `DNS02_TOKEN` | Token valid on the second node |
| `SYNC_SUBNET` | Managed IPv4 subnet; required unless `SYNC_SCOPES_JSON` is set |
| `DNS_SUFFIX` | Existing forward zone and generated client suffix; may instead be provided per scope |

### Multiple networks

`SYNC_SCOPES_JSON` overrides the single-subnet configuration:

```json
[{"name":"lab","subnet":"192.0.2.0/24","dns_suffix":"clients.example.com"},{"name":"iot","subnet":"198.51.100.0/24","dns_suffix":"clients.example.com"}]
```

Scopes must not overlap. Desired names must be unique across a shared suffix.
UniFi clients are fetched once per cycle, then processed by scope. The current
reverse-zone derivation assumes /24 reverse zones, even for differently sized
configured subnets; provision each required zone. RFC 2317 layouts and IPv6 are
not supported. See [architecture and limitations](docs/architecture.md).

### Optional values

| Variable | Default | Purpose |
|---|---:|---|
| `UNIFI_NETWORK_PORT` | `443` | UniFi HTTPS port |
| `UNIFI_NETWORK_SITE` | `default` | UniFi site name |
| `UNIFI_NETWORK_VERIFY_SSL` | `true` | Verify UniFi TLS certificates |
| `TECHNITIUM_SCHEME` | `https` | Technitium API transport |
| `TECHNITIUM_PORT` | `5380` | Technitium API port |
| `TECHNITIUM_VERIFY_SSL` | `true` | Verify Technitium TLS certificates |
| `ALLOW_INSECURE_TECHNITIUM_HTTP` | `false` | Required explicit opt-in for HTTP |
| `SYNC_NETWORK_NAME` | `managed-network` | Name used in logs |
| `POLL_INTERVAL` | `300` | Seconds between cycles |
| `STALE_AFTER_DAYS` | `30` | Minimum absent-client age before cleanup |
| `DB_PATH` | `/data/state.db` | Persistent SQLite database |
| `DRY_RUN` | `true` | Global DNS write kill switch |

Boolean variables accept only `true` or `false`.

### TLS and plaintext HTTP

TLS verification is enabled by default for both systems. Set `TECHNITIUM_PORT`
to the actual configured HTTPS API listener; the default port does not itself
enable HTTPS on the server. If your internal PKI
uses a private CA, mount the CA bundle into the container and configure Python's
standard certificate environment variables rather than disabling verification.

Technitium HTTP is rejected unless both conditions are explicit:

```dotenv
TECHNITIUM_SCHEME=http
ALLOW_INSECURE_TECHNITIUM_HTTP=true
```

This sends bearer tokens in plaintext on the local network and is not
recommended.

## Infisical mode

Set `INFISICAL_ENABLED=true` to start through `infisical_bootstrap.py`. The
bootstrap authenticates using Universal Auth, loads only these runtime values,
and replaces itself with the sync process:

- `UNIFI_API_KEY`
- `DNS01_TOKEN`
- `DNS02_TOKEN`

The Infisical client ID, client secret, project ID, environment, and secret path
remain deployment configuration. Secret values are never written to SQLite.

For a Portainer/QNAP-style deployment with an existing Macvlan network, use
`compose.infisical-macvlan.example.yml`. Network name, container address,
Infisical URL, and all infrastructure addresses remain private `.env` values.
See [QNAP/Portainer deployment](docs/qnap-portainer.md).

## Persistent data

The database contains client MAC addresses, hostnames, IP addresses, record
ownership, and transaction history. Treat it as private operational data.

Never commit:

- `data/`
- `state.db`
- `state.db-wal`
- `state.db-shm`
- `.env`

These paths are ignored by both Git and Docker build context rules.

## Development

Run the standard-library test suite:

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

The tests use an isolated temporary SQLite database and an in-memory fake DNS;
they do not contact UniFi, Technitium, or Infisical.

## Documentation

- [Architecture](docs/architecture.md)
- [Recovery](docs/recovery.md)
- [Security model](docs/security-model.md)
- [QNAP/Portainer deployment](docs/qnap-portainer.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE).
