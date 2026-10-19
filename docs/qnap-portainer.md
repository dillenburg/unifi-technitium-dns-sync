# Docker, QNAP and Portainer

Build from this repository's complete source directory. Start with
`compose.example.yml`; the alternative `compose.infisical-macvlan.example.yml`
expects an already-created Docker network and a free address supplied through
`DOCKER_NETWORK_NAME` and `CONTAINER_IPV4`.

1. Copy `.env.example` to `.env` and replace the example values locally.
2. Configure existing zones, API credentials, HTTPS listeners and CA trust.
3. Create a private `data` directory writable by container UID/GID 10001:10001.
   On a NAS, apply equivalent share ACLs; avoid world-writable permissions.
4. Keep `DRY_RUN=true` and start the selected Compose file.
5. Review a complete cycle, then follow [the live-run checks](recovery.md).

For example:

```sh
mkdir -p data
sudo chown 10001:10001 data
chmod 700 data
cp compose.example.yml compose.yml
docker compose up --build -d
docker compose logs -f unifi-technitium-dns-sync
```

The container runs without root, with a read-only root filesystem, dropped
capabilities and persistent `/data`. The healthcheck checks process existence
only; it does not prove successful synchronization or upstream connectivity.
Monitor completed cycles and conflicts separately.

## Infisical

Set `INFISICAL_ENABLED=true` and supply the Universal Auth client ID/secret,
project, environment and secret path. The bootstrap loads UNIFI_API_KEY,
DNS01_TOKEN and DNS02_TOKEN, then replaces itself with the sync process. Do not
put real credentials into an exported Portainer stack or this repository.
Direct mode uses the same three credentials from the environment.

## Multiple scopes

Place JSON on one line in `.env`, or use a quoted YAML scalar for
`SYNC_SCOPES_JSON` in a private Compose configuration. Each entry needs a unique
name and a non-overlapping IPv4 subnet. See [architecture](architecture.md) for
reverse-zone limitations. Do not run several containers against the same state
file or overlapping managed names.
