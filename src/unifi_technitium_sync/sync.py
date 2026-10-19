#!/usr/bin/env python3

import ipaddress
import json
import logging
import os
import re
import sqlite3
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone, timedelta


# ============================================================
# Configuration
# ============================================================

def env_bool(name, default):
    value = os.getenv(name, default).lower()
    if value not in {"true", "false"}:
        raise RuntimeError(f"{name} must be true or false")
    return value == "true"


def required_env(name):
    value = os.environ[name].strip()
    if not value:
        raise RuntimeError(f"{name} must not be empty")
    return value


UNIFI_HOST = required_env("UNIFI_NETWORK_HOST")
UNIFI_PORT = int(os.getenv("UNIFI_NETWORK_PORT", "443"))
UNIFI_SITE = os.getenv("UNIFI_NETWORK_SITE", "default")
UNIFI_API_KEY = os.environ["UNIFI_API_KEY"]

UNIFI_VERIFY_SSL = env_bool("UNIFI_NETWORK_VERIFY_SSL", "true")

TECHNITIUM_PORT = int(os.getenv("TECHNITIUM_PORT", "5380"))
TECHNITIUM_SCHEME = os.getenv("TECHNITIUM_SCHEME", "https").lower()
TECHNITIUM_VERIFY_SSL = env_bool("TECHNITIUM_VERIFY_SSL", "true")
ALLOW_INSECURE_TECHNITIUM_HTTP = env_bool("ALLOW_INSECURE_TECHNITIUM_HTTP", "false")
if TECHNITIUM_SCHEME not in {"http", "https"}:
    raise RuntimeError("TECHNITIUM_SCHEME must be http or https")
if TECHNITIUM_SCHEME == "http" and not ALLOW_INSECURE_TECHNITIUM_HTTP:
    raise RuntimeError("Plaintext HTTP requires ALLOW_INSECURE_TECHNITIUM_HTTP=true")
TECHNITIUM_SSL_CONTEXT = (
    ssl.create_default_context() if TECHNITIUM_VERIFY_SSL
    else ssl._create_unverified_context()
)

TECHNITIUM_BOOTSTRAP = [
    {
        "name": "dns01",
        "host": required_env("TECHNITIUM_DNS01_HOST"),
        "token": os.environ["DNS01_TOKEN"],
    },
    {
        "name": "dns02",
        "host": required_env("TECHNITIUM_DNS02_HOST"),
        "token": os.environ["DNS02_TOKEN"],
    },
]

SYNC_NETWORK_NAME = os.getenv("SYNC_NETWORK_NAME", "managed-network")

DNS_SUFFIX = os.getenv("DNS_SUFFIX", "").rstrip(".").lower()


def parse_sync_scopes():

    raw_scopes = os.getenv("SYNC_SCOPES_JSON")

    if not raw_scopes:
        raw_scopes = json.dumps(
            [
                {
                    "name": SYNC_NETWORK_NAME,
                    "subnet": required_env("SYNC_SUBNET"),
                    "dns_suffix": DNS_SUFFIX,
                }
            ]
        )

    try:
        configured_scopes = json.loads(raw_scopes)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "SYNC_SCOPES_JSON must contain valid JSON"
        ) from exc

    if not isinstance(configured_scopes, list) or not configured_scopes:
        raise RuntimeError(
            "SYNC_SCOPES_JSON must be a non-empty JSON list"
        )

    scopes = []
    names = set()

    for index, configured in enumerate(configured_scopes):

        if not isinstance(configured, dict):
            raise RuntimeError(
                "Each SYNC_SCOPES_JSON entry must be an object"
            )

        name = str(configured.get("name", "")).strip()
        subnet_text = str(configured.get("subnet", "")).strip()
        dns_suffix = str(
            configured.get("dns_suffix", DNS_SUFFIX)
        ).rstrip(".").lower()

        if not name:
            raise RuntimeError(
                f"SYNC_SCOPES_JSON entry {index} has no name"
            )

        normalized_name = name.casefold()

        if normalized_name in names:
            raise RuntimeError(
                f"Duplicate sync scope name: {name}"
            )

        try:
            subnet = ipaddress.ip_network(
                subnet_text,
                strict=False,
            )
        except ValueError as exc:
            raise RuntimeError(
                f"Invalid subnet for sync scope {name}: "
                f"{subnet_text}"
            ) from exc

        if subnet.version != 4:
            raise RuntimeError(
                f"Sync scope {name} must use an IPv4 network"
            )

        if (not dns_suffix or len(dns_suffix) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in dns_suffix.split(".")
        )):
            raise RuntimeError(
                f"Invalid DNS suffix for sync scope {name}"
            )

        for previous in scopes:
            if subnet.overlaps(previous["subnet"]):
                raise RuntimeError(
                    f"Sync scopes {previous['name']} and {name} "
                    "have overlapping subnets"
                )

        names.add(normalized_name)
        scopes.append(
            {
                "name": name,
                "subnet": subnet,
                "dns_suffix": dns_suffix,
            }
        )

    return tuple(scopes)


SYNC_SCOPES = parse_sync_scopes()

# Compatibility alias for the previous single-scope configuration.
SYNC_SUBNET = SYNC_SCOPES[0]["subnet"]

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))
STALE_AFTER_DAYS = int(os.getenv("STALE_AFTER_DAYS", "30"))

DRY_RUN = env_bool("DRY_RUN", "true")

DB_PATH = os.getenv("DB_PATH", "/data/state.db")


# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

log = logging.getLogger("unifi-dns-sync")

ACTIVE_NETWORK = None


def event(action, network=None, **kwargs):
    payload = {
        "action": action,
        "network": (
            network
            or ACTIVE_NETWORK
            or SYNC_NETWORK_NAME
        ),
        **kwargs,
    }

    log.info(json.dumps(payload, sort_keys=True))


# ============================================================
# SSL
# ============================================================

if UNIFI_VERIFY_SSL:
    UNIFI_SSL_CONTEXT = ssl.create_default_context()
else:
    UNIFI_SSL_CONTEXT = ssl._create_unverified_context()


# ============================================================
# Generic JSON HTTP
# ============================================================

def http_json(
    url,
    headers=None,
    ssl_context=None,
    label="HTTP",
    method="GET",
    form_data=None,
):

    if method not in {"GET", "POST"}:
        raise RuntimeError(
            f"Unsupported HTTP method: {method}"
        )

    body = None
    request_headers = dict(headers or {})

    if form_data is not None:
        if method != "POST":
            raise RuntimeError(
                "Form data is only valid for POST requests"
            )

        body = urllib.parse.urlencode(
            form_data
        ).encode("utf-8")

        request_headers[
            "Content-Type"
        ] = "application/x-www-form-urlencoded"

    request = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=20,
            context=ssl_context,
        ) as response:

            body = response.read()

            event(
                "HTTP_RESPONSE",
                service=label,
                status=response.status,
                content_type=response.headers.get("Content-Type", ""),
                body_length=len(body),
            )

            if not body:
                raise RuntimeError(f"{label} returned empty response")

            try:
                return json.loads(body.decode("utf-8"))

            except json.JSONDecodeError as exc:
                preview = body[:300].decode(
                    "utf-8",
                    errors="replace",
                )

                raise RuntimeError(
                    f"{label} returned non-JSON"
                ) from exc

    except urllib.error.HTTPError as exc:

        body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        raise RuntimeError(
            f"{label} HTTP {exc.code}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"{label} connection failed: {exc}"
        ) from exc


# ============================================================
# UniFi
# ============================================================

def unifi_get(path):

    url = f"https://{UNIFI_HOST}:{UNIFI_PORT}{path}"

    return http_json(
        url,
        headers={
            "X-API-Key": UNIFI_API_KEY,
            "Accept": "application/json",
        },
        ssl_context=UNIFI_SSL_CONTEXT,
        label="unifi",
    )


def response_data(result):

    if isinstance(result, list):
        return result

    if isinstance(result, dict):
        data = result.get("data")

        if isinstance(data, list):
            return data

    return []


# ============================================================
# Database
# ============================================================

db = sqlite3.connect(DB_PATH)

# SQLite's own WAL complements the application-level DNS
# write-ahead journal below. FULL synchronous mode makes the
# RESERVED commit durable before the first external DNS write.
db.execute("PRAGMA journal_mode = WAL")
db.execute("PRAGMA synchronous = FULL")
db.execute("PRAGMA foreign_keys = ON")

db.execute("""
CREATE TABLE IF NOT EXISTS clients (
    mac TEXT PRIMARY KEY,
    hostname TEXT,
    ip TEXT,
    fqdn TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL
)
""")

db.execute("""
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
)
""")

db.execute("""
CREATE TABLE IF NOT EXISTS technitium_nodes (
    name TEXT PRIMARY KEY,
    node_id INTEGER,
    ip TEXT,
    url TEXT,
    node_type TEXT,
    state TEXT,
    discovered_via TEXT,
    last_seen TEXT NOT NULL
)
""")

db.execute("""
CREATE TABLE IF NOT EXISTS dns_records_owned (
    record_type TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    zone TEXT NOT NULL,
    client_mac TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (record_type, name)
)
""")

db.execute("""
CREATE TABLE IF NOT EXISTS dns_pair_transactions (
    tx_id TEXT PRIMARY KEY,
    client_mac TEXT NOT NULL,
    fqdn TEXT NOT NULL,
    ip TEXT NOT NULL,
    a_name TEXT NOT NULL,
    a_value TEXT NOT NULL,
    a_zone TEXT NOT NULL,
    a_action TEXT NOT NULL
        CHECK(a_action IN ('ADD', 'UPDATE', 'NO_CHANGE')),
    a_previous_value TEXT,
    ptr_name TEXT NOT NULL,
    ptr_value TEXT NOT NULL,
    ptr_zone TEXT NOT NULL,
    ptr_action TEXT NOT NULL
        CHECK(ptr_action IN ('ADD', 'UPDATE', 'NO_CHANGE')),
    ptr_previous_value TEXT,
    state TEXT NOT NULL
        CHECK(state IN (
            'RESERVED',
            'A_CREATED',
            'COMPLETE',
            'CONFLICT'
        )),
    cleanup_pending INTEGER NOT NULL DEFAULT 0
        CHECK(cleanup_pending IN (0, 1)),
    conflict_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
)
""")

db.execute("""
CREATE INDEX IF NOT EXISTS idx_dns_pair_tx_open
ON dns_pair_transactions(state, cleanup_pending)
""")

db.execute("""
CREATE INDEX IF NOT EXISTS idx_dns_pair_tx_mac
ON dns_pair_transactions(client_mac)
""")

db.execute("""
CREATE TABLE IF NOT EXISTS dns_record_retirements (
    retirement_id TEXT PRIMARY KEY,
    tx_id TEXT,
    record_type TEXT NOT NULL
        CHECK(record_type IN ('A', 'PTR')),
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    zone TEXT NOT NULL,
    client_mac TEXT NOT NULL,
    expected_remaining_json TEXT NOT NULL,
    remove_ownership INTEGER NOT NULL
        CHECK(remove_ownership IN (0, 1)),
    reason TEXT NOT NULL,
    state TEXT NOT NULL
        CHECK(state IN ('RESERVED', 'COMPLETE', 'CONFLICT')),
    conflict_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
)
""")

db.execute("""
CREATE INDEX IF NOT EXISTS idx_dns_retirement_open
ON dns_record_retirements(state)
""")

db.commit()


# ============================================================
# Metadata
# ============================================================

def metadata_get(key):

    row = db.execute(
        "SELECT value FROM metadata WHERE key = ?",
        (key,),
    ).fetchone()

    return row[0] if row else None


def metadata_set(key, value):

    db.execute(
        """
        INSERT INTO metadata (key, value)
        VALUES (?, ?)
        ON CONFLICT(key)
        DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )

    db.commit()


# ============================================================
# Helpers
# ============================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def parse_timestamp(value):

    if not value:
        return None

    try:
        return datetime.fromisoformat(value)

    except ValueError:
        return None


def canonical_name(value):
    return str(value).rstrip(".").lower()


def normalize_hostname(value):

    if not value:
        return None

    value = str(value).strip().lower()

    value = re.sub(
        r"[^a-z0-9-]+",
        "-",
        value,
    )

    value = re.sub(
        r"-+",
        "-",
        value,
    ).strip("-")

    return value[:63] if value else None


def reverse_zone_for_ip(ip):

    address = ipaddress.ip_address(ip)

    if address.version != 4:
        raise RuntimeError("Only IPv4 is supported")

    octets = str(address).split(".")

    return (
        f"{octets[2]}."
        f"{octets[1]}."
        f"{octets[0]}."
        "in-addr.arpa"
    )


def ptr_name_for_ip(ip):
    return ipaddress.ip_address(ip).reverse_pointer


# ============================================================
# UniFi Site Discovery
# ============================================================

def discover_site():

    event(
        "SITE_DISCOVERY_START",
        requested_site=UNIFI_SITE,
    )

    result = unifi_get(
        "/proxy/network/api/self/sites"
    )

    sites = response_data(result)

    event(
        "SITE_DISCOVERY_RESULT",
        site_count=len(sites),
    )

    for site in sites:

        site_name = site.get("name")

        event(
            "SITE_FOUND",
            name=site_name,
            description=site.get("desc"),
        )

        if site_name == UNIFI_SITE:

            event(
                "SITE_SELECTED",
                site=UNIFI_SITE,
            )

            return UNIFI_SITE

    raise RuntimeError(
        f"Configured UniFi site '{UNIFI_SITE}' was not found"
    )


# ============================================================
# UniFi Clients
# ============================================================

def get_connected_clients(site):

    result = unifi_get(
        f"/proxy/network/api/s/{site}/stat/sta"
    )

    clients = response_data(result)

    event(
        "CLIENT_PAGE",
        site=site,
        page_clients=len(clients),
    )

    return clients


def extract_ip(raw):

    for key in (
        "ip",
        "ipAddress",
        "fixed_ip",
        "fixedIp",
    ):
        value = raw.get(key)

        if value:
            return str(value)

    return None


def extract_mac(raw):

    for key in ("mac", "macAddress"):

        value = raw.get(key)

        if value:
            return str(value).strip().lower()

    return None


def extract_hostname(raw):

    for key in (
        "hostname",
        "name",
        "displayName",
    ):

        hostname = normalize_hostname(
            raw.get(key)
        )

        if hostname:
            return hostname

    return None


def parse_client(raw, scope=None):

    if scope is None:
        scope = SYNC_SCOPES[0]

    ip = extract_ip(raw)
    mac = extract_mac(raw)

    if not ip or not mac:
        return None

    try:
        address = ipaddress.ip_address(ip)

    except ValueError:
        return None

    if address not in scope["subnet"]:
        return None

    hostname = extract_hostname(raw)

    if not hostname:

        event(
            "SKIP",
            network=scope["name"],
            reason="no_usable_hostname",
            mac=mac,
            ip=ip,
        )

        return None

    return {
        "mac": mac,
        "ip": ip,
        "hostname": hostname,
        "fqdn": f"{hostname}.{scope['dns_suffix']}",
        "network": scope["name"],
        "dns_suffix": scope["dns_suffix"],
    }


# ============================================================
# Client State
# ============================================================

def process_client(client, baseline):

    timestamp = utc_now()

    row = db.execute(
        """
        SELECT hostname, ip, fqdn
        FROM clients
        WHERE mac = ?
        """,
        (client["mac"],),
    ).fetchone()

    if row is None:

        event(
            "BASELINE_ADD" if baseline else "WOULD_ADD",
            mac=client["mac"],
            hostname=client["hostname"],
            ip=client["ip"],
            fqdn=client["fqdn"],
            dry_run=DRY_RUN,
        )

        db.execute(
            """
            INSERT INTO clients (
                mac,
                hostname,
                ip,
                fqdn,
                first_seen,
                last_seen,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client["mac"],
                client["hostname"],
                client["ip"],
                client["fqdn"],
                timestamp,
                timestamp,
                timestamp,
            ),
        )

        return

    old_hostname, old_ip, old_fqdn = row

    changed = (
        old_hostname != client["hostname"]
        or old_ip != client["ip"]
        or old_fqdn != client["fqdn"]
    )

    if changed:

        event(
            "CLIENT_STATE_CHANGE",
            mac=client["mac"],
            old_hostname=old_hostname,
            new_hostname=client["hostname"],
            old_ip=old_ip,
            new_ip=client["ip"],
            old_fqdn=old_fqdn,
            new_fqdn=client["fqdn"],
        )

        db.execute(
            """
            UPDATE clients
            SET hostname = ?,
                ip = ?,
                fqdn = ?,
                last_seen = ?,
                updated_at = ?
            WHERE mac = ?
            """,
            (
                client["hostname"],
                client["ip"],
                client["fqdn"],
                timestamp,
                timestamp,
                client["mac"],
            ),
        )

    else:

        db.execute(
            """
            UPDATE clients
            SET last_seen = ?
            WHERE mac = ?
            """,
            (
                timestamp,
                client["mac"],
            ),
        )


# ============================================================
# Ownership
# ============================================================

def get_owned_record(record_type, name):

    name = canonical_name(name)

    row = db.execute(
        """
        SELECT
            value,
            zone,
            client_mac,
            created_at,
            updated_at,
            last_seen
        FROM dns_records_owned
        WHERE record_type = ?
          AND name = ?
        """,
        (
            record_type,
            name,
        ),
    ).fetchone()

    if not row:
        return None

    return {
        "record_type": record_type,
        "name": name,
        "value": row[0],
        "zone": row[1],
        "client_mac": row[2],
        "created_at": row[3],
        "updated_at": row[4],
        "last_seen": row[5],
    }


def get_owned_records_for_mac(mac):

    rows = db.execute(
        """
        SELECT
            record_type,
            name,
            value,
            zone,
            client_mac,
            created_at,
            updated_at,
            last_seen
        FROM dns_records_owned
        WHERE client_mac = ?
        """,
        (mac,),
    ).fetchall()

    return [
        {
            "record_type": row[0],
            "name": row[1],
            "value": row[2],
            "zone": row[3],
            "client_mac": row[4],
            "created_at": row[5],
            "updated_at": row[6],
            "last_seen": row[7],
        }
        for row in rows
    ]


def touch_owned_record(record_type, name, client_mac):

    timestamp = utc_now()

    db.execute(
        """
        UPDATE dns_records_owned
        SET last_seen = ?
        WHERE record_type = ?
          AND name = ?
          AND client_mac = ?
        """,
        (
            timestamp,
            record_type,
            canonical_name(name),
            client_mac,
        ),
    )


# ============================================================
# Technitium
# ============================================================

def technitium_get(host, token, path, params=None):

    url = f"{TECHNITIUM_SCHEME}://{host}:{TECHNITIUM_PORT}{path}"

    if params:
        url += "?" + urllib.parse.urlencode(params)

    result = http_json(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        label="technitium",
        ssl_context=TECHNITIUM_SSL_CONTEXT,
    )

    if result.get("status") != "ok":

        raise RuntimeError(
            "Technitium API error: "
            f"status={result.get('status')}, "
            "response details suppressed"
        )

    return result


def technitium_post(primary, path, params):

    if DRY_RUN:
        raise RuntimeError(
            "DRY_RUN blocks all Technitium writes"
        )

    if primary.get("node_type") != "Primary":
        raise RuntimeError(
            "Refusing Technitium write: target was not "
            "dynamically identified as Primary"
        )

    url = (
        f"{TECHNITIUM_SCHEME}://{primary['host']}:"
        f"{TECHNITIUM_PORT}{path}"
    )

    result = http_json(
        url,
        headers={
            "Authorization": (
                f"Bearer {primary['token']}"
            ),
            "Accept": "application/json",
        },
        label="technitium",
        ssl_context=TECHNITIUM_SSL_CONTEXT,
        method="POST",
        form_data=params,
    )

    if result.get("status") != "ok":
        raise RuntimeError(
            "Technitium API error: "
            f"status={result.get('status')}, "
            "response details suppressed"
        )

    return result


# ============================================================
# Technitium Cluster
# ============================================================

def cache_cluster_nodes(nodes, discovered_via):

    timestamp = utc_now()

    for node in nodes:

        addresses = node.get("ipAddresses") or []

        ip = addresses[0] if addresses else None

        db.execute(
            """
            INSERT INTO technitium_nodes (
                name,
                node_id,
                ip,
                url,
                node_type,
                state,
                discovered_via,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(name)
            DO UPDATE SET
                node_id = excluded.node_id,
                ip = excluded.ip,
                url = excluded.url,
                node_type = excluded.node_type,
                state = excluded.state,
                discovered_via = excluded.discovered_via,
                last_seen = excluded.last_seen
            """,
            (
                node.get("name"),
                node.get("id"),
                ip,
                node.get("url"),
                node.get("type"),
                node.get("state"),
                discovered_via,
                timestamp,
            ),
        )

    db.commit()


def discover_technitium_cluster():

    errors = []

    for bootstrap in TECHNITIUM_BOOTSTRAP:

        event(
            "TECHNITIUM_BOOTSTRAP_TRY",
            node=bootstrap["name"],
            host=bootstrap["host"],
        )

        try:

            result = technitium_get(
                bootstrap["host"],
                bootstrap["token"],
                "/api/admin/cluster/state",
            )

            response = result.get("response") or {}

            if not response.get("clusterInitialized"):
                raise RuntimeError(
                    "Technitium cluster is not initialized"
                )

            nodes = response.get("clusterNodes") or []

            if not nodes:
                raise RuntimeError(
                    "Technitium returned no cluster nodes"
                )

            event(
                "TECHNITIUM_CLUSTER_DISCOVERED",
                via=bootstrap["name"],
                version=response.get("version"),
                cluster_domain=response.get("clusterDomain"),
                nodes=len(nodes),
            )

            cache_cluster_nodes(
                nodes,
                bootstrap["name"],
            )

            primary = None

            for node in nodes:

                addresses = node.get("ipAddresses") or []

                event(
                    "TECHNITIUM_NODE",
                    name=node.get("name"),
                    node_id=node.get("id"),
                    node_type=node.get("type"),
                    state=node.get("state"),
                    ip_addresses=addresses,
                )

                if node.get("type") == "Primary":
                    primary = node

            if not primary:
                raise RuntimeError(
                    "No Technitium Primary found"
                )

            primary_ips = primary.get("ipAddresses") or []

            if not primary_ips:
                raise RuntimeError(
                    "Technitium Primary has no IP address"
                )

            primary_ip = primary_ips[0]
            primary_token = None

            for candidate in TECHNITIUM_BOOTSTRAP:

                if candidate["host"] == primary_ip:
                    primary_token = candidate["token"]
                    break

            if not primary_token:
                raise RuntimeError(
                    f"Primary discovered at {primary_ip}, "
                    "but no token is configured"
                )

            event(
                "TECHNITIUM_PRIMARY",
                name=primary.get("name"),
                host=primary_ip,
                state=primary.get("state"),
            )

            return {
                "name": primary.get("name"),
                "host": primary_ip,
                "token": primary_token,
                "url": primary.get("url"),
                "node_type": primary.get("type"),
                "state": primary.get("state"),
            }

        except Exception as exc:

            errors.append(
                f"{bootstrap['name']}: {exc}"
            )

            event(
                "TECHNITIUM_BOOTSTRAP_FAILED",
                node=bootstrap["name"],
                host=bootstrap["host"],
                error=str(exc),
            )

    raise RuntimeError(
        "Technitium cluster discovery failed: "
        + " | ".join(errors)
    )


# ============================================================
# DNS Reads
# ============================================================

def get_dns_records(primary, name, zone):

    result = technitium_get(
        primary["host"],
        primary["token"],
        "/api/zones/records/get",
        {
            "domain": name,
            "zone": zone,
        },
    )

    response = result.get("response") or {}
    records = response.get("records") or []

    event(
        "DNS_RECORD_READ",
        name=name,
        zone=zone,
        records=len(records),
    )

    return records


def find_a_record(records, fqdn):

    target = canonical_name(fqdn)
    matches = []

    for record in records:

        if canonical_name(
            record.get("name", "")
        ) != target:
            continue

        if record.get("type") != "A":
            continue

        value = (
            record.get("rData")
            or {}
        ).get("ipAddress")

        if value:
            matches.append(str(value))

    return matches


def find_ptr_record(records, ptr_name):

    target = canonical_name(ptr_name)
    matches = []

    for record in records:

        if canonical_name(
            record.get("name", "")
        ) != target:
            continue

        if record.get("type") != "PTR":
            continue

        rdata = record.get("rData") or {}

        value = (
            rdata.get("ptrName")
            or rdata.get("domainName")
            or rdata.get("name")
        )

        if value:
            matches.append(
                canonical_name(value)
            )

    return matches


def normalize_record_values(record_type, values):

    normalized = []

    for value in values:

        if record_type == "PTR":
            value = canonical_name(value)
        else:
            value = str(value)

        if value not in normalized:
            normalized.append(value)

    return sorted(normalized)


def read_record_values(
    primary,
    record_type,
    name,
    zone,
):

    records = get_dns_records(
        primary,
        name,
        zone,
    )

    if record_type == "A":
        values = find_a_record(
            records,
            name,
        )

    elif record_type == "PTR":
        values = find_ptr_record(
            records,
            name,
        )

    else:
        raise RuntimeError(
            f"Unsupported record type: {record_type}"
        )

    return normalize_record_values(
        record_type,
        values,
    )


def add_dns_record(
    primary,
    record_type,
    name,
    value,
    zone,
    tx_id,
):

    expected_state = (
        "RESERVED"
        if record_type == "A"
        else "A_CREATED"
    )
    prefix = (
        "a"
        if record_type == "A"
        else "ptr"
    )

    journal = db.execute(
        f"""
        SELECT state, {prefix}_name,
               {prefix}_value, {prefix}_zone
        FROM dns_pair_transactions
        WHERE tx_id = ?
        """,
        (tx_id,),
    ).fetchone()

    expected_value = (
        canonical_name(value)
        if record_type == "PTR"
        else str(value)
    )

    if (
        not journal
        or journal[0] != expected_state
        or canonical_name(journal[1])
        != canonical_name(name)
        or (
            canonical_name(journal[2])
            if record_type == "PTR"
            else str(journal[2])
        )
        != expected_value
        or canonical_name(journal[3])
        != canonical_name(zone)
    ):
        raise RuntimeError(
            "Refusing DNS add without a matching durable "
            f"journal state ({expected_state})"
        )

    params = {
        "domain": canonical_name(name),
        "zone": canonical_name(zone),
        "type": record_type,
        "overwrite": "false",
        "comments": (
            "managed-by=unifi-dns-sync;"
            f"tx={tx_id}"
        ),
    }

    if record_type == "A":
        params["ipAddress"] = str(value)
        params["ptr"] = "false"

    elif record_type == "PTR":
        params["ptrName"] = canonical_name(
            value
        )

    else:
        raise RuntimeError(
            f"Unsupported record type: {record_type}"
        )

    event(
        "DNS_RECORD_ADD",
        record_type=record_type,
        name=name,
        value=value,
        zone=zone,
        tx_id=tx_id,
        overwrite=False,
    )

    technitium_post(
        primary,
        "/api/zones/records/add",
        params,
    )


def delete_dns_record(
    primary,
    record_type,
    name,
    value,
    zone,
    retirement_id,
):

    journal = db.execute(
        """
        SELECT state, record_type, name, value, zone
        FROM dns_record_retirements
        WHERE retirement_id = ?
        """,
        (retirement_id,),
    ).fetchone()

    expected_value = (
        canonical_name(value)
        if record_type == "PTR"
        else str(value)
    )

    if (
        not journal
        or journal[0] != "RESERVED"
        or journal[1] != record_type
        or canonical_name(journal[2])
        != canonical_name(name)
        or (
            canonical_name(journal[3])
            if record_type == "PTR"
            else str(journal[3])
        )
        != expected_value
        or canonical_name(journal[4])
        != canonical_name(zone)
    ):
        raise RuntimeError(
            "Refusing DNS delete without a matching "
            "durable retirement reservation"
        )

    params = {
        "domain": canonical_name(name),
        "zone": canonical_name(zone),
        "type": record_type,
    }

    if record_type == "A":
        params["ipAddress"] = str(value)
        params["updateSvcbHints"] = "false"

    elif record_type == "PTR":
        params["ptrName"] = canonical_name(
            value
        )

    else:
        raise RuntimeError(
            f"Unsupported record type: {record_type}"
        )

    event(
        "DNS_RECORD_DELETE",
        record_type=record_type,
        name=name,
        value=value,
        zone=zone,
        retirement_id=retirement_id,
    )

    technitium_post(
        primary,
        "/api/zones/records/delete",
        params,
    )


# ============================================================
# Record Analysis
# ============================================================

def analyze_record(
    record_type,
    name,
    expected_value,
    existing_values,
    zone,
    client_mac,
):

    name = canonical_name(name)

    if record_type == "PTR":
        expected_value = canonical_name(
            expected_value
        )
        existing_values = [
            canonical_name(v)
            for v in existing_values
        ]

    # Remove duplicate API values without hiding a genuine
    # multi-value RRset. Ordering is not significant in DNS.
    existing_values = normalize_record_values(
        record_type,
        existing_values,
    )

    owned = get_owned_record(
        record_type,
        name,
    )

    result = {
        "record_type": record_type,
        "name": name,
        "zone": zone,
        "expected_value": expected_value,
        "existing_values": existing_values,
        "client_mac": client_mac,
        "owned": owned,
        "state": None,
        "reason": None,
    }

    # --------------------------------------------------------
    # Nothing exists
    # --------------------------------------------------------

    if not existing_values:

        if owned:
            result["state"] = "DRIFT"
            result["reason"] = "owned_record_missing"
            return result

        result["state"] = "ADD"
        result["reason"] = "record_missing"

        return result

    # --------------------------------------------------------
    # Multiple values: fail closed
    # --------------------------------------------------------

    if len(existing_values) != 1:

        result["state"] = "CONFLICT"

        result["reason"] = (
            "multiple_existing_values"
        )

        return result

    current_value = existing_values[0]

    # --------------------------------------------------------
    # External record
    # --------------------------------------------------------

    if not owned:

        if current_value == expected_value:

            result["state"] = "EXTERNAL_MATCH"
            result["reason"] = (
                "matching_external_record"
            )

        else:

            result["state"] = "CONFLICT"
            result["reason"] = (
                "external_record_conflict"
            )

        return result

    # --------------------------------------------------------
    # Ownership belongs to another client
    # --------------------------------------------------------

    if owned["client_mac"] != client_mac:

        result["state"] = "CONFLICT"
        result["reason"] = (
            "ownership_client_mismatch"
        )

        return result

    owned_value = owned["value"]

    if record_type == "PTR":
        owned_value = canonical_name(
            owned_value
        )

    # --------------------------------------------------------
    # Actual DNS differs from what we last owned.
    #
    # Somebody may have manually changed it.
    # Fail closed.
    # --------------------------------------------------------

    if current_value != owned_value:

        result["state"] = "DRIFT"
        result["reason"] = (
            "dns_differs_from_owned_value"
        )

        return result

    # --------------------------------------------------------
    # Desired state already present
    # --------------------------------------------------------

    if current_value == expected_value:

        result["state"] = "NO_CHANGE"
        result["reason"] = "owned_match"

        return result

    # --------------------------------------------------------
    # Safe update candidate
    # --------------------------------------------------------

    result["state"] = "UPDATE"
    result["reason"] = "owned_value_changed"

    return result


# ============================================================
# Persistent DNS Write-Ahead Journal
# ============================================================

def pair_transaction_from_row(row):

    keys = (
        "tx_id",
        "client_mac",
        "fqdn",
        "ip",
        "a_name",
        "a_value",
        "a_zone",
        "a_action",
        "a_previous_value",
        "ptr_name",
        "ptr_value",
        "ptr_zone",
        "ptr_action",
        "ptr_previous_value",
        "state",
        "cleanup_pending",
        "conflict_reason",
        "created_at",
        "updated_at",
        "completed_at",
    )

    return dict(zip(keys, row))


def load_pair_transactions_for_recovery():

    rows = db.execute(
        """
        SELECT
            tx_id,
            client_mac,
            fqdn,
            ip,
            a_name,
            a_value,
            a_zone,
            a_action,
            a_previous_value,
            ptr_name,
            ptr_value,
            ptr_zone,
            ptr_action,
            ptr_previous_value,
            state,
            cleanup_pending,
            conflict_reason,
            created_at,
            updated_at,
            completed_at
        FROM dns_pair_transactions
        WHERE state IN ('RESERVED', 'A_CREATED')
           OR (state = 'COMPLETE' AND cleanup_pending = 1)
        ORDER BY created_at, tx_id
        """
    ).fetchall()

    return [
        pair_transaction_from_row(row)
        for row in rows
    ]


def expected_values_for_action(
    record_type,
    action,
    value,
    previous_value,
    after_write,
):

    if action == "NO_CHANGE":
        values = [value]

    elif action == "ADD":
        values = [value] if after_write else []

    elif action == "UPDATE":

        if not previous_value:
            raise RuntimeError(
                "UPDATE journal entry has no previous value"
            )

        values = [previous_value]

        if after_write:
            values.append(value)

    else:
        raise RuntimeError(
            f"Invalid journal action: {action}"
        )

    return normalize_record_values(
        record_type,
        values,
    )


def reserve_pair_transaction(
    client,
    a_analysis,
    ptr_analysis,
):

    if DRY_RUN:
        raise RuntimeError(
            "DRY_RUN forbids real journal reservations"
        )

    tx_id = str(uuid.uuid4())
    timestamp = utc_now()

    a_previous = (
        a_analysis["existing_values"][0]
        if a_analysis["state"] == "UPDATE"
        else None
    )

    ptr_previous = (
        ptr_analysis["existing_values"][0]
        if ptr_analysis["state"] == "UPDATE"
        else None
    )

    try:
        db.execute("BEGIN IMMEDIATE")

        existing = db.execute(
            """
            SELECT tx_id, state
            FROM dns_pair_transactions
            WHERE client_mac = ?
              AND (
                    state IN ('RESERVED', 'A_CREATED')
                    OR (
                        state = 'COMPLETE'
                        AND cleanup_pending = 1
                    )
                  )
            LIMIT 1
            """,
            (client["mac"],),
        ).fetchone()

        if existing:
            raise RuntimeError(
                "Client already has an unfinished DNS "
                f"transaction: {existing[0]} ({existing[1]})"
            )

        db.execute(
            """
            INSERT INTO dns_pair_transactions (
                tx_id,
                client_mac,
                fqdn,
                ip,
                a_name,
                a_value,
                a_zone,
                a_action,
                a_previous_value,
                ptr_name,
                ptr_value,
                ptr_zone,
                ptr_action,
                ptr_previous_value,
                state,
                cleanup_pending,
                created_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, 'RESERVED', 0, ?, ?
            )
            """,
            (
                tx_id,
                client["mac"],
                canonical_name(client["fqdn"]),
                client["ip"],
                a_analysis["name"],
                a_analysis["expected_value"],
                a_analysis["zone"],
                a_analysis["state"],
                a_previous,
                ptr_analysis["name"],
                canonical_name(
                    ptr_analysis["expected_value"]
                ),
                ptr_analysis["zone"],
                ptr_analysis["state"],
                ptr_previous,
                timestamp,
                timestamp,
            ),
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    event(
        "DNS_TX_RESERVED",
        tx_id=tx_id,
        client_mac=client["mac"],
        fqdn=client["fqdn"],
        ip=client["ip"],
        a_action=a_analysis["state"],
        ptr_action=ptr_analysis["state"],
    )

    row = db.execute(
        """
        SELECT
            tx_id, client_mac, fqdn, ip,
            a_name, a_value, a_zone,
            a_action, a_previous_value,
            ptr_name, ptr_value, ptr_zone,
            ptr_action, ptr_previous_value,
            state, cleanup_pending, conflict_reason,
            created_at, updated_at, completed_at
        FROM dns_pair_transactions
        WHERE tx_id = ?
        """,
        (tx_id,),
    ).fetchone()

    return pair_transaction_from_row(row)


def set_pair_transaction_state(tx_id, state):

    if state not in {"A_CREATED"}:
        raise RuntimeError(
            f"Invalid intermediate state: {state}"
        )

    timestamp = utc_now()

    try:
        db.execute("BEGIN IMMEDIATE")
        cursor = db.execute(
            """
            UPDATE dns_pair_transactions
            SET state = ?,
                updated_at = ?
            WHERE tx_id = ?
              AND state = 'RESERVED'
            """,
            (state, timestamp, tx_id),
        )

        if cursor.rowcount != 1:
            raise RuntimeError(
                "DNS transaction state transition failed: "
                f"{tx_id} -> {state}"
            )

        db.commit()

    except Exception:
        db.rollback()
        raise

    event(
        "DNS_TX_STATE",
        tx_id=tx_id,
        state=state,
    )


def mark_pair_transaction_conflict(tx, reason):

    timestamp = utc_now()

    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            """
            UPDATE dns_pair_transactions
            SET state = 'CONFLICT',
                conflict_reason = ?,
                updated_at = ?
            WHERE tx_id = ?
            """,
            (reason, timestamp, tx["tx_id"]),
        )
        db.commit()

    except Exception:
        db.rollback()
        raise

    event(
        "DNS_TX_CONFLICT",
        tx_id=tx["tx_id"],
        client_mac=tx["client_mac"],
        reason=reason,
        action_taken="FAIL_CLOSED",
    )


def complete_pair_transaction(tx):

    timestamp = utc_now()
    cleanup_pending = int(
        tx["a_action"] == "UPDATE"
        or tx["ptr_action"] == "UPDATE"
    )

    records = (
        (
            "A",
            tx["a_name"],
            tx["a_value"],
            tx["a_zone"],
        ),
        (
            "PTR",
            tx["ptr_name"],
            canonical_name(tx["ptr_value"]),
            tx["ptr_zone"],
        ),
    )

    try:
        db.execute("BEGIN IMMEDIATE")

        for record_type, name, value, zone in records:

            existing = db.execute(
                """
                SELECT client_mac
                FROM dns_records_owned
                WHERE record_type = ?
                  AND name = ?
                """,
                (record_type, canonical_name(name)),
            ).fetchone()

            if (
                existing
                and existing[0] != tx["client_mac"]
            ):
                raise RuntimeError(
                    "Ownership changed while completing "
                    f"transaction {tx['tx_id']}"
                )

            db.execute(
                """
                INSERT INTO dns_records_owned (
                    record_type,
                    name,
                    value,
                    zone,
                    client_mac,
                    created_at,
                    updated_at,
                    last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(record_type, name)
                DO UPDATE SET
                    value = excluded.value,
                    zone = excluded.zone,
                    updated_at = excluded.updated_at,
                    last_seen = excluded.last_seen
                """,
                (
                    record_type,
                    canonical_name(name),
                    value,
                    canonical_name(zone),
                    tx["client_mac"],
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )

        cursor = db.execute(
            """
            UPDATE dns_pair_transactions
            SET state = 'COMPLETE',
                cleanup_pending = ?,
                updated_at = ?,
                completed_at = ?
            WHERE tx_id = ?
              AND state IN ('RESERVED', 'A_CREATED')
            """,
            (
                cleanup_pending,
                timestamp,
                timestamp,
                tx["tx_id"],
            ),
        )

        if cursor.rowcount != 1:
            raise RuntimeError(
                "Could not atomically complete DNS "
                f"transaction {tx['tx_id']}"
            )

        db.commit()

    except Exception:
        db.rollback()
        raise

    tx["state"] = "COMPLETE"
    tx["cleanup_pending"] = cleanup_pending

    event(
        "DNS_TX_COMPLETE",
        tx_id=tx["tx_id"],
        client_mac=tx["client_mac"],
        cleanup_pending=bool(cleanup_pending),
    )


def mark_pair_cleanup_complete(tx_id):

    timestamp = utc_now()

    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            """
            UPDATE dns_pair_transactions
            SET cleanup_pending = 0,
                updated_at = ?
            WHERE tx_id = ?
              AND state = 'COMPLETE'
            """,
            (timestamp, tx_id),
        )
        db.commit()

    except Exception:
        db.rollback()
        raise

    event(
        "DNS_TX_CLEANUP_COMPLETE",
        tx_id=tx_id,
    )


def retirement_from_row(row):

    keys = (
        "retirement_id",
        "tx_id",
        "record_type",
        "name",
        "value",
        "zone",
        "client_mac",
        "expected_remaining_json",
        "remove_ownership",
        "reason",
        "state",
        "conflict_reason",
        "created_at",
        "updated_at",
        "completed_at",
    )

    result = dict(zip(keys, row))
    result["expected_remaining"] = json.loads(
        result.pop("expected_remaining_json")
    )

    return result


def load_open_retirements():

    rows = db.execute(
        """
        SELECT
            retirement_id, tx_id, record_type,
            name, value, zone, client_mac,
            expected_remaining_json,
            remove_ownership, reason, state,
            conflict_reason, created_at,
            updated_at, completed_at
        FROM dns_record_retirements
        WHERE state = 'RESERVED'
        ORDER BY created_at, retirement_id
        """
    ).fetchall()

    return [
        retirement_from_row(row)
        for row in rows
    ]


def reserve_retirement(
    record_type,
    name,
    value,
    zone,
    client_mac,
    expected_remaining,
    remove_ownership,
    reason,
    tx_id=None,
):

    if DRY_RUN:
        raise RuntimeError(
            "DRY_RUN forbids retirement reservations"
        )

    name = canonical_name(name)
    zone = canonical_name(zone)
    value = (
        canonical_name(value)
        if record_type == "PTR"
        else str(value)
    )
    expected_remaining = normalize_record_values(
        record_type,
        expected_remaining,
    )

    existing = db.execute(
        """
        SELECT
            retirement_id, tx_id, record_type,
            name, value, zone, client_mac,
            expected_remaining_json,
            remove_ownership, reason, state,
            conflict_reason, created_at,
            updated_at, completed_at
        FROM dns_record_retirements
        WHERE state = 'RESERVED'
          AND record_type = ?
          AND name = ?
          AND value = ?
        LIMIT 1
        """,
        (record_type, name, value),
    ).fetchone()

    if existing:
        return retirement_from_row(existing)

    retirement_id = str(uuid.uuid4())
    timestamp = utc_now()

    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            """
            INSERT INTO dns_record_retirements (
                retirement_id,
                tx_id,
                record_type,
                name,
                value,
                zone,
                client_mac,
                expected_remaining_json,
                remove_ownership,
                reason,
                state,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    'RESERVED', ?, ?)
            """,
            (
                retirement_id,
                tx_id,
                record_type,
                name,
                value,
                zone,
                client_mac,
                json.dumps(expected_remaining),
                int(remove_ownership),
                reason,
                timestamp,
                timestamp,
            ),
        )
        db.commit()

    except Exception:
        db.rollback()
        raise

    event(
        "DNS_RETIREMENT_RESERVED",
        retirement_id=retirement_id,
        tx_id=tx_id,
        record_type=record_type,
        name=name,
        value=value,
        reason=reason,
    )

    row = db.execute(
        """
        SELECT
            retirement_id, tx_id, record_type,
            name, value, zone, client_mac,
            expected_remaining_json,
            remove_ownership, reason, state,
            conflict_reason, created_at,
            updated_at, completed_at
        FROM dns_record_retirements
        WHERE retirement_id = ?
        """,
        (retirement_id,),
    ).fetchone()

    return retirement_from_row(row)


def mark_retirement_conflict(retirement, reason):

    timestamp = utc_now()

    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            """
            UPDATE dns_record_retirements
            SET state = 'CONFLICT',
                conflict_reason = ?,
                updated_at = ?
            WHERE retirement_id = ?
            """,
            (
                reason,
                timestamp,
                retirement["retirement_id"],
            ),
        )
        db.commit()

    except Exception:
        db.rollback()
        raise

    event(
        "DNS_RETIREMENT_CONFLICT",
        retirement_id=retirement["retirement_id"],
        reason=reason,
        action_taken="FAIL_CLOSED",
    )


def complete_retirement(retirement):

    timestamp = utc_now()

    try:
        db.execute("BEGIN IMMEDIATE")

        if retirement["remove_ownership"]:
            db.execute(
                """
                DELETE FROM dns_records_owned
                WHERE record_type = ?
                  AND name = ?
                  AND value = ?
                  AND client_mac = ?
                """,
                (
                    retirement["record_type"],
                    retirement["name"],
                    retirement["value"],
                    retirement["client_mac"],
                ),
            )

        db.execute(
            """
            UPDATE dns_record_retirements
            SET state = 'COMPLETE',
                updated_at = ?,
                completed_at = ?
            WHERE retirement_id = ?
              AND state = 'RESERVED'
            """,
            (
                timestamp,
                timestamp,
                retirement["retirement_id"],
            ),
        )
        db.commit()

    except Exception:
        db.rollback()
        raise

    event(
        "DNS_RETIREMENT_COMPLETE",
        retirement_id=retirement["retirement_id"],
        record_type=retirement["record_type"],
        name=retirement["name"],
        value=retirement["value"],
    )


def execute_retirement(primary, retirement):

    remaining = normalize_record_values(
        retirement["record_type"],
        retirement["expected_remaining"],
    )
    before = normalize_record_values(
        retirement["record_type"],
        remaining + [retirement["value"]],
    )

    actual = read_record_values(
        primary,
        retirement["record_type"],
        retirement["name"],
        retirement["zone"],
    )

    if actual == remaining:
        # The delete completed before a crash or a lost
        # response. Finalize only the local journal state.
        complete_retirement(retirement)
        return

    if actual != before:
        reason = (
            "retirement_dns_state_unexpected:"
            f"expected_before={before},"
            f"expected_after={remaining},"
            f"actual={actual}"
        )
        mark_retirement_conflict(
            retirement,
            reason,
        )
        raise RuntimeError(reason)

    delete_dns_record(
        primary,
        retirement["record_type"],
        retirement["name"],
        retirement["value"],
        retirement["zone"],
        retirement["retirement_id"],
    )

    verified = read_record_values(
        primary,
        retirement["record_type"],
        retirement["name"],
        retirement["zone"],
    )

    if verified != remaining:
        reason = (
            "retirement_delete_verification_failed:"
            f"expected={remaining},actual={verified}"
        )
        mark_retirement_conflict(
            retirement,
            reason,
        )
        raise RuntimeError(reason)

    complete_retirement(retirement)


def retire_owned_record(
    primary,
    record_type,
    name,
    value,
    zone,
    client_mac,
    reason,
    expected_remaining=None,
    remove_ownership=True,
    tx_id=None,
):

    retirement = reserve_retirement(
        record_type=record_type,
        name=name,
        value=value,
        zone=zone,
        client_mac=client_mac,
        expected_remaining=(
            expected_remaining or []
        ),
        remove_ownership=remove_ownership,
        reason=reason,
        tx_id=tx_id,
    )

    execute_retirement(
        primary,
        retirement,
    )


def cleanup_completed_pair(primary, tx):

    cleanup_specs = []

    if tx["a_action"] == "UPDATE":
        cleanup_specs.append(
            (
                "A",
                tx["a_name"],
                tx["a_previous_value"],
                tx["a_zone"],
                [tx["a_value"]],
            )
        )

    if tx["ptr_action"] == "UPDATE":
        cleanup_specs.append(
            (
                "PTR",
                tx["ptr_name"],
                tx["ptr_previous_value"],
                tx["ptr_zone"],
                [tx["ptr_value"]],
            )
        )

    for (
        record_type,
        name,
        previous_value,
        zone,
        remaining,
    ) in cleanup_specs:

        retire_owned_record(
            primary=primary,
            record_type=record_type,
            name=name,
            value=previous_value,
            zone=zone,
            client_mac=tx["client_mac"],
            reason="superseded_same_owner_value",
            expected_remaining=remaining,
            remove_ownership=False,
            tx_id=tx["tx_id"],
        )

    mark_pair_cleanup_complete(
        tx["tx_id"]
    )


def process_pair_transaction(primary, tx):

    if tx["state"] == "COMPLETE":
        cleanup_completed_pair(primary, tx)
        return

    a_before = expected_values_for_action(
        "A",
        tx["a_action"],
        tx["a_value"],
        tx["a_previous_value"],
        after_write=False,
    )
    a_after = expected_values_for_action(
        "A",
        tx["a_action"],
        tx["a_value"],
        tx["a_previous_value"],
        after_write=True,
    )
    ptr_before = expected_values_for_action(
        "PTR",
        tx["ptr_action"],
        tx["ptr_value"],
        tx["ptr_previous_value"],
        after_write=False,
    )
    ptr_after = expected_values_for_action(
        "PTR",
        tx["ptr_action"],
        tx["ptr_value"],
        tx["ptr_previous_value"],
        after_write=True,
    )

    actual_a = read_record_values(
        primary,
        "A",
        tx["a_name"],
        tx["a_zone"],
    )
    actual_ptr = read_record_values(
        primary,
        "PTR",
        tx["ptr_name"],
        tx["ptr_zone"],
    )

    if tx["state"] == "RESERVED":

        if actual_a == a_after and actual_ptr == ptr_after:
            complete_pair_transaction(tx)

        elif actual_a == a_after and actual_ptr == ptr_before:
            set_pair_transaction_state(
                tx["tx_id"],
                "A_CREATED",
            )
            tx["state"] = "A_CREATED"

        elif actual_a == a_before and actual_ptr == ptr_before:

            if tx["a_action"] != "NO_CHANGE":
                add_dns_record(
                    primary,
                    "A",
                    tx["a_name"],
                    tx["a_value"],
                    tx["a_zone"],
                    tx["tx_id"],
                )

            verified_a = read_record_values(
                primary,
                "A",
                tx["a_name"],
                tx["a_zone"],
            )

            if verified_a != a_after:
                reason = (
                    "a_verification_failed:"
                    f"expected={a_after},actual={verified_a}"
                )
                mark_pair_transaction_conflict(
                    tx,
                    reason,
                )
                raise RuntimeError(reason)

            set_pair_transaction_state(
                tx["tx_id"],
                "A_CREATED",
            )
            tx["state"] = "A_CREATED"

        else:
            reason = (
                "reserved_dns_state_unexpected:"
                f"a_before={a_before},a_after={a_after},"
                f"actual_a={actual_a},"
                f"ptr_before={ptr_before},"
                f"ptr_after={ptr_after},"
                f"actual_ptr={actual_ptr}"
            )
            mark_pair_transaction_conflict(
                tx,
                reason,
            )
            raise RuntimeError(reason)

    if tx["state"] == "A_CREATED":

        actual_a = read_record_values(
            primary,
            "A",
            tx["a_name"],
            tx["a_zone"],
        )
        actual_ptr = read_record_values(
            primary,
            "PTR",
            tx["ptr_name"],
            tx["ptr_zone"],
        )

        if actual_a != a_after:
            reason = (
                "a_created_dns_state_unexpected:"
                f"expected_a={a_after},actual_a={actual_a}"
            )
            mark_pair_transaction_conflict(
                tx,
                reason,
            )
            raise RuntimeError(reason)

        if actual_ptr == ptr_after:
            complete_pair_transaction(tx)

        elif actual_ptr == ptr_before:

            if tx["ptr_action"] != "NO_CHANGE":
                add_dns_record(
                    primary,
                    "PTR",
                    tx["ptr_name"],
                    tx["ptr_value"],
                    tx["ptr_zone"],
                    tx["tx_id"],
                )

            verified_ptr = read_record_values(
                primary,
                "PTR",
                tx["ptr_name"],
                tx["ptr_zone"],
            )

            if verified_ptr != ptr_after:
                reason = (
                    "ptr_verification_failed:"
                    f"expected={ptr_after},actual={verified_ptr}"
                )
                mark_pair_transaction_conflict(
                    tx,
                    reason,
                )
                raise RuntimeError(reason)

            complete_pair_transaction(tx)

        else:
            reason = (
                "a_created_ptr_state_unexpected:"
                f"expected_before={ptr_before},"
                f"expected_after={ptr_after},"
                f"actual={actual_ptr}"
            )
            mark_pair_transaction_conflict(
                tx,
                reason,
            )
            raise RuntimeError(reason)

    if tx.get("cleanup_pending"):
        cleanup_completed_pair(primary, tx)


def unresolved_conflict_count():

    pair_count = db.execute(
        """
        SELECT COUNT(*)
        FROM dns_pair_transactions
        WHERE state = 'CONFLICT'
        """
    ).fetchone()[0]

    retirement_count = db.execute(
        """
        SELECT COUNT(*)
        FROM dns_record_retirements
        WHERE state = 'CONFLICT'
        """
    ).fetchone()[0]

    return pair_count + retirement_count


def recover_dns_journal(primary):

    pair_transactions = (
        load_pair_transactions_for_recovery()
    )
    retirements = load_open_retirements()

    event(
        "DNS_RECOVERY_START",
        pair_transactions=len(pair_transactions),
        retirements=len(retirements),
        dry_run=DRY_RUN,
    )

    existing_conflicts = unresolved_conflict_count()

    if existing_conflicts:
        event(
            "DNS_RECOVERY_BLOCKED",
            conflicts=existing_conflicts,
            action_taken="FAIL_CLOSED",
        )
        return False

    if DRY_RUN and (pair_transactions or retirements):
        event(
            "DNS_RECOVERY_DRY_RUN_BLOCKED",
            reason="unfinished_real_journal_entries",
            action_taken="NO_WRITES_NO_STATE_CHANGES",
        )
        return False

    try:
        # Finish pair creation first. Same-owner cleanup may
        # create retirement reservations of its own.
        for tx in pair_transactions:
            event(
                "DNS_TX_RECOVER",
                tx_id=tx["tx_id"],
                state=tx["state"],
                cleanup_pending=bool(
                    tx["cleanup_pending"]
                ),
            )
            process_pair_transaction(
                primary,
                tx,
            )

        # Reload so retirements created by pair cleanup are
        # included and already-completed items disappear.
        for retirement in load_open_retirements():
            event(
                "DNS_RETIREMENT_RECOVER",
                retirement_id=(
                    retirement["retirement_id"]
                ),
                record_type=retirement["record_type"],
                name=retirement["name"],
            )
            execute_retirement(
                primary,
                retirement,
            )

    except Exception as exc:
        event(
            "DNS_RECOVERY_FAILED",
            error=str(exc),
            action_taken="FAIL_CLOSED",
        )
        return False

    conflicts = unresolved_conflict_count()

    if conflicts:
        event(
            "DNS_RECOVERY_BLOCKED",
            conflicts=conflicts,
            action_taken="FAIL_CLOSED",
        )
        return False

    event("DNS_RECOVERY_COMPLETE")
    return True


# ============================================================
# Pair Evaluation
# ============================================================

def evaluate_client_pair(
    primary,
    client,
    writes_allowed,
):

    fqdn = client["fqdn"]
    ip = client["ip"]
    mac = client["mac"]
    dns_suffix = client.get(
        "dns_suffix",
        DNS_SUFFIX,
    )

    reverse_zone = reverse_zone_for_ip(ip)
    ptr_name = ptr_name_for_ip(ip)

    a_records = get_dns_records(
        primary,
        fqdn,
        dns_suffix,
    )

    ptr_records = get_dns_records(
        primary,
        ptr_name,
        reverse_zone,
    )

    a = analyze_record(
        record_type="A",
        name=fqdn,
        expected_value=ip,
        existing_values=find_a_record(
            a_records,
            fqdn,
        ),
        zone=dns_suffix,
        client_mac=mac,
    )

    ptr = analyze_record(
        record_type="PTR",
        name=ptr_name,
        expected_value=fqdn,
        existing_values=find_ptr_record(
            ptr_records,
            ptr_name,
        ),
        zone=reverse_zone,
        client_mac=mac,
    )

    event(
        "DNS_PAIR_ANALYSIS",
        client_mac=mac,
        fqdn=fqdn,
        ip=ip,
        a_state=a["state"],
        a_reason=a["reason"],
        ptr_state=ptr["state"],
        ptr_reason=ptr["reason"],
    )

    blocked_states = {
        "CONFLICT",
        "DRIFT",
        "EXTERNAL_MATCH",
    }

    # Pair ownership is deliberately conservative.
    #
    # If one side is external, we do not create/manage
    # only the other half of the pair.
    if (
        a["state"] in blocked_states
        or ptr["state"] in blocked_states
    ):

        event(
            "DNS_PAIR_BLOCKED",
            client_mac=mac,
            fqdn=fqdn,
            ip=ip,
            a_state=a["state"],
            a_reason=a["reason"],
            a_existing=a["existing_values"],
            ptr_state=ptr["state"],
            ptr_reason=ptr["reason"],
            ptr_existing=ptr["existing_values"],
            action_taken="SKIP_PAIR",
        )

        return False

    actions = {
        a["state"],
        ptr["state"],
    }

    if actions == {"NO_CHANGE"}:

        touch_owned_record(
            "A",
            a["name"],
            mac,
        )

        touch_owned_record(
            "PTR",
            ptr["name"],
            mac,
        )

        event(
            "DNS_PAIR_NO_CHANGE",
            client_mac=mac,
            fqdn=fqdn,
            ip=ip,
            ownership="owned",
        )

        return True

    if "UPDATE" in actions:

        action = "DNS_PAIR_WOULD_UPDATE"

    elif "ADD" in actions:

        action = "DNS_PAIR_WOULD_ADD"

    else:

        action = "DNS_PAIR_NO_CHANGE"

    event(
        action,
        client_mac=mac,
        fqdn=fqdn,
        ip=ip,
        a_action=a["state"],
        a_name=a["name"],
        a_old=a["existing_values"],
        a_new=a["expected_value"],
        ptr_action=ptr["state"],
        ptr_name=ptr["name"],
        ptr_old=ptr["existing_values"],
        ptr_new=ptr["expected_value"],
        dry_run=DRY_RUN,
        writes_allowed=writes_allowed,
    )

    if not writes_allowed or DRY_RUN:
        return False

    tx = reserve_pair_transaction(
        client,
        a,
        ptr,
    )

    process_pair_transaction(
        primary,
        tx,
    )

    return True


# ============================================================
# Superseded Ownership
# ============================================================

def evaluate_superseded_records(
    primary,
    client,
    writes_allowed,
):

    mac = client["mac"]

    desired = {
        (
            "A",
            canonical_name(client["fqdn"]),
        ),
        (
            "PTR",
            canonical_name(
                ptr_name_for_ip(
                    client["ip"]
                )
            ),
        ),
    }

    owned_records = get_owned_records_for_mac(
        mac
    )

    for owned in owned_records:

        key = (
            owned["record_type"],
            canonical_name(
                owned["name"]
            ),
        )

        if key in desired:
            continue

        records = get_dns_records(
            primary,
            owned["name"],
            owned["zone"],
        )

        if owned["record_type"] == "A":

            actual_values = find_a_record(
                records,
                owned["name"],
            )

            owned_value = owned["value"]

        elif owned["record_type"] == "PTR":

            actual_values = find_ptr_record(
                records,
                owned["name"],
            )

            owned_value = canonical_name(
                owned["value"]
            )

        else:
            continue

        actual_values = normalize_record_values(
            owned["record_type"],
            actual_values,
        )

        # Delete candidate only if DNS still contains
        # exactly what our ownership database says.
        if actual_values != [owned_value]:

            event(
                "DNS_SUPERSEDED_BLOCKED",
                record_type=owned["record_type"],
                name=owned["name"],
                owned_value=owned_value,
                actual_values=actual_values,
                client_mac=mac,
                reason="ownership_drift",
                action_taken="SKIP",
            )

            continue

        event(
            "DNS_SUPERSEDED_WOULD_DELETE",
            record_type=owned["record_type"],
            name=owned["name"],
            value=owned_value,
            zone=owned["zone"],
            client_mac=mac,
            reason="desired_record_changed",
            dry_run=DRY_RUN,
            writes_allowed=writes_allowed,
        )

        if writes_allowed and not DRY_RUN:
            retire_owned_record(
                primary=primary,
                record_type=owned["record_type"],
                name=owned["name"],
                value=owned_value,
                zone=owned["zone"],
                client_mac=mac,
                reason="desired_record_changed",
            )


# ============================================================
# Stale Records
# ============================================================

def evaluate_stale_records(
    primary,
    active_clients,
    writes_allowed,
):

    active_macs = {
        client["mac"]
        for client in active_clients
    }

    now = datetime.now(timezone.utc)

    threshold = (
        now
        - timedelta(
            days=STALE_AFTER_DAYS
        )
    )

    # Client last_seen is authoritative for staleness.
    rows = db.execute(
        """
        SELECT
            o.record_type,
            o.name,
            o.value,
            o.zone,
            o.client_mac,
            o.last_seen,
            c.last_seen
        FROM dns_records_owned o
        LEFT JOIN clients c
            ON c.mac = o.client_mac
        """
    ).fetchall()

    event(
        "STALE_CHECK",
        owned_records=len(rows),
        stale_after_days=STALE_AFTER_DAYS,
    )

    for row in rows:

        (
            record_type,
            name,
            value,
            zone,
            client_mac,
            ownership_last_seen,
            client_last_seen,
        ) = row

        if client_mac in active_macs:
            continue

        # Fail closed for orphaned ownership. Staleness is
        # authorized exclusively by clients.last_seen, never
        # by the ownership verification timestamp.
        if not client_last_seen:
            event(
                "STALE_SKIP",
                record_type=record_type,
                name=name,
                client_mac=client_mac,
                reason="missing_client_last_seen",
            )
            continue

        last_seen_dt = parse_timestamp(
            client_last_seen
        )

        if not last_seen_dt:

            event(
                "STALE_SKIP",
                record_type=record_type,
                name=name,
                client_mac=client_mac,
                reason="invalid_last_seen",
            )

            continue

        age_days = (
            now - last_seen_dt
        ).days

        if last_seen_dt > threshold:

            event(
                "DNS_KEEP_STALE",
                record_type=record_type,
                name=name,
                client_mac=client_mac,
                age_days=age_days,
                stale_after_days=STALE_AFTER_DAYS,
            )

            continue

        records = get_dns_records(
            primary,
            name,
            zone,
        )

        if record_type == "A":

            actual_values = find_a_record(
                records,
                name,
            )

            owned_value = value

        elif record_type == "PTR":

            actual_values = find_ptr_record(
                records,
                name,
            )

            owned_value = canonical_name(
                value
            )

        else:
            continue

        actual_values = normalize_record_values(
            record_type,
            actual_values,
        )

        # Exact ownership match required.
        if actual_values != [owned_value]:

            event(
                "DNS_STALE_CONFLICT",
                record_type=record_type,
                name=name,
                owned_value=owned_value,
                actual_values=actual_values,
                zone=zone,
                client_mac=client_mac,
                action_taken="SKIP",
            )

            continue

        event(
            "DNS_WOULD_DELETE",
            record_type=record_type,
            name=name,
            value=owned_value,
            zone=zone,
            client_mac=client_mac,
            age_days=age_days,
            stale_after_days=STALE_AFTER_DAYS,
            ownership="owned",
            dry_run=DRY_RUN,
            writes_allowed=writes_allowed,
        )

        if writes_allowed and not DRY_RUN:
            retire_owned_record(
                primary=primary,
                record_type=record_type,
                name=name,
                value=owned_value,
                zone=zone,
                client_mac=client_mac,
                reason="client_stale",
            )


# ============================================================
# Sync
# ============================================================

def sync_cycle(
    site,
    primary,
    writes_allowed,
):

    global ACTIVE_NETWORK

    baseline = (
        metadata_get(
            "baseline_complete"
        )
        != "true"
    )

    event(
        "SYNC_START",
        site=site,
        scopes=[
            {
                "name": scope["name"],
                "subnet": str(scope["subnet"]),
                "dns_suffix": scope["dns_suffix"],
            }
            for scope in SYNC_SCOPES
        ],
        baseline=baseline,
        dry_run=DRY_RUN,
        writes_allowed=writes_allowed,
        stale_after_days=STALE_AFTER_DAYS,
    )

    raw_clients = get_connected_clients(
        site
    )

    event(
        "UNIFI_CLIENTS",
        connected_clients=len(raw_clients),
    )

    matched = []
    scope_clients = []

    for scope in SYNC_SCOPES:

        ACTIVE_NETWORK = scope["name"]
        current_clients = []

        for raw in raw_clients:

            client = parse_client(
                raw,
                scope,
            )

            if client:
                current_clients.append(client)

        matched.extend(current_clients)
        scope_clients.append(
            (scope, current_clients)
        )

        event(
            "SUBNET_CLIENTS",
            subnet=str(scope["subnet"]),
            dns_suffix=scope["dns_suffix"],
            matched_clients=len(current_clients),
        )

    # --------------------------------------------------------
    # Duplicate hostname protection
    # --------------------------------------------------------

    desired_name_map = {}

    for client in matched:

        desired_name_map.setdefault(
            canonical_name(client["fqdn"]),
            [],
        ).append(client)

    duplicate_macs = set()

    for fqdn, items in desired_name_map.items():

        if len(items) <= 1:
            continue

        duplicate_macs.update(
            item["mac"]
            for item in items
        )

        event(
            "DUPLICATE_HOSTNAME",
            network="all-scopes",
            fqdn=fqdn,
            clients=[
                {
                    "mac": item["mac"],
                    "ip": item["ip"],
                    "network": item["network"],
                }
                for item in items
            ],
            action_taken="SKIP_DNS",
        )

    # --------------------------------------------------------
    # Client DB
    # --------------------------------------------------------

    for scope, current_clients in scope_clients:

        ACTIVE_NETWORK = scope["name"]

        for client in current_clients:

            process_client(
                client,
                baseline,
            )

    if baseline:

        metadata_set(
            "baseline_complete",
            "true",
        )

        metadata_set(
            "baseline_timestamp",
            utc_now(),
        )

        event(
            "BASELINE_COMPLETE",
            network="all-scopes",
            clients=len(matched),
        )

    db.commit()

    # --------------------------------------------------------
    # DNS pair evaluation, one scope at a time
    # --------------------------------------------------------

    dns_client_count = 0

    for scope, current_clients in scope_clients:

        ACTIVE_NETWORK = scope["name"]

        dns_clients = [
            client
            for client in current_clients
            if client["mac"]
            not in duplicate_macs
        ]

        event(
            "SCOPE_DNS_START",
            subnet=str(scope["subnet"]),
            dns_suffix=scope["dns_suffix"],
            dns_clients=len(dns_clients),
            writes_allowed=writes_allowed,
        )

        for client in dns_clients:

            pair_safe = evaluate_client_pair(
                primary,
                client,
                writes_allowed,
            )

            # Superseded records are only evaluated when
            # the desired pair itself is not blocked.
            if pair_safe:

                evaluate_superseded_records(
                    primary,
                    client,
                    writes_allowed,
                )

        dns_client_count += len(dns_clients)

        event(
            "SCOPE_DNS_COMPLETE",
            dns_clients=len(dns_clients),
            writes_allowed=writes_allowed,
        )

    # --------------------------------------------------------
    # Stale clients
    # --------------------------------------------------------

    ACTIVE_NETWORK = "all-scopes"

    try:
        evaluate_stale_records(
            primary,
            matched,
            writes_allowed,
        )
    finally:
        ACTIVE_NETWORK = None

    db.commit()

    event(
        "SYNC_COMPLETE",
        network="all-scopes",
        connected_clients=len(raw_clients),
        matched_clients=len(matched),
        dns_clients=dns_client_count,
        scopes=len(SYNC_SCOPES),
        baseline=baseline,
        dry_run=DRY_RUN,
        writes_allowed=writes_allowed,
    )


# ============================================================
# Main
# ============================================================

def main():

    global ACTIVE_NETWORK

    event(
        "SERVICE_START",
        unifi_host=UNIFI_HOST,
        unifi_port=UNIFI_PORT,
        configured_site=UNIFI_SITE,
        scopes=[
            {
                "name": scope["name"],
                "subnet": str(scope["subnet"]),
                "dns_suffix": scope["dns_suffix"],
            }
            for scope in SYNC_SCOPES
        ],
        poll_interval=POLL_INTERVAL,
        stale_after_days=STALE_AFTER_DAYS,
        dry_run=DRY_RUN,
        phase="4",
    )

    site = None

    while True:

        if not site:

            try:
                site = discover_site()

            except Exception as exc:

                event(
                    "SITE_DISCOVERY_ERROR",
                    error=str(exc),
                )

                event(
                    "RETRY_WAIT",
                    seconds=POLL_INTERVAL,
                )

                time.sleep(
                    POLL_INTERVAL
                )

                continue

        try:

            primary = (
                discover_technitium_cluster()
            )

        except Exception as exc:

            event(
                "TECHNITIUM_DISCOVERY_ERROR",
                error=str(exc),
            )

            event(
                "RETRY_WAIT",
                seconds=POLL_INTERVAL,
            )

            time.sleep(
                POLL_INTERVAL
            )

            continue

        try:

            ACTIVE_NETWORK = None

            recovery_safe = recover_dns_journal(
                primary
            )

            writes_allowed = (
                recovery_safe
                and not DRY_RUN
            )

            if not writes_allowed:
                event(
                    "DNS_WRITES_DISABLED",
                    dry_run=DRY_RUN,
                    recovery_safe=recovery_safe,
                )

            sync_cycle(
                site,
                primary,
                writes_allowed,
            )

        except Exception as exc:

            event(
                "SYNC_ERROR",
                error=str(exc),
            )

            site = None

        event(
            "SLEEP",
            seconds=POLL_INTERVAL,
        )

        time.sleep(
            POLL_INTERVAL
        )


if __name__ == "__main__":
    main()
