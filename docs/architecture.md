# Architecture

UniFi is the client inventory source; Technitium owns the authoritative zones.
The service polls connected clients once per cycle, filters them into configured
IPv4 scopes, normalizes hostnames, and excludes duplicate desired names.
It maintains A/PTR pairs in existing zones. It does not configure DHCP or create
zones. Runtime dependencies are Python's standard library and SQLite.

## Configuration and boundaries

Use `SYNC_SUBNET` and `DNS_SUFFIX` for one scope, or `SYNC_SCOPES_JSON` for a
non-empty list of `{name, subnet, dns_suffix}` objects. Names must be unique,
subnets must not overlap, and suffixes must be DNS names. A scope may inherit
`DNS_SUFFIX`. A shared suffix requires unique desired hostnames across scopes.

Reverse zone names are currently derived as /24 zones from each IPv4 address.
Other reverse-zone layouts, including RFC 2317 delegation, are not implemented.
For a subnet spanning multiple /24s, provision and authorize every corresponding
reverse zone. IPv6 and AAAA records are not supported.

## Persistent state

`clients` stores last-seen observations; `dns_records_owned` records proven
ownership; `dns_pair_transactions` and `dns_record_retirements` record durable
intent. Metadata and cluster observations use separate tables. SQLite WAL and
FULL synchronous mode are enabled. Run only one service instance per state
file and managed namespace. This is not a distributed locking system.

## Writes

Discover the current Primary, recover unfinished work, then evaluate clients.
Reserve intent before DNS writes. Read back A and PTR results before committing
ownership. Matching external records remain external. New values are created
before old owned values are retired; an address change can therefore briefly
produce two A values. An unexpected multi-value set is a conflict.

DNS API operations and SQLite are separate systems, so the pair is not an
atomic DNS transaction. The journal makes intermediate states recoverable.
The implementation does not fence concurrent external writers or a role change
between discovery and a write. Avoid concurrent writers in the managed scope.
