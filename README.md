# TLSA sync

Synchronizes mail TLSA records from a chosen DNS server to deSEC, with mailcow
usage in mind. By default it looks up `_25._tcp.<domain>` for every FQDN in
`DOMAIN_LIST` and updates the matching deSEC RRset only when its records or TTL
have changed.

## How it works

1. Resolve `_25._tcp.<domain>` (or the configured `TLSA_PORT`) against
   `DNS_SERVER`.
2. Normalize and compare the returned records with the deSEC RRset.
3. Create or replace the deSEC RRset only when necessary.
4. Repeat after `POLL_INTERVAL_SECONDS`.

The current deSEC state is cached in `DESEC_CACHE_FILE`, so normal polling does
not issue a deSEC GET request every time. Mount the cache directory when using
Docker so the cache survives container recreation. Delete the cache file to
force a fresh provider read.

DNS errors are logged per domain and do not stop the other domains from being
processed. An empty successful DNS answer removes stale records from deSEC.

The deSEC token must be allowed to manage `DESEC_ZONE`. `DOMAIN_LIST` contains
the mail FQDNs, while `DESEC_ZONE` contains the deSEC zone. For example,
`DOMAIN_LIST=mail.ward.nl` and `DESEC_ZONE=ward.nl` query
`_25._tcp.mail.ward.nl` and synchronize `_25._tcp.mail` in the `ward.nl` zone.

## Configuration

Copy [.env.example](.env.example) to `.env` and set the token and domains.

| Variable                | Required | Default                   | Description                                                     |
| ----------------------- | -------- | ------------------------- | --------------------------------------------------------------- |
| `DOMAIN_LIST`           | yes      |                           | Comma-separated mail FQDNs, for example `mail.example.com`      |
| `DESEC_ZONE`            | yes      |                           | deSEC zone containing the mail FQDNs, for example `example.com` |
| `DNS_SERVER`            | yes      |                           | Nameserver address or container hostname used for lookups       |
| `DESEC_TOKEN`           | yes      |                           | deSEC API token                                                 |
| `TLSA_PORT`             | no       | `25`                      | Mail/service port used in the TLSA name                         |
| `DNS_PORT`              | no       | `53`                      | Port of the configured nameserver                               |
| `TIMEOUT_SECONDS`       | no       | `5`                       | DNS and deSEC HTTP timeout                                      |
| `POLL_INTERVAL_SECONDS` | no       | `300`                     | Seconds between synchronization passes                          |
| `DESEC_TTL_SECONDS`     | no       | `300`                     | TTL sent to deSEC when an RRset changes                         |
| `DESEC_BASE_URL`        | no       | `https://desec.io/api/v1` | deSEC API endpoint                                              |
| `DESEC_CACHE_FILE`      | no       | `/data/desec-cache.json`  | Persistent cache of current deSEC RRsets                        |
| `LOG_LEVEL`             | no       | `INFO`                    | Python logging level                                            |

## Run locally

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
cd src
uv sync --no-dev
DOMAIN_LIST=example.com DNS_SERVER=1.1.1.1 DESEC_TOKEN=your-token uv run main.py
```

## Run with Docker

```sh
docker build -t tlsa-sync .
docker run --rm --env-file .env -v tlsa-sync-cache:/data tlsa-sync
```

Or pull the published image from GitHub Container Registry:

```sh
docker pull ghcr.io/wardpieters/tlsa-sync:latest
```

Example `docker-compose.yml`:

```yaml
services:
  tlsa-sync:
    image: ghcr.io/wardpieters/tlsa-sync:latest
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - tlsa-sync-cache:/data

volumes:
  tlsa-sync-cache:
```

The image uses Python 3.12 and uv. GitHub Actions publishes tagged images to
GitHub Container Registry when a `v*.*.*` tag is pushed.
