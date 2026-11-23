# TLSA sync

Derives mail TLSA records from Mailcow's local TLS files and synchronizes them
to deSEC. By default it publishes `_25._tcp.<domain>` for every FQDN in
`DOMAIN_LIST`. All configured FQDNs must use the certificate stored in
`MAILCOW_SSL_DIR`.

## How it works

1. Read `cert.pem` (full chain) and `key.pem` (private key) directly from
   `MAILCOW_SSL_DIR`.
2. Confirm that the public key of the first certificate in `cert.pem` matches
   `key.pem`. Generate a `3 1 1` TLSA record using the SHA-256 digest of that
   certificate's DER-encoded SubjectPublicKeyInfo. When `cert.pem` includes a
   verified CA issuer, add a `2 0 1` backup record using the SHA-256 digest of
   the highest verified CA certificate in the supplied chain.
3. Update the RRset for each configured domain and `TLSA_PORT` when its record
   or TTL changes.
4. Repeat after `POLL_INTERVAL_SECONDS`.

The backup record can authenticate a renewed certificate while the old TLSA
RRset is cached, provided the server still presents a valid chain to the same
CA certificate. If `cert.pem` contains only the leaf, the sync publishes only
the leaf TLSA record.

The current deSEC state is cached in `DESEC_CACHE_FILE`, so normal polling does
not issue a deSEC GET request every time. Mount the cache directory when using
Docker so the cache survives container recreation. Delete the cache file to
force a fresh provider read.

If the files are missing, unreadable, invalid, or inconsistent, the sync logs
the error and retries at the next poll. Existing deSEC records stay in place.

The deSEC token must be allowed to manage `DESEC_ZONE`. `DOMAIN_LIST` contains
the mail FQDNs, while `DESEC_ZONE` contains the deSEC zone. For example,
`DOMAIN_LIST=mail.ward.nl` and `DESEC_ZONE=ward.nl` synchronize
`_25._tcp.mail` in the `ward.nl` zone.

## Configuration

Copy [.env.example](.env.example) to `.env` and set the token, domains, and
absolute path to Mailcow's `data/assets/ssl` directory. The sync process needs
read access to `cert.pem` and `key.pem`.

| Variable                | Required | Default                   | Description                                                     |
| ----------------------- | -------- | ------------------------- | --------------------------------------------------------------- |
| `DOMAIN_LIST`           | yes      |                           | Comma-separated mail FQDNs, for example `mail.example.com`      |
| `DESEC_ZONE`            | yes      |                           | deSEC zone containing the mail FQDNs, for example `example.com` |
| `MAILCOW_SSL_DIR`       | yes      |                           | Directory containing Mailcow's `cert.pem` and `key.pem`         |
| `DESEC_TOKEN`           | yes      |                           | deSEC API token                                                 |
| `TLSA_PORT`             | no       | `25`                      | Mail/service port used in the TLSA name                         |
| `TIMEOUT_SECONDS`       | no       | `5`                       | deSEC HTTP timeout                                              |
| `POLL_INTERVAL_SECONDS` | no       | `300`                     | Seconds between synchronization passes                          |
| `DESEC_TTL_SECONDS`     | no       | `300`                     | TTL sent to deSEC when an RRset changes                         |
| `DESEC_BASE_URL`        | no       | `https://desec.io/api/v1` | deSEC API endpoint                                              |
| `DESEC_CACHE_FILE`      | no       | `/data/desec-cache.json`  | Persistent cache of current deSEC RRsets                        |
| `LOG_LEVEL`             | no       | `INFO`                    | Python logging level                                            |

## Run locally

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
uv --directory src run --no-dev --env-file ../.env main.py
```

## Run with Docker

Bind-mount Mailcow's SSL directory read-only at `/mailcow-ssl` so the container
can read renewed files on subsequent polls. The `.env` file supplies the host
path, and the container receives `MAILCOW_SSL_DIR=/mailcow-ssl`.

```sh
docker build -t tlsa-sync .
set -a
. ./.env
set +a
docker run --rm --env-file .env \
  --env MAILCOW_SSL_DIR=/mailcow-ssl \
  --mount "type=bind,source=${MAILCOW_SSL_DIR},target=/mailcow-ssl,readonly" \
  -v tlsa-sync-cache:/data tlsa-sync
```

Or pull the published image from GitHub Container Registry:

```sh
docker pull ghcr.io/wardpieters/tlsa-sync:v2
```

Example `docker-compose.yml`:

```yaml
services:
  tlsa-sync:
    image: ghcr.io/wardpieters/tlsa-sync:v2
    restart: unless-stopped
    env_file:
      - .env
    environment:
      MAILCOW_SSL_DIR: /mailcow-ssl
    volumes:
      - tlsa-sync-cache:/data
      - "${MAILCOW_SSL_DIR}:/mailcow-ssl:ro"

volumes:
  tlsa-sync-cache:
```

The image uses Python 3.12 and uv. GitHub Actions publishes tagged images to
GitHub Container Registry when a `v*.*.*` tag is pushed. A stable release such
as `v2.0.0` also publishes the major-version image tag `v2`.
