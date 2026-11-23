"""Derive TLSA records from Mailcow TLS files and synchronize them to deSEC."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

from providers.desec import DesecClient

LOG = logging.getLogger("tlsa-sync")


@dataclass(frozen=True)
class Settings:
    domains: tuple[str, ...]
    desec_zone: str
    tlsa_port: int
    mailcow_ssl_dir: Path
    timeout: float
    interval: float
    desec_token: str
    desec_ttl: int
    desec_base_url: str
    desec_cache_file: str

    @classmethod
    def from_environment(cls) -> "Settings":
        domains = tuple(
            domain.strip().rstrip(".")
            for domain in os.environ.get("DOMAIN_LIST", "").split(",")
            if domain.strip()
        )
        if not domains:
            raise ValueError("Missing required environment variable: DOMAIN_LIST")

        return cls(
            domains=domains,
            desec_zone=_required("DESEC_ZONE").rstrip("."),
            tlsa_port=_positive_int("TLSA_PORT", 25),
            mailcow_ssl_dir=Path(_required("MAILCOW_SSL_DIR")),
            timeout=_positive_float("TIMEOUT_SECONDS", 5.0),
            interval=_positive_float("POLL_INTERVAL_SECONDS", 300.0),
            desec_token=_required("DESEC_TOKEN"),
            desec_ttl=_positive_int("DESEC_TTL_SECONDS", 300),
            desec_base_url=os.environ.get("DESEC_BASE_URL", "https://desec.io/api/v1"),
            desec_cache_file=os.environ.get("DESEC_CACHE_FILE", "/data/desec-cache.json"),
        )


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()

    if not value:
        raise ValueError(f"Missing required environment variable: {name}")

    return value


def _positive_int(name: str, default: int) -> int:
    value = int(os.environ.get(name, str(default)))

    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")

    return value


def _positive_float(name: str, default: float) -> float:
    value = float(os.environ.get(name, str(default)))

    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")

    return value


def _read_tlsa_records(ssl_dir: Path) -> tuple[str, ...]:
    fullchain = x509.load_pem_x509_certificates((ssl_dir / "cert.pem").read_bytes())
    leaf = fullchain[0]
    key = load_pem_private_key((ssl_dir / "key.pem").read_bytes(), password=None)
    leaf_spki = leaf.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    key_spki = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if leaf_spki != key_spki:
        raise ValueError("key.pem does not match the first certificate in cert.pem")

    return (f"3 1 1 {sha256(leaf_spki).hexdigest()}",)


def _desec_subname(settings: Settings, domain: str) -> str:
    zone = settings.desec_zone
    suffix = f".{zone}"

    if domain != zone and not domain.endswith(suffix):
        raise ValueError(f"Domain {domain} is outside deSEC zone {zone}")

    hostname = domain.removesuffix(suffix).strip(".")
    service = f"_{settings.tlsa_port}._tcp"

    return service if not hostname else f"{service}.{hostname}"


def synchronize_domain(
    settings: Settings, client: DesecClient, domain: str, records: tuple[str, ...]
) -> bool:
    subname = _desec_subname(settings, domain)
    changed = client.upsert_rrset(settings.desec_zone, subname, records, settings.desec_ttl)

    if changed:
        LOG.info(
            "TLSA RRset %s for %s updated with %d record(s); next check in %ss.",
            subname,
            domain,
            len(records),
            settings.interval,
        )
    else:
        LOG.info(
            "TLSA RRset %s for %s is already up to date (%d record(s)); next check in %ss.",
            subname,
            domain,
            len(records),
            settings.interval,
        )

    return changed


def synchronize_all(settings: Settings, client: DesecClient) -> None:
    ssl_dir = settings.mailcow_ssl_dir
    try:
        records = _read_tlsa_records(ssl_dir)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as error:
        LOG.error("Could not derive TLSA records from %s: %s", ssl_dir, error)
        return

    for domain in settings.domains:
        try:
            synchronize_domain(settings, client, domain, records)
        except Exception as error:
            LOG.error(
                "Could not synchronize TLSA RRset for %s in deSEC zone %s: %s [%s]",
                domain,
                settings.desec_zone,
                error,
                type(error).__name__,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )


def run(settings: Settings) -> None:
    client = DesecClient(
        settings.desec_token,
        settings.timeout,
        settings.desec_base_url,
        settings.desec_cache_file,
    )
    try:
        synchronize_all(settings, client)
        while True:
            time.sleep(settings.interval)
            synchronize_all(settings, client)
    finally:
        client.close()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    settings = Settings.from_environment()

    LOG.info("Watching %d domain(s) every %ss", len(settings.domains), settings.interval)
    run(settings)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        LOG.info("Stopped")
