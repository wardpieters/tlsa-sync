"""Poll TLSA records and synchronize them to deSEC."""

from __future__ import annotations

import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import cast

import dns.exception
import dns.resolver

from providers.desec import DesecClient

LOG = logging.getLogger("tlsa-sync")


@dataclass(frozen=True)
class Settings:
    domains: tuple[str, ...]
    desec_zone: str
    tlsa_port: int
    dns_server: str
    dns_port: int
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
        required = {"DOMAIN_LIST": domains, "DNS_SERVER": os.environ.get("DNS_SERVER")}
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"Missing required environment variable(s): {', '.join(missing)}")

        return cls(
            domains=domains,
            desec_zone=_required("DESEC_ZONE").rstrip("."),
            tlsa_port=_positive_int("TLSA_PORT", 25),
            dns_server=str(required["DNS_SERVER"]),
            dns_port=_positive_int("DNS_PORT", 53),
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


def _resolve_nameserver(server: str) -> list[str]:
    addresses = socket.getaddrinfo(server, None, type=socket.SOCK_DGRAM)
    nameservers = list(
        dict.fromkeys(
            cast(str, address[4][0])
            for address in addresses
            if isinstance(address[4][0], str)
        )
    )

    if not nameservers:
        raise OSError(f"Could not resolve DNS server hostname: {server}")

    return nameservers


def _normalize_record_text(record: object) -> str:
    return " ".join(str(record).split())


def lookup_tlsa(settings: Settings, domain: str) -> tuple[str, ...]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = _resolve_nameserver(settings.dns_server)
    resolver.port = settings.dns_port
    resolver.timeout = settings.timeout
    resolver.lifetime = settings.timeout
    answer = resolver.resolve(f"_{settings.tlsa_port}._tcp.{domain}", "TLSA")

    return tuple(sorted({_normalize_record_text(record) for record in answer}))


def _desec_subname(settings: Settings, domain: str) -> str:
    zone = settings.desec_zone
    suffix = f".{zone}"

    if domain != zone and not domain.endswith(suffix):
        raise ValueError(f"Domain {domain} is outside deSEC zone {zone}")

    hostname = domain.removesuffix(suffix).strip(".")
    service = f"_{settings.tlsa_port}._tcp"

    return service if not hostname else f"{service}.{hostname}"


def synchronize_domain(settings: Settings, client: DesecClient, domain: str) -> bool | None:
    try:
        records = lookup_tlsa(settings, domain)
    except (dns.exception.DNSException, OSError) as error:
        LOG.error(
            "Could not query TLSA records for %s via %s:%s within %ss: %s [%s]",
            domain,
            settings.dns_server,
            settings.dns_port,
            settings.timeout,
            error,
            type(error).__name__,
        )

        return None

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
    for domain in settings.domains:
        try:
            synchronize_domain(settings, client, domain)
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
