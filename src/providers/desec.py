"""deSEC API client for TLSA RRsets."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, cast
from urllib.parse import quote

import httpx

LOG = logging.getLogger("tlsa-sync.providers.desec")


class CacheEntry(TypedDict):
    exists: bool
    records: list[str]
    ttl: int | None


@dataclass(frozen=True)
class RRset:
    """A deSEC RRset identified by its zone-relative subname."""

    domain: str
    subname: str
    rrtype: str
    records: tuple[str, ...]
    ttl: int | None = None


class DesecClient:
    """Small deSEC client that avoids writes when an RRset is unchanged."""

    def __init__(
        self,
        token: str,
        timeout: float,
        base_url: str = "https://desec.io/api/v1",
        cache_file: str = "/data/desec-cache.json",
    ) -> None:
        self._cache_path = Path(cache_file)
        self._cache: dict[str, CacheEntry] = self._load_cache()
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Token {token}", "Accept": "application/json"},
            timeout=timeout,
            event_hooks={"request": [self._log_request], "response": [self._log_response]},
        )

    def close(self) -> None:
        self._client.close()

    def get_rrset(self, domain: str, subname: str, rrtype: str = "TLSA") -> RRset | None:
        cache_key = self._cache_key(domain, subname, rrtype)

        if cache_key in self._cache:
            LOG.debug("deSEC cache hit for %s/%s/%s", domain, subname, rrtype)
            cached = self._cache[cache_key]

            if not cached["exists"]:
                return None

            return RRset(domain, subname, rrtype, tuple(cached["records"]), cached["ttl"])

        response = self._client.get(self._rrset_path(domain, subname, rrtype))

        if response.status_code == 404:
            self._cache[cache_key] = {"exists": False, "records": [], "ttl": None}
            self._save_cache()

            return None

        response.raise_for_status()
        payload = response.json()
        records = tuple(sorted(_record_text(record) for record in payload.get("records", [])))
        rrset = RRset(domain, subname, rrtype, records, payload.get("ttl"))
        self._cache[cache_key] = {"exists": True, "records": list(records), "ttl": rrset.ttl}
        self._save_cache()

        return rrset

    def upsert_rrset(
        self,
        domain: str,
        subname: str,
        records: tuple[str, ...],
        ttl: int,
        rrtype: str = "TLSA",
    ) -> bool:
        """Create or replace an RRset. Returns True when a request was sent."""
        desired = tuple(sorted(set(records)))
        current = self.get_rrset(domain, subname, rrtype)

        if current is not None and current.records == desired and current.ttl == ttl:
            return False

        response = self._client.put(
            self._rrset_path(domain, subname, rrtype),
            json={"records": list(desired), "ttl": ttl},
        )
        response.raise_for_status()
        self._cache[self._cache_key(domain, subname, rrtype)] = {
            "exists": True,
            "records": list(desired),
            "ttl": ttl,
        }
        self._save_cache()

        return True

    def _load_cache(self) -> dict[str, CacheEntry]:
        try:
            payload = json.loads(self._cache_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

        return cast(dict[str, CacheEntry], payload) if isinstance(payload, dict) else {}

    def _save_cache(self) -> None:
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = self._cache_path.with_suffix(".tmp")
            temporary_path.write_text(json.dumps(self._cache, sort_keys=True) + "\n")
            temporary_path.replace(self._cache_path)
        except OSError:
            # A read-only cache must not prevent synchronization.
            return

    @staticmethod
    def _log_request(request: httpx.Request) -> None:
        LOG.debug("deSEC request: %s %s", request.method, request.url)

    @staticmethod
    def _log_response(response: httpx.Response) -> None:
        LOG.debug("deSEC response: %s %s", response.status_code, response.request.url)

    @staticmethod
    def _cache_key(domain: str, subname: str, rrtype: str) -> str:
        return f"{domain.strip('.')}|{subname.strip('.')}|{rrtype.upper()}"

    @staticmethod
    def _rrset_path(domain: str, subname: str, rrtype: str) -> str:
        encoded_domain = quote(domain.strip("."), safe="")
        encoded_subname = quote(subname.strip("."), safe="")
        return f"/domains/{encoded_domain}/rrsets/{encoded_subname}/{rrtype.upper()}/"


def _normalize_record_text(record: object) -> str:
    return " ".join(str(record).split())


def _record_text(record: object) -> str:
    """Normalize API records whether deSEC returns strings or record objects."""
    if isinstance(record, dict) and "rr" in record:
        return _normalize_record_text(record["rr"])
    return _normalize_record_text(record)
