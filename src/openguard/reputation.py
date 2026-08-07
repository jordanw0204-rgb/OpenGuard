"""Privacy-preserving local endpoint enrichment with bounded PTR caching."""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any

from .config import active_content_path, security_content_root
from .models import NetworkEndpoint


class ReputationFeed:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _active_reputation_path()
        self.version = "unavailable"
        self.error = ""
        self._networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str]] = []
        self.reload()

    def reload(self) -> None:
        self._networks.clear()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if raw.get("schema") != 1 or not isinstance(raw.get("entries", []), list):
                raise ValueError("unsupported reputation feed schema")
            self.version = str(raw.get("version", "unknown"))
            for item in raw.get("entries", []):
                if not isinstance(item, dict):
                    continue
                indicator = str(item.get("indicator", ""))
                verdict = str(item.get("verdict", "suspicious")).casefold()
                if verdict not in {"suspicious", "malicious"}:
                    continue
                network = ipaddress.ip_network(indicator, strict=False)
                self._networks.append((network, verdict, str(item.get("label", indicator))))
            self.error = ""
        except (OSError, ValueError, TypeError) as error:
            self.version = "unavailable"
            self.error = f"{type(error).__name__}: {error}"

    def classify(self, address: str) -> tuple[str, str]:
        normalized = address.split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(normalized)
        except ValueError:
            return "unknown", "No remote IP address"
        for network, verdict, label in self._networks:
            if ip.version == network.version and ip in network:
                return verdict, f"Signed local reputation feed: {label}"
        if ip.is_loopback:
            return "local", "Loopback address"
        if ip.is_private or ip.is_link_local:
            return "local", "Private or link-local address"
        if ip.is_unspecified:
            return "local", "Unspecified/listening address"
        return "unknown", "No match in the signed local reputation feed"


class EndpointEnricher:
    def __init__(self, feed: ReputationFeed | None = None, ttl_seconds: float = 600.0) -> None:
        self.feed = feed or ReputationFeed()
        self.ttl_seconds = max(ttl_seconds, 5.0)
        self._cache: dict[str, tuple[float, str]] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="OpenGuardDNS")

    def enrich(self, endpoints: list[NetworkEndpoint]) -> list[NetworkEndpoint]:
        now = time.monotonic()
        enriched: list[NetworkEndpoint] = []
        for endpoint in endpoints:
            address = endpoint.remote_address
            verdict, reason = self.feed.classify(address)
            hostname = self._cached_hostname(address, now)
            enriched.append(
                replace(
                    endpoint,
                    remote_hostname=hostname,
                    reputation=verdict,
                    reputation_reason=reason,
                )
            )
        return enriched

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _cached_hostname(self, address: str, now: float) -> str:
        normalized = address.split("%", 1)[0]
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            return ""
        with self._lock:
            cached = self._cache.get(normalized)
            if cached and cached[0] > now:
                return cached[1]
            if normalized not in self._pending:
                self._pending.add(normalized)
                self._executor.submit(self._resolve, normalized)
        return cached[1] if cached else ""

    def _resolve(self, address: str) -> None:
        try:
            hostname = socket.gethostbyaddr(address)[0]
        except (OSError, socket.error):
            hostname = ""
        with self._lock:
            self._cache[address] = (time.monotonic() + self.ttl_seconds, hostname)
            self._pending.discard(address)


def _active_reputation_path() -> Path:
    try:
        state = json.loads(active_content_path().read_text(encoding="utf-8"))
        version = str(state["active_version"])
        candidate = security_content_root() / "versions" / version / "reputation.json"
        if candidate.is_file():
            return candidate
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return Path(__file__).with_name("data") / "reputation.json"
