"""YARA-X adapter with explicit health and explainable match metadata."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import MAX_CONTENT_INSPECTION_BYTES, active_content_path, security_content_root


@dataclass(frozen=True, slots=True)
class YaraMatch:
    identifier: str
    namespace: str
    description: str
    severity: str


class YaraEngine:
    """Compile trusted local rule sources once and scan bounded in-memory data."""

    def __init__(self, rule_paths: Iterable[Path] | None = None) -> None:
        self._lock = threading.RLock()
        self._rules: Any | None = None
        self.status = "initializing"
        self.error = ""
        self.rule_paths = tuple(rule_paths) if rule_paths is not None else tuple(_active_rule_paths())
        self.reload()

    @property
    def available(self) -> bool:
        return self._rules is not None

    def reload(self) -> None:
        try:
            import yara_x

            compiler = yara_x.Compiler()
            compiler.enable_includes(False)
            paths = self.rule_paths or (builtin_rules_path(),)
            for path in paths:
                compiler.add_source(path.read_text(encoding="utf-8"), origin=str(path))
            rules = compiler.build()
            with self._lock:
                self._rules = rules
                self.status = "ready"
                self.error = ""
        except Exception as error:  # optional native module and rule compiler errors
            with self._lock:
                self._rules = None
                self.status = "unavailable"
                self.error = f"{type(error).__name__}: {error}"

    def scan(self, content: bytes) -> tuple[YaraMatch, ...]:
        if self._rules is None:
            return ()
        if len(content) > MAX_CONTENT_INSPECTION_BYTES:
            content = content[:MAX_CONTENT_INSPECTION_BYTES]
        try:
            with self._lock:
                results = self._rules.scan(content)
            matches: list[YaraMatch] = []
            for rule in results.matching_rules:
                metadata = {str(key): value for key, value in rule.metadata}
                matches.append(
                    YaraMatch(
                        identifier=str(rule.identifier),
                        namespace=str(rule.namespace),
                        description=str(metadata.get("description", rule.identifier)),
                        severity=str(metadata.get("severity", "suspicious")).casefold(),
                    )
                )
            return tuple(matches)
        except Exception as error:
            self.status = "scan_error"
            self.error = f"{type(error).__name__}: {error}"
            return ()

    @staticmethod
    def validate_sources(paths: Iterable[Path]) -> None:
        import yara_x

        compiler = yara_x.Compiler()
        compiler.enable_includes(False)
        for path in paths:
            compiler.add_source(path.read_text(encoding="utf-8"), origin=str(path))
        compiler.build()


def builtin_rules_path() -> Path:
    return Path(__file__).with_name("data") / "builtin.yar"


def _active_rule_paths() -> list[Path]:
    paths = [builtin_rules_path()]
    try:
        state = json.loads(active_content_path().read_text(encoding="utf-8"))
        version = str(state["active_version"])
        rules_root = (security_content_root() / "versions" / version / "rules").resolve()
        paths.extend(sorted(rules_root.glob("*.yar")))
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return paths
