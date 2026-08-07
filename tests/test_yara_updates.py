from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from support import add_src_to_path

add_src_to_path()

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openguard.updates import SecurityContentUpdater, UpdateError, canonical_manifest_payload
from openguard.yara_engine import YaraEngine


class YaraEngineTests(unittest.TestCase):
    def test_builtin_marker_is_explainable(self) -> None:
        engine = YaraEngine()
        self.assertEqual(engine.status, "ready", engine.error)
        matches = engine.scan(b"OPENGUARD_INERT_YARA_TEST_MARKER_2026")
        self.assertEqual(matches[0].identifier, "OpenGuard_Inert_Test_Marker")
        self.assertEqual(matches[0].severity, "malicious")


class SecurityContentUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.updater = SecurityContentUpdater(public_key=public, root=self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _manifest(self, version: str, data: bytes) -> bytes:
        value = {
            "schema": 1,
            "version": version,
            "published_at": "2026-08-06T00:00:00Z",
            "files": [
                {
                    "path": "rules/community.yar",
                    "url": "https://updates.example.invalid/community.yar",
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
            ],
        }
        value["signature"] = base64.b64encode(
            self.private.sign(canonical_manifest_payload(value))
        ).decode("ascii")
        return json.dumps(value).encode("utf-8")

    def test_verified_update_activates_and_rolls_back(self) -> None:
        rule_one = b'rule VersionOne { condition: true }'
        rule_two = b'rule VersionTwo { condition: false }'
        self.updater.install(self._manifest("one", rule_one), lambda _url, _size: rule_one)
        self.updater.install(self._manifest("two", rule_two), lambda _url, _size: rule_two)
        self.assertEqual(self.updater.state()["active_version"], "two")
        self.assertEqual(self.updater.rollback(), "one")
        self.assertEqual(self.updater.state()["active_version"], "one")

    def test_tampered_manifest_is_rejected(self) -> None:
        rule = b'rule Valid { condition: true }'
        value = json.loads(self._manifest("one", rule))
        value["version"] = "changed"
        with self.assertRaisesRegex(UpdateError, "signature"):
            self.updater.install(json.dumps(value).encode(), lambda _url, _size: rule)

    def test_hash_mismatch_never_activates(self) -> None:
        rule = b'rule Valid { condition: true }'
        with self.assertRaisesRegex(UpdateError, "SHA-256"):
            self.updater.install(self._manifest("one", rule), lambda _url, _size: b"x" * len(rule))
        self.assertEqual(self.updater.state(), {})

    def test_non_https_content_url_is_rejected_even_when_signed(self) -> None:
        rule = b'rule Valid { condition: true }'
        raw = json.loads(self._manifest("one", rule))
        raw["files"][0]["url"] = "http://example.invalid/rule.yar"
        raw["signature"] = base64.b64encode(
            self.private.sign(canonical_manifest_payload(raw))
        ).decode("ascii")
        with self.assertRaisesRegex(UpdateError, "HTTPS"):
            self.updater.install(json.dumps(raw).encode())


if __name__ == "__main__":
    unittest.main()
