from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from support import add_src_to_path

add_src_to_path()

from openguard.models import NetworkEndpoint
from openguard.reputation import EndpointEnricher, ReputationFeed


class ReputationTests(unittest.TestCase):
    def test_local_and_signed_feed_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            feed_path = Path(directory) / "reputation.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "version": "test",
                        "entries": [
                            {
                                "indicator": "203.0.113.0/24",
                                "verdict": "malicious",
                                "label": "documentation-only test range",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            feed = ReputationFeed(feed_path)
            self.assertEqual(feed.classify("127.0.0.1")[0], "local")
            self.assertEqual(feed.classify("203.0.113.12")[0], "malicious")
            self.assertEqual(feed.classify("8.8.8.8")[0], "unknown")

    def test_enrichment_does_not_block_for_ptr_lookup(self) -> None:
        endpoint = NetworkEndpoint("TCP4", "127.0.0.1", 1, "8.8.8.8", 53, "ESTABLISHED", 4)
        enricher = EndpointEnricher(ttl_seconds=5)
        try:
            enriched = enricher.enrich([endpoint])[0]
            self.assertEqual(enriched.reputation, "unknown")
            self.assertEqual(enriched.remote_hostname, "")
        finally:
            enricher.close()


if __name__ == "__main__":
    unittest.main()
