# Contributing

Contributions are welcome. Keep detection logic explainable, local-first, and conservative.

1. Create a focused branch and add tests for behavior changes.
2. Run `python -m unittest discover -s tests -v` on Windows.
3. Run `python openguard_cli.py doctor --pretty` and a packaged snapshot smoke test for native changes.
4. Do not add telemetry, file uploads, auto-delete behavior, unsigned drivers, or Defender configuration changes without an approved design and threat-model update.
5. Do not commit malware samples, private threat feeds, API keys, signing material, or user scan databases.

Detection rules must document their signal, expected false positives, severity rationale, and inert test cases.
