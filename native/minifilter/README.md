# OpenGuard minifilter signing gate

OpenGuard does not ship an unsigned kernel driver. This directory freezes the pointer-free, fixed-size v1 file-event protocol and contains a fail-closed build gate. The driver implementation is intentionally withheld until all of these external prerequisites exist:

1. A Microsoft-assigned minifilter altitude and Hardware Developer Program account.
2. A separate driver threat model and independent kernel review.
3. Static Driver Verifier, Driver Verifier, fuzz, crash-dump, upgrade/rollback, and HLK plans.
4. Microsoft-compatible production signing and a recovery-tested installer.

The eventual minifilter will emit only create/write/execute metadata and selected browser-vault read opens. It will not parse YARA, JSON, SQLite, network payloads, or variable recursive structures in kernel mode. Pre-execution holds must have a strict timeout and default-allow on service failure; automatic deny requires a cryptographic signature or exact high-confidence policy, never a heuristic score.
