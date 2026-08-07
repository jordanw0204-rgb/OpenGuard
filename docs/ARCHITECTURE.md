# Architecture and threat model

## Design principles

- Local-first: no telemetry and no file-upload path.
- Explainable: every non-clean score includes concrete evidence.
- Safe failure: access denied and malformed files become explicit limited/error results, not crashes or implicit trust.
- Non-destructive by default: no process termination, auto-delete, Defender changes, or driver installation.
- Least privilege: the desktop MVP works without elevation and labels reduced coverage.

## Runtime flow

The LocalSystem service runs the monitor while the desktop app is closed. A small native helper controls a private real-time `Microsoft-Windows-Kernel-Process` ETW session; process start/stop events trigger immediate refreshes while bounded polling reconciles state and supplies CPU/network metrics. A read-only WFP net-event subscription reports capability/activity without adding filters. IP Helper remains the endpoint inventory source, and the elevated service enables supported TCP Extended Statistics collection for real per-connection byte counters.

The scanner runs on a worker, streams SHA-256, limits in-memory inspection, and combines transparent heuristics, YARA-X, Authenticode, and the installed AMSI provider. Security-content manifests are authenticated with a pinned Ed25519 public key; every content file is size/hash checked and validated in staging before an atomic version switch.

SQLite uses WAL mode and one connection per operation. The database, logs, and quarantine live under `%LOCALAPPDATA%\OpenGuard` unless `OPENGUARD_DATA_DIR` is set for tests or portable diagnostics.

## Windows API choices

- Tool Help + process query APIs provide a robust unprivileged inventory, with protected processes represented as limited records.
- `GetExtendedTcpTable` and `GetExtendedUdpTable` expose current owner-PID endpoints. `GetPerTcpConnectionEStats` supplies observed TCP byte totals after the LocalSystem service enables collection; the desktop app computes rates from monotonic deltas. UDP byte rates and encrypted packet contents remain unavailable.
- `WinVerifyTrust` checks Authenticode policy. Only a return value of zero is trusted; unsigned, invalid, and offline-revocation cases remain distinct from an application allow-list.
- `StartTraceW`, `EnableTraceEx2`, `OpenTraceW`, and `ProcessTrace` consume kernel process events from the elevated service. Failure is visible and falls back to polling.
- `FwpmEngineOpen0` and `FwpmNetEventSubscribe0` create a read-only net-event subscription. OpenGuard installs no WFP filter or callout.
- AMSI is consumed as an optional second opinion from the installed antimalware provider. OpenGuard is not an AMSI provider.

## Trust boundaries

```text
Untrusted files/process/network metadata
          |
          v
native/ctypes adapters + bounded parsers ---- installed AMSI provider (optional)
          |
          v
heuristics + YARA-X ---- SQLite (shared WAL) ---- quarantine (explicit action)
          ^
          |
Ed25519 manifest -> hash/size/rule validation -> atomic content activation
          |
          v
desktop UI / JSON CLI
```

The current user, LocalSystem service, local database, and UI are not a security boundary against a hostile local administrator or kernel attacker. File paths may race between observation and scan/quarantine; quarantine verifies the scanned hash before moving and verifies it again before restore, but OpenGuard does not hold kernel-level file identities.

## Privileged boundary

ETW/WFP subscriptions run in the service because their access controls normally reject the desktop user's token. The desktop keeps a user-mode fallback so loss of the service is visible rather than fatal. There is no privileged IPC command surface in v0.2; service health is shared through narrowly scoped SQLite metadata.

Packet/stream interception and file-system minifilters remain out of scope. If a future audited driver is justified, it must use Microsoft retail signing. OpenGuard will not ask users to enable test signing or disable Secure Boot.

## Source references

- [Windows Filtering Platform overview](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [WFP architecture](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-architecture-overview)
- [GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
- [Event tracing sessions and permissions](https://learn.microsoft.com/en-us/windows/win32/etw/controlling-event-tracing-sessions)
- [SystemTraceProvider sessions](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session)
- [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [Antimalware Scan Interface](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [Driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)
- [MSIX package signing](https://learn.microsoft.com/en-us/windows/msix/package/signing-package-overview)
- [YARA-X documentation](https://virustotal.github.io/yara-x/docs/)
- [ClamAV documentation](https://docs.clamav.net/)
