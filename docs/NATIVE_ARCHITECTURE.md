# OpenGuard native architecture

Status: Implemented through the native v0.4 release
Decision date: 2026-08-07

## Decision

OpenGuard will no longer ship Python. The production architecture is split into three deliberately narrow technology boundaries:

1. A Rust 2024 workspace implements the domain model, detection engine, persistence, Windows user-mode telemetry, background service, scanner worker, updater, quarantine, and CLI.
2. A C#/.NET 10 WinUI 3 application implements the unprivileged desktop experience. It contains presentation logic only and never opens the security database or privileged Windows handles directly.
3. C++ and the Windows Driver Kit are reserved for the future file-system minifilter and Windows Filtering Platform callout. Kernel code is not used for logic that can remain memory-safe in user mode.

The former Python implementation and its build/test dependencies have been removed. Native Rust, C#, and C++ sources are the only production implementation.

## Why this architecture

- Rust provides native code, deterministic ownership, safe concurrency, and strong parser boundaries for untrusted files and telemetry.
- WinUI 3 is Microsoft's current native Windows desktop UI platform. C# provides the supported WinRT projection and a mature binding/MVVM ecosystem without placing managed code in the privileged sensor.
- The `windows` Rust crate is generated from official Windows metadata and feature-gates the Win32 surface, allowing the project to keep unsafe FFI small and auditable.
- YARA-X is already implemented in Rust and exposes its native Rust crate, avoiding a Python interpreter or a scanner subprocess bridge.
- Microsoft documents minifilters as the supported file-I/O interception model for antivirus products and WFP callouts as the supported deep network-inspection model. Those components require a WDK toolchain, independent review, Microsoft-compatible signing, and isolated deployment.

This is intentionally not an all-C++ rewrite. Putting rule parsing, update parsing, IPC, persistence, and UI orchestration into C++ would increase memory-safety risk without improving the relevant bottlenecks. It is also not an all-C# rewrite: the always-on sensor and untrusted-content engine should not depend on a managed runtime or garbage-collection pauses.

## Repository topology

```text
OpenGuard/
|-- Cargo.toml                         Rust workspace and pinned dependency policy
|-- crates/
|   |-- openguard-domain/              Immutable models, risk evidence, protocol types
|   |-- openguard-storage/             SQLite migrations and repositories; service-only
|   |-- openguard-detection/           Hashing, YARA-X, PE/script heuristics, AMSI orchestration
|   |-- openguard-windows/             ETW, IP Helper, EStats, WinTrust, AMSI, WFP user-mode APIs
|   |-- openguard-ipc/                 Bounded framing, authorization and protocol negotiation
|   |-- openguard-service/             SCM host, orchestration, event pipeline and command handlers
|   |-- openguard-scanner/             Standalone scanner and hardening boundary
|   `-- openguard-cli/                 Diagnostics, automation and service management
|-- apps/
|   `-- OpenGuard.App/                 .NET 10 / WinUI 3 / MVVM desktop client
|-- contracts/                         Protocol schema, version fixtures and compatibility tests
|-- drivers/                           Future separately signed minifilter and WFP projects
|-- security-content/                  Signed rules and reputation content
|-- native/                            Minimal C++ ETW helper
`-- security-content/                  Signed rules and reputation content
```

Crates may depend only downward:

```text
domain
  ^
  |-- storage
  |-- detection
  |-- windows
  `-- ipc
        ^
        |-- service --> scanner worker
        `-- CLI

WinUI client ------ versioned local IPC ------ service
drivers ----------- bounded driver protocol --- service
```

No UI assembly is loaded by the service. No driver parses JSON, YARA rules, SQLite, or update manifests.

## Process and privilege model

| Process | Default token | Responsibility |
|---|---|---|
| `OpenGuard.exe` | Interactive user | Rendering, navigation, local preferences, consent prompts |
| `OpenGuardService.exe` | LocalSystem service SID | Windows telemetry, database ownership, scheduling, policy and privileged coordination |
| `OpenGuardScanner.exe` | Caller token | Standalone bounded scan diagnostics; future restricted worker boundary |
| `OpenGuardCLI.exe` | Caller token | Automation client and explicit elevated service management |
| Future `.sys` drivers | Kernel | Minimal event capture/enforcement only; no policy or content parsing |

The service runs as LocalSystem. Its named pipe has an explicit DACL, rejects remote clients, and authenticates each caller before owner-scoped operations. Global writable runtime paths, anonymous pipe access, and UI-requested arbitrary command execution are forbidden.

## IPC contract

The local protocol is a four-byte little-endian length followed by strict UTF-8 JSON. JSON is chosen only at the low-rate control/presentation boundary, where readability and cross-language compatibility matter more than encoding throughput.

- Pipe name: `\\.\pipe\OpenGuard.v1`
- Maximum frame: 4 MiB; larger frames are rejected before allocation.
- Every request contains `protocol`, `request_id`, `operation`, and a typed `payload`.
- Every response echoes `request_id` and contains either typed `data` or a stable error code.
- Every request declares protocol version 1; incompatible versions fail closed.
- Unknown required fields, invalid enum values, duplicate identifiers, trailing bytes, and malformed UTF-8 fail closed.
- Telemetry is exposed as bounded request/response snapshots, keeping slow clients out of the collector path.
- The pipe receives an explicit DACL. Remote and anonymous access are denied. The service obtains and validates the client token/SID before executing a command.
- Read-only status is available to authenticated interactive users. Quarantine, restore, exclusions, allow-list changes, updates, and service mutations have separate authorization checks and audit events.

The protocol schema and golden messages under `contracts/` are authoritative. UI and service builds must pass compatibility tests against the current and previous supported protocol versions.

## State ownership

The service is the sole writer and normal reader of the security database. The UI and CLI query through IPC, preventing lock contention and removing SQLite from the privileged boundary exposed to arbitrary clients.

- Machine security state: `%ProgramData%\OpenGuard`
- Quarantine: `%ProgramData%\OpenGuard\Quarantine`, owned and mediated by the LocalSystem service
- Per-user UI preferences: `%LOCALAPPDATA%\OpenGuard`
- Logs: Windows Event Log plus bounded local diagnostic logs with no file contents

Native v0.3 starts a new machine database. The former prototype database is not imported automatically because its trust and ownership model differs from the service-owned schema.

## Telemetry pipeline

1. A minimal native ETW helper subscribes to kernel process events and reports event counts and coverage state.
2. Tool Help and IP Helper snapshots reconcile current process and endpoint state on each bounded snapshot request.
3. TCP EStats supplies connection byte counters where Windows exposes them; the client calculates rates from successive monotonic samples.
4. A read-only WFP subscription reports availability and event counts without installing filters.
5. The service enriches observations with executable identity, Authenticode, signed reputation, and per-user history.
6. A correlation pass combines process ancestry, executable novelty/trust, and destination reputation into additive, explainable evidence; ordinary trusted network activity does not become an alert by itself.
7. Storage uses short SQLite WAL transactions for durable scan, alert, policy, quarantine, update, and executable-baseline state.
8. IPC returns bounded snapshots; DNS lookups run in a cached background resolver and never block a response.

All queues have capacity, cancellation, shutdown, health, dropped-event and latency metrics. Access denied is a first-class limited-coverage result, not an exception loop.

## Detection and scanning

- Stream SHA-256 rather than loading whole files.
- Use YARA-X 1.19 through its Rust API with includes disabled and explicit scan limits.
- Parse only bounded PE regions needed by explainable heuristics.
- Invoke AMSI as an optional installed-provider second opinion.
- Verify Authenticode with `WinVerifyTrust`; only exact success is trusted.
- Preserve explicit verdicts: clean, low risk, suspicious, malicious, skipped, error and cancelled.
- Run service-requested scans on a bounded background worker so IPC and WinUI remain responsive. `OpenGuardScanner.exe` exposes the same native engine for standalone diagnostics; restricted-token/job isolation remains a hardening milestone.
- Re-open/verify file identity before quarantine, store content under a non-executable extension, and verify its hash again before restore.

No model-generated or opaque score is allowed to cause an automatic destructive action. Every alert has evidence, confidence, observation time and coverage source.

## Update security

- Security content remains local-first and opt-in for network retrieval.
- HTTPS transport is necessary but not trusted by itself.
- Ed25519 verifies a canonical manifest with a pinned key identifier.
- Size and SHA-256 are checked before parsing; rules and reputation data validate in staging.
- Activation is an atomic directory/version switch with last-known-good rollback.
- Key rotation requires a manifest signed by both the active and next trusted key during the overlap window.
- The private content-signing key and Authenticode credentials never enter the repository or ordinary developer machines.

## UI/UX direction

The new interface is an investigation workspace rather than a themed Task Manager clone.

- Black and neutral graphite surfaces; color is reserved for state and evidence.
- A compact rail, persistent machine-health header, command/search surface, and contextual detail pane replace page-sized table redraws.
- Overview answers three questions immediately: "Am I protected?", "What changed?", and "What needs action?"
- Processes and network activity share an entity model so selecting an application reveals its executable trust, process tree, destinations, transfer history and alerts in one place.
- The investigation dialog computes SHA-256 asynchronously and correlates process ancestry, owned connections, startup folders, and Run/RunOnce values without blocking collection or navigation.
- Large collections use virtualization, incremental updates and stable selection. Navigation never performs service, database, DNS or file work on the UI thread.
- Severity is communicated with text/icon/shape as well as color. Keyboard navigation, screen readers, reduced motion, high contrast and 200% scaling are release gates.
- The new mark must not be a shield, lock, bug, skull or generic antivirus checkmark. The selected concept is an abstract open aperture/gate with a deliberate gap and central signal, representing visibility, control and open source.

## Performance budgets

Budgets are measured on the CI reference machine and a documented local Windows machine after a five-minute warmup:

| Metric | Release budget |
|---|---|
| Service idle CPU | <= 1% five-minute average |
| Service idle working set | <= 100 MiB |
| UI idle working set | <= 250 MiB |
| Cached IPC request p95 | <= 50 ms |
| UI navigation handler p95 | <= 16 ms; no blocking I/O |
| Process/network reconciliation p95 | <= 1 second |
| Sustained event loss | 0 under the documented load test; drops otherwise surfaced |
| In-memory detection throughput | >= 1.5x the v0.2 Python reference on the same machine |
| Clean shutdown | <= 5 seconds with no leaked session/service handles |

Release builds enable Rust LTO, one codegen unit, panic abort, overflow checks, and stripped symbols in distributed binaries while retaining separate symbols for crash analysis.

## Kernel roadmap and signing gate

A strong native architecture does not justify prematurely shipping a driver. The first native release preserves and improves all current user-mode behavior. The next protected-mode milestone adds:

1. A minimal minifilter that reports file create/write/execute identity and can hold an execution decision within a strict timeout.
2. A minimal WFP callout for flow metadata and explicitly authorized blocking, not TLS decryption.
3. A versioned binary driver protocol with no user-provided pointers or variable recursion.
4. Static analysis, Driver Verifier, fuzzing, HLK, independent review, crash-dump handling and Microsoft-compatible retail signing.

OpenGuard will never instruct users to disable Secure Boot or enable test signing for a public release.

## Release acceptance criteria

The migration is complete only when all of the following are proven:

- The release artifacts contain no Python interpreter, Python bytecode, PyInstaller loader or Python package.
- There are no `.py`/`.pyw` production or test files, `pyproject.toml`, or Python requirements/build steps in the release branch.
- Every documented v0.2 capability has a native parity test or an explicitly improved replacement.
- The service is the only privileged process and the only database owner.
- IPC frame bounds, ACLs, client identity and operation authorization have automated/live tests.
- Scanning, cancellation, signed updates, rollback, quarantine and restore pass adversarial tests.
- Process/network telemetry and TCP byte rates pass live Windows checks with visible limited-coverage states.
- The new WinUI interface passes functional, accessibility, scaling, stress and screenshot review.
- The new non-shield identity appears in window chrome, executable resources, installer and documentation.
- A clean machine can build, install, start, stop, upgrade and uninstall the product using documented commands.
- Portable ZIP and per-machine MSI artifacts have matching SHA-256 records; MSI administrative extraction is part of release validation.
- Unit, integration, fuzz-smoke, performance, package and installed-runtime audits pass in CI.
- Public release documentation continues to state the exact protection limits until signed kernel protection and independent validation exist.

## Primary references

- Windows App SDK and WinUI: <https://learn.microsoft.com/windows/apps/windows-app-sdk/>
- Windows app performance: <https://learn.microsoft.com/windows/apps/performance/>
- Windows named-pipe security: <https://learn.microsoft.com/windows/win32/ipc/named-pipe-security-and-access-rights>
- Event Tracing for Windows: <https://learn.microsoft.com/windows/win32/etw/event-tracing-portal>
- Windows Filtering Platform: <https://learn.microsoft.com/windows/win32/fwp/windows-filtering-platform-start-page>
- File-system minifilters: <https://learn.microsoft.com/windows-hardware/drivers/ifs/about-file-system-filter-drivers>
- Windows Driver Kit: <https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk>
- Driver signing: <https://learn.microsoft.com/windows-hardware/drivers/install/driver-signing>
- Rust for Windows: <https://github.com/microsoft/windows-rs>
- YARA-X: <https://github.com/VirusTotal/yara-x>
