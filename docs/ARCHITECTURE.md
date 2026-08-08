# Architecture and threat model

OpenGuard 0.3 is a native, local-first Windows security companion. A Rust service owns security state and collection, a WinUI 3 client renders bounded snapshots over a versioned local pipe, and a small C++ helper consumes kernel process ETW when the service has permission.

## Runtime flow

```text
Windows processes/endpoints
        |
        +-- Tool Help + IP Helper + TCP EStats
        +-- ETW helper (process event coverage/counts)
        `-- read-only WFP subscription (coverage/counts; no filters)
                              |
                              v
                     OpenGuardService.exe
                  / scanner | SQLite | updates \
                 /          | policy | quarantine \
                v           v                    v
       OpenGuard.exe <== bounded named pipe ==> OpenGuardCLI.exe
```

The UI performs no privileged collection, database access, DNS lookup, or file scanning on its thread. It requests coalesced snapshots and applies filtering/sorting to retained view-model collections. Scans run on service background workers with progress and cancellation.

## Windows API choices

- Tool Help and process-query APIs provide process inventory; protected processes remain visible with limited evidence.
- `GetExtendedTcpTable` and `GetExtendedUdpTable` map IPv4/IPv6 endpoints to owning PIDs. Supported TCP connections use Extended Statistics monotonic byte counters, from which the UI derives transfer rates. UDP byte rates and packet contents are not available.
- PTR names are resolved by one bounded, deduplicated Windows resolver worker with a finite cache and TTL.
- `WinVerifyTrust` checks Authenticode. Only exact success is trusted.
- `StartTraceW`/`ProcessTrace` power the ETW helper. Access denial is reported as limited coverage and inventory polling continues.
- `FwpmEngineOpen0`/`FwpmNetEventSubscribe0` provide read-only WFP event coverage. OpenGuard installs no filter or callout.
- AMSI is an optional second opinion supplied by the antimalware provider configured on the PC.

## Trust boundaries

The named pipe rejects remote clients, has a bounded 4 MiB frame, uses strict typed JSON, and captures the Windows client PID/SID under impersonation. User-owned state—scan jobs, events, exclusions, hash allowances, and quarantine records—is scoped to that authenticated SID. The service is the only database owner.

Scanning streams SHA-256 and bounds file size/in-memory inspection before YARA-X, heuristics, Authenticode, and AMSI are applied. Quarantine rechecks the scanned digest, uses a non-executable authenticated container, never overwrites on restore, and verifies integrity again before restoration.

Security-content manifests are canonicalized and verified with a pinned Ed25519 key. HTTPS transport, declared size, SHA-256, schema, CIDR entries, and YARA compilation must all pass in staging before atomic activation; the previous version remains available for rollback.

The standalone scanner currently runs with its caller's token, while service-requested scans run on bounded background threads in the service. A restricted-token/job-object scanner subprocess is a future hardening boundary, not a current claim.

## Explicit limits

OpenGuard does not decrypt TLS, inspect packet payloads, intercept files in kernel mode, register with Windows Security, or protect against a hostile administrator/kernel attacker. ETW, WFP event subscription, and some TCP counters require the installed LocalSystem service; unavailable access is surfaced as limited coverage. OpenGuard does not automatically delete files or terminate processes.

Keep Microsoft Defender or another mature antivirus enabled. Future minifilter/WFP enforcement requires WDK validation, independent review, and Microsoft-compatible retail signing; users will never be asked to disable Secure Boot or enable test signing for a public build.

See [NATIVE_ARCHITECTURE.md](NATIVE_ARCHITECTURE.md) for the detailed decision record and release criteria.
