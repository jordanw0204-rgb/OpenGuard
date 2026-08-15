# Architecture and threat model

OpenGuard 0.7 is a native, local-first Windows security companion. A Rust service owns security state and collection, a WinUI 3 client renders bounded cached snapshots over a versioned local pipe, and a small C++ helper consumes kernel process ETW when the service has permission.

## Runtime flow

```text
Windows processes/endpoints
        |
        +-- Tool Help + IP Helper + TCP EStats
        +-- ETW helper + Security/Defender Event Log channels
        +-- optional existing Sysmon Operational channel
        `-- WFP net-event coverage + confirmed Firewall/WFP rules
                              |
                              v
                     OpenGuardService.exe
                  / scanner | SQLite | updates \
                 /          | policy | quarantine \
                v           v                    v
       OpenGuard.exe <== bounded named pipe ==> OpenGuardCLI.exe
```

The UI performs no privileged collection, database access, DNS lookup, or file scanning on its thread. An independent three-second service loop owns expensive process/network collection, analyzes only newly observed executable identities, and publishes a cached snapshot. UI requests clone that cache, while scan jobs run on bounded background workers with progress and cancellation.

## Windows API choices

- Tool Help and process-query APIs provide process inventory; protected processes remain visible with limited evidence.
- `GetExtendedTcpTable` and `GetExtendedUdpTable` map IPv4/IPv6 endpoints to owning PIDs. Supported TCP connections use Extended Statistics monotonic byte counters, from which the UI derives transfer rates. UDP byte rates and packet contents are not available.
- PTR names are resolved by one bounded, deduplicated Windows resolver worker with a finite cache and TTL.
- `WinVerifyTrust` checks Authenticode. Only exact success is trusted.
- `StartTraceW`/`ProcessTrace` power the ETW helper. Access denial is reported as limited coverage and inventory polling continues.
- `EvtSubscribe` consumes future Security 4688/4689 and Defender 1116/1117/5007 events. An optional second subscriber uses an already configured Sysmon Operational channel without installing or changing Sysmon.
- `FwpmEngineOpen0`/`FwpmNetEventSubscribe0` provide read-only WFP event coverage. A confirmed response can add an application-plus-remote-IP Windows Firewall rule, which Windows enforces through WFP; OpenGuard installs no custom callout.
- AMSI is an optional second opinion supplied by the antimalware provider configured on the PC.
- `VirtualQueryEx` supplies allocation metadata for bounded new/untrusted-process inspection; this path does not copy process memory.
- Goblin parses PE import tables inside the already bounded content sample. Capability evidence is correlated with trust, memory, ancestry, and network behavior before severity rises.

## Trust boundaries

The named pipe rejects remote clients, has a bounded 4 MiB frame, uses strict typed JSON, and captures the Windows client PID/SID under impersonation. User-owned state—scan jobs, events, exclusions, hash allowances, and quarantine records—is scoped to that authenticated SID. The service is the only database owner.

Scanning streams SHA-256 and bounds file size/in-memory inspection before YARA-X, heuristics, Authenticode, and AMSI are applied. Quarantine rechecks the scanned digest, uses a non-executable authenticated container, never overwrites on restore, and verifies integrity again before restoration.

Security-content manifests are canonicalized and verified with a pinned Ed25519 key. HTTPS transport, declared size, SHA-256, schema, CIDR entries, and YARA compilation must all pass in staging before atomic activation; the previous version remains available for rollback. Version-bound SHA-256 baselines detect same-version service/helper replacement and report it without self-bricking the service.

Optional telemetry is treated as untrusted input. Event XML is size/field bounded before parsing, callbacks use finite non-blocking queues with surfaced drop counts, correlation state is capped at 4,096 process chains with 32 signals each, evidence expires after 10 minutes, and duplicate chain alerts cool down for one hour. SQLite keeps only the newest 10,000 detections and 100,000 timeline rows.

The standalone scanner currently runs with its caller's token, while service-requested scans run on bounded background threads in the service. A restricted-token/job-object scanner subprocess is a future hardening boundary, not a current claim.

## Explicit limits

OpenGuard does not decrypt TLS, inspect packet payloads, intercept files in kernel mode, register with Windows Security, or protect against a hostile administrator/kernel attacker. ETW, Event Log, optional Sysmon, WFP event subscription, and some TCP counters require the installed LocalSystem service or corresponding Windows audit configuration; unavailable access is surfaced as limited coverage. Static capabilities and memory layout are evidence, not proof. OpenGuard does not automatically delete files, terminate processes, or change Sysmon configuration.

Keep Microsoft Defender or another mature antivirus enabled. The existing driverless Windows Firewall/WFP isolation covers explicit application/destination blocks. A future minifilter or custom WFP callout will be reconsidered only after sponsorship, a demonstrated user-mode coverage gap, WDK validation, independent review, and Microsoft-compatible retail signing; users will never be asked to disable Secure Boot or enable test signing for a public build.

See [NATIVE_ARCHITECTURE.md](NATIVE_ARCHITECTURE.md) for the detailed decision record and release criteria.
