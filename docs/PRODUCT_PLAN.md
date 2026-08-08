# OpenGuard product plan

OpenGuard is a local-first, open-source Windows activity monitor and on-demand security scanner. The first release is deliberately a useful, testable user-mode product: it shows processes and application-owned network endpoints, learns which executable versions have been seen, explains risk signals, scans files/folders, and records findings.

It is not yet a replacement for Microsoft Defender or another mature endpoint suite. "See everything" requires several privileged Windows components, signed drivers, continuous signature intelligence, security review, and years of false-positive work. The architecture leaves clean seams for those components without asking users to weaken Windows to run an early build.

## Completed v0.1 foundation

- Windows process inventory and previously unseen executable alerts
- Authenticode trust checks and explainable risk scoring
- IPv4/IPv6 TCP and UDP owner-PID endpoint inventory with service-enabled TCP byte totals/rates
- Local recursive file scanning with SHA-256, transparent rules/heuristics, and optional installed-provider AMSI checks
- Local SQLite alert/scan history
- Explicit, recoverable quarantine action
- Responsive Windows desktop dashboard and headless diagnostic CLI
- Reproducible portable packaging and Windows CI

## Completed v0.2 hardening

- YARA-X 1.19.0 with explainable local rules
- Pinned-key Ed25519 security-content manifests, atomic updates, and rollback
- Quarantine restore, SHA-256 allow-list, visible exclusions, and named scan profiles
- Asynchronous PTR enrichment and signed local reputation feed
- Native ETW process event helper with polling fallback
- Read-only WFP net-event subscription with IP Helper endpoint inventory
- Automatic LocalSystem background service and management CLI
- Conditional Authenticode signing/verification and GitHub release automation

## Completed v0.3–v0.4 native investigation milestone

- Stable, virtualized process and network tables with click-to-sort columns and rolling activity graphs
- In-app process investigation for SHA-256, signer/identity, parent/children, connections, persistence, and evidence
- Explainable cross-signal behavior correlation with explicit false-positive guardrails
- Per-machine MSI deployment of the WinUI console and automatic LocalSystem telemetry service
- Release verification for native-only payloads, checksums, Authenticode status, and administrative MSI extraction

## Completed v0.5 real-time investigation and response

- User-mode real-time file monitoring with bounded queues, USN journal gap checks, reconciliation, and targeted changed-file scans
- Historical process, file, network, persistence, detection, and response timeline with owner-scoped cursor pagination
- Services, drivers, scheduled tasks, WMI consumer, Run/RunOnce, and browser-extension persistence inventory
- Explicit, audited, identity-bound process control, detection-gated quarantine, temporary outbound blocking, and reversible safe startup response

## Current security architecture

```text
Desktop UI (unprivileged)
        |
        v
Desktop monitor / Scanner / Risk engine
   |          |          |
Win32 APIs   Local DB   AMSI consumer (optional)
   |
Toolhelp + IP Helper + WinTrust + YARA-X

Windows service -> native ETW process events + read-only WFP net events
```

## Remaining release gates

1. Obtain and protect a CA-issued Authenticode certificate; build public releases only through the signing workflow.
2. Independent security review, parser fuzzing, false-positive corpus, performance budgets, and update-key rotation drills.
3. Curated community rule/reputation operations with reproducible provenance and review.
4. Only if evidence proves necessary: independently audited, Microsoft-signed kernel components.

The detailed requirements and acceptance criteria are maintained in `.taskmaster/docs/prd.txt`.
