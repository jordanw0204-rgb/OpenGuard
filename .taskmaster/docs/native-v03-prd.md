# OpenGuard native v0.3 migration PRD

## Objective

Replace the Python/PyInstaller OpenGuard product with a native, memory-safe and scalable Windows security architecture while preserving every useful v0.2 capability, materially improving performance and responsiveness, and delivering a completely redesigned black/graphite WinUI experience with a new non-shield brand.

## Required deliverables

1. Rust workspace for domain, storage, detection, Windows platform, IPC, service, scanner and CLI.
2. C#/.NET 10 WinUI 3 MVVM application that communicates only through authenticated local IPC.
3. Feature parity for process/network monitoring, EStats usage, ETW/WFP capability telemetry, Authenticode, risk evidence, YARA-X, AMSI, signed updates, profiles, exclusions, allow-list, history and quarantine recovery.
4. Versioned, bounded, ACL-restricted named-pipe protocol and compatibility fixtures.
5. Migration of the v0.2 local database and quarantine metadata.
6. New investigation-first UI/UX with virtualization, background data loading, accessibility and performance budgets.
7. New abstract aperture/gate logo that is not a shield, lock, bug, skull or checkmark.
8. Native tests, build, packaging, optional signing, CI, deployment, installed smoke verification and public release.
9. Removal of Python sources, dependencies, tests, PyInstaller and Python build workflow after parity is proven.

## Non-negotiable safety constraints

- Keep Microsoft Defender enabled and disclose coexistence limits.
- Never decrypt TLS, capture credentials, upload files/telemetry, or claim network metadata proves cookie theft.
- Never auto-delete or auto-kill based solely on a heuristic score.
- Never ship a test-signed/unsigned kernel driver or ask users to weaken Secure Boot.
- Restrict privileged operations by pipe ACL, caller identity, typed authorization and audit event.
- Bound every parser, queue, frame, recursive walk and untrusted-file operation.

## Definition of done

The authoritative technical design, security boundaries, performance budgets and release audit are in `docs/NATIVE_ARCHITECTURE.md`. Task 21 and its subtasks track implementation. The goal is not complete until the release-acceptance checklist in that document is supported by current build, test, visual, installed-runtime and repository evidence.
