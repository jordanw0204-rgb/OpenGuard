# Changelog

## 0.5.0 — 2026-08-08

- Added bounded real-time monitoring of Downloads, Desktop, Startup, and Temp through the Windows `ReadDirectoryChangesW` backend, NTFS USN journal identity/cursor checks, overflow reconciliation, and concurrency-limited scans of changed executable/script files.
- Added an owner-scoped, filtered, cursor-paginated investigation timeline for detailed ETW process starts/stops and command lines, polling fallback events, file changes, DNS-enriched network flows, persistence changes, detections, and response audits.
- Expanded persistence inventory to active services, drivers, scheduled tasks, permanent WMI command/script consumers, Run/RunOnce entries, and Chrome, Edge, and Firefox extensions with honest per-source coverage.
- Added explicit confirmation flows for PID/path-revalidated terminate, suspend, and resume; detection-gated quarantine; temporary program-scoped outbound firewall blocks; and reversible disable/restore of review-worthy services and scheduled tasks.
- Added schema v5 migrations, owner-scoped rollback records, bounded response fields/queues, safe limited-coverage states, and focused tests for monitoring, timeline pagination, persistence baselines, response authorization, and rollback isolation.

## 0.4.0 — 2026-08-08

- Added an in-app process investigation view with SHA-256, signer and identity details, parent/child relationships, owned connections, persistence matches, and explainable evidence.
- Added contextual behavior correlation for newly observed or unsigned processes, public and reputation-matched destinations, and suspicious Office/browser child-process chains.
- Added a per-machine MSI that installs the WinUI console and automatic LocalSystem telemetry service, plus administrative extraction and checksum validation.
- Hardened Authenticode automation with SHA-256 file digests, RFC 3161 timestamps, post-sign verification, and explicit unsigned-development labeling when no trusted certificate is configured.
- Expanded safe adversarial and false-positive tests for behavior correlations while retaining stable process and network row ordering.

## 0.3.2 — 2026-08-07

- Stopped live CPU, memory, and transfer updates from continuously re-ranking process and network rows.
- Preserved row order and selection between snapshots while keeping header clicks and filters immediately sortable.
- Coalesced each activity graph's repeated collection notifications into one low-priority UI render per update cycle.

## 0.3.1 — 2026-08-07

- Stabilized process and network tables with keyed in-place row updates that preserve selection and virtualization state.
- Added click-to-sort headers with explicit direction indicators and CPU/download defaults.
- Added rolling CPU/memory and download/upload activity graphs with bounded three-minute histories.
- Added safe right-click actions for file location, OpenGuard scanning, web lookup, and copying process/connection details.

## 0.3.0 — 2026-08-07

- Replaced the prototype runtime with a Rust service, scanner, CLI, SQLite layer, signed updater, and Windows API collector.
- Rebuilt the desktop client in self-contained WinUI 3 with a responsive graphite design system and a new non-shield OpenGuard mark.
- Added authenticated per-user IPC, scan jobs, profiles, cancellation, quarantine, exclusions, allow-list controls, and security-content rollback.
- Added real IPv4/IPv6 owner mapping, TCP byte/rate counters, signed IP/CIDR reputation, background PTR enrichment, read-only WFP coverage, and ETW helper integration.
- Added fully native build, CI, release, signing, and zero-Python artifact checks.

## 0.2.2 — 2026-08-06

- Moved Security-page content, service, and database refreshes off the Tk event thread.
- Coalesced repeated Security refresh requests to prevent duplicate background work.
- Added supported Windows TCP Extended Statistics collection through the elevated monitor service.
- Added per-connection upload/download rates, observed byte totals, and combined hostname/IP destinations.
- Added connection detail explanations and explicit HTTPS/UDP visibility limitations.

## 0.2.1 — 2026-08-06

- Reworked the desktop interface around a near-black graphite design system.
- Added dark Windows title-bar chrome and cohesive Treeview, Notebook, Combobox, and progress styles.
- Replaced native ttk scrollbars with compact dark tracks and hover/pressed states.
- Rebuilt the sidebar with larger Segoe Fluent icon tiles, selection rails, and hover feedback.
- Added a generated OpenGuard shield logo and multi-resolution Windows executable icon.

## 0.2.0 — 2026-08-06

- Integrated YARA-X 1.19.0 and exact-pinned cryptography 50.0.0.
- Added authenticated, atomic security-content updates and rollback.
- Added quarantine restore, exact-hash allow-listing, path exclusions, and four scan profiles.
- Added asynchronous DNS context and a signed local reputation feed.
- Added a native ETW process-event helper, polling fallback, and read-only WFP subscription.
- Added the automatic OpenGuard Monitor Windows service.
- Expanded the GUI/CLI and packaged four Windows executables.
- Added conditional SHA-256/RFC 3161 Authenticode signing and GitHub release workflows.
