# Contributing

Contributions are welcome. Keep detection logic explainable, local-first, conservative, and covered by inert tests.

1. Create a focused branch and add tests for behavior changes.
2. Run `cargo fmt --all --check`.
3. Run `cargo clippy --workspace --all-targets --locked -- -D warnings`.
4. Run `cargo test --workspace --all-targets --locked` and build the WinUI project.
5. Run `OpenGuardCLI.exe doctor --pretty` and relevant live Windows smoke tests.
6. Do not add telemetry, file uploads, automatic deletion, unsigned drivers, or Defender configuration changes without an approved design and threat-model update.
7. Do not commit malware samples, private feeds, API keys, signing material, or user databases.

Detection rules must document their signal, expected false positives, severity rationale, and inert test cases. Native FFI must remain isolated, document ownership and thread-safety invariants, and expose safe Rust interfaces.
