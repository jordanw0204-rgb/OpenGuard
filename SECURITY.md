# Security policy

OpenGuard is security software and should be treated as alpha software. Keep Microsoft Defender or another mature endpoint product enabled.

## Reporting a vulnerability

Do not open a public issue containing exploit details, malware samples, credentials, personal data, or live command-and-control infrastructure. Contact the project maintainers privately through the repository's security-advisory channel. Include the affected version, reproduction steps using inert test data where possible, impact, and suggested mitigation.

## Safe testing

- Use isolated Windows Sandbox or disposable virtual machines for malware research.
- Use the EICAR test file for antivirus workflow checks; do not commit live malware.
- Never disable Secure Boot, driver-signing enforcement, Defender, or other endpoint protection merely to run OpenGuard.
- Never run production packet/file-system drivers under test-signing mode.
- Treat quarantine as containment, not proof that a system is clean.

## Security-content signing

Update manifests use a pinned Ed25519 public key. Release maintainers keep the matching private key outside the repository and provide it to the native manifest-signing utility through `OPENGUARD_UPDATE_PRIVATE_KEY`. A content version is activated only after the signature, declared sizes, SHA-256 hashes, YARA compilation, and reputation schema all validate. Report a suspected signing-key compromise immediately.

## Current security boundaries

Version 0.7 uses a LocalSystem service for supported ETW, Windows Event Log, optional existing-Sysmon, WFP, and TCP statistics access, but it cannot inspect protected process memory, decrypt TLS, or resist a local administrator/kernel attacker. These event sources improve timing and context; they are not packet capture. Behavior chains require multiple observations and remain explainable heuristics, not proof of compromise. Findings are evidence for investigation, not a guarantee of safety. OpenGuard never installs or reconfigures Sysmon automatically and ordinary builds contain no kernel driver.
