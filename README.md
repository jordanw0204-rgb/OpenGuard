# OpenGuard

OpenGuard is an open-source Windows activity monitor and local security scanner. It combines a readable process inventory, app-owned TCP/UDP endpoint visibility, unseen executable alerts, Authenticode checks, YARA-X rules, optional Windows AMSI scanning, signed security-content updates, and recoverable quarantine.

> [!IMPORTANT]
> OpenGuard 0.2 is an alpha security companion, not a replacement for Microsoft Defender or another mature endpoint antivirus. It does not intercept packet contents, decrypt TLS, install a kernel driver, or register itself with Windows Security.

## What works in 0.2

- Live Windows process inventory with CPU, memory, executable path, signature status, risk score, and evidence
- First-run baseline followed by alerts for unseen or changed executables
- IPv4/IPv6 TCP and UDP endpoints mapped to owner PIDs/apps, asynchronous PTR names, and signed local IP/CIDR reputation
- YARA-X 1.19.0, SHA-256, script/filename/path/PE heuristics, known hashes, and optional installed-provider AMSI checks
- Quick, Full, Startup, and Downloads scan profiles
- Ed25519-signed rule/reputation updates with SHA-256/size checks, validation, atomic activation, and rollback
- Local SQLite scan and alert history under `%LOCALAPPDATA%\OpenGuard`
- Quarantine browsing/restoration, exact-hash allow-listing, and visible path exclusions
- Automatic background Windows service with native ETW process events, polling reconciliation, and a read-only WFP net-event subscription
- Desktop dashboard plus JSON CLI modes for diagnosis and automation

## Run from source

Install the exact-pinned open-source dependencies with Python 3.12 or newer on Windows:

```powershell
python -m pip install -r requirements-runtime.txt
```

```powershell
python OpenGuard.pyw
```

Diagnostic commands:

```powershell
python openguard_cli.py snapshot --pretty
python openguard_cli.py scan "C:\path\to\file-or-folder" --pretty
python openguard_cli.py scan-profile quick --pretty
python openguard_cli.py quarantine list --pretty
python openguard_cli.py update install --pretty
python openguard_cli.py service status --pretty
python openguard_cli.py doctor --pretty
```

Run tests:

```powershell
python -m unittest discover -s tests -v
```

Build a portable Windows release with the included PowerShell script:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

The build creates `release\OpenGuard-<version>-win-x64.zip` and a matching `.sha256` file. Set `OPENGUARD_SIGN_PFX` and `OPENGUARD_SIGN_PASSWORD` to Authenticode-sign and verify every executable with SHA-256 and an RFC 3161 timestamp. Without a CA-issued certificate the script labels the artifact as an unsigned development build.

Install the packaged background monitor from an Administrator terminal:

```powershell
.\OpenGuardCLI.exe service install --pretty
.\OpenGuardCLI.exe service start --pretty
```

Security content defaults to the repository's `security-content/manifest.json`. Every manifest is verified against the public key embedded in OpenGuard; the private signing key is not stored in this repository.

## Privacy and coexistence

OpenGuard stores its database locally and contains no telemetry or file-upload client. DNS PTR resolution uses the operating system resolver. If AMSI scanning is enabled, the installed antimalware provider handles the request and may apply its configured cloud-protection policy. OpenGuard does not disable Defender, change Defender exclusions, install WFP filters, or register itself as the machine's antivirus.

## Architecture and roadmap

- [Product plan](docs/PRODUCT_PLAN.md)
- [Architecture and threat model](docs/ARCHITECTURE.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

Licensed under the [MIT License](LICENSE).
