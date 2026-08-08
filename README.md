# OpenGuard

OpenGuard is an open-source, local-first Windows security monitor and scanner. The native Rust service owns monitoring, policy, SQLite state, scanning, signed updates, and quarantine; the WinUI 3 desktop app presents that data without blocking its UI thread.

> [!IMPORTANT]
> OpenGuard 0.3 is a security companion, not yet a replacement for Microsoft Defender or another mature endpoint antivirus. It does not decrypt TLS, inspect packet payloads, install a kernel driver, or register with Windows Security. Keep an established antivirus enabled.

## Current capabilities

- Process inventory with sampled CPU, memory, executable identity, Authenticode status, risk score, evidence, and unseen-executable alerts
- Process investigation with SHA-256, signer/identity evidence, parent and child relationships, owned connections, and matching Run/RunOnce or Startup-folder persistence
- Explainable behavior correlation for new or untrusted processes, public or reputation-matched destinations, and suspicious Office/browser child-process chains
- IPv4/IPv6 TCP and UDP ownership, real TCP Extended Statistics byte/rate counters, bounded asynchronous PTR names, and signed local IP/CIDR reputation
- Streaming SHA-256, YARA-X 1.19, PE/script/path heuristics, EICAR detection, and the installed Windows AMSI provider
- File, folder, Quick, Downloads, Startup, and explicitly confirmed Full scan profiles with progress and cancellation
- User-scoped path exclusions and exact SHA-256 allow-list entries that remain visible as skipped scan records
- Recoverable, defanged, integrity-checked quarantine with no automatic deletion
- Strict Ed25519 security-content updates with HTTPS-only retrieval, size/hash validation, YARA compilation, atomic activation, and rollback
- ACL-restricted, remote-rejecting named-pipe IPC with per-request Windows identity impersonation
- Read-only WFP net-event capability reporting and an ETW process-event helper, with explicit limited states when elevation is unavailable
- Dark graphite WinUI 3 dashboard and native JSON CLI; no Python runtime or telemetry/file-upload client

## Build from source

Requirements:

- Windows 10 version 2004 (build 19041) or later
- Rust 1.97 with the MSVC x64 target
- .NET SDK 10.0.302 or a compatible 10.0 patch
- Visual Studio Build Tools with the C++ x64 workload and Windows SDK

Build and test the complete portable release:

```powershell
pwsh -File scripts\build.ps1
```

The script runs Rust format, lint, and workspace tests; builds the C++ ETW helper; publishes the self-contained WinUI app; verifies the package contains no Python artifacts; and creates portable ZIP and per-machine MSI artifacts in `release\`, each with a SHA-256 file. The MSI installs the automatic LocalSystem telemetry service and a Start menu shortcut.

For a quicker development loop:

```powershell
cargo build --workspace
dotnet build apps\OpenGuard.App\OpenGuard.App.csproj -c Debug -p:Platform=x64
cargo run -p openguard-service -- --console
```

Run `apps\OpenGuard.App\bin\x64\Debug\net10.0-windows10.0.26100.0\win-x64\OpenGuard.exe` after the console service is ready.

Install a built MSI from an elevated terminal:

```powershell
msiexec.exe /i .\release\OpenGuard-0.4.0-win-x64.msi /norestart
```

The installer registers and starts `OpenGuardNative` as a LocalSystem automatic service. Windows will show an elevation prompt for this per-machine installation.

## Native CLI

```powershell
.\OpenGuardCLI.exe doctor --pretty
.\OpenGuardCLI.exe snapshot --pretty
.\OpenGuardCLI.exe scan "C:\path\to\file-or-folder" --pretty
.\OpenGuardCLI.exe scan-profile startup --pretty
.\OpenGuardCLI.exe events --limit 100 --pretty
.\OpenGuardCLI.exe quarantine-list --pretty
.\OpenGuardCLI.exe policy exclusions --pretty
.\OpenGuardCLI.exe policy allowed-hashes --pretty
.\OpenGuardCLI.exe update status --pretty
```

Install the packaged background service from an Administrator terminal:

```powershell
.\OpenGuardCLI.exe service install --pretty
.\OpenGuardCLI.exe service status --pretty
```

The service is installed as `OpenGuardNative` and resolves `OpenGuardService.exe` next to the CLI by default. ETW and supported TCP counters become available when the service runs elevated as LocalSystem.

To replace an existing local installation safely, run the repository deployment helper from an Administrator terminal:

```powershell
pwsh -File scripts\deploy-local.ps1
```

It stops only OpenGuard processes from the configured install directory, removes a stale ETW helper if an earlier service was interrupted, copies the native package, and starts `OpenGuardNative` again.

## Signing and updates

Set `OPENGUARD_SIGN_PFX` and `OPENGUARD_SIGN_PASSWORD` before running `scripts\build.ps1` to Authenticode-sign and verify every executable and the MSI with SHA-256 and an RFC 3161 timestamp. Without a CA-issued certificate, the script produces explicitly labeled unsigned development artifacts; tagged automation publishes those artifacts as a prerelease.

Security content defaults to `security-content/manifest.json`. The updater accepts only HTTPS assets covered by the pinned Ed25519 manifest signature and validates every declared size, SHA-256 digest, YARA rule, and reputation schema before activation. The private signing key is never stored in this repository.

## Privacy and limits

OpenGuard stores its state locally. PTR resolution uses the Windows resolver. AMSI requests go to the antimalware provider configured on the PC and may follow that provider's cloud-protection policy. OpenGuard does not disable Defender, change Defender exclusions, install WFP filters, decrypt TLS, or upload files.

See [native architecture](docs/NATIVE_ARCHITECTURE.md), [product plan](docs/PRODUCT_PLAN.md), [security policy](SECURITY.md), and [contributing](CONTRIBUTING.md).

Licensed under the [MIT License](LICENSE).
