# OpenGuard AMSI provider

This bounded in-process provider detects the standardized EICAR marker and assigns non-blocking AMSI risk levels to correlated script injection, browser-credential, and LSASS-dump patterns. It reads at most 16 MiB, performs no network or IPC work, and does not replace the richer service correlation engine.

Build with `pwsh -File build.ps1`. Registration is deliberately separate: `register.ps1` requires elevation, an exact Program Files install path, and a currently trusted Authenticode signature. The ordinary development/release build does not package or register this DLL. Microsoft requires antimalware providers to be Authenticode-signed on current Windows versions; an unsigned provider is never a supported deployment.
