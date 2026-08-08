#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Source = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist\OpenGuard'),
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\OpenGuard')
)

$ErrorActionPreference = 'Stop'
$sourcePath = [System.IO.Path]::GetFullPath($Source)
$installPath = [System.IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$programsRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs')).TrimEnd('\')

if (-not $installPath.StartsWith($programsRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "InstallRoot must be a child of $programsRoot"
}
foreach ($name in @('OpenGuard.exe', 'OpenGuardService.exe', 'OpenGuardCLI.exe', 'OpenGuardETW.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $sourcePath $name))) {
        throw "The native package is missing $name under $sourcePath"
    }
}

$service = Get-Service -Name 'OpenGuardNative' -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') {
    Stop-Service -Name 'OpenGuardNative' -Force
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -in @('OpenGuard.exe', 'OpenGuardService.exe', 'OpenGuardETW.exe') -and
        $_.ExecutablePath -and
        $_.ExecutablePath.StartsWith($installPath + '\', [System.StringComparison]::OrdinalIgnoreCase)
    } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 1

if ([System.IO.Directory]::Exists($installPath)) {
    [System.IO.Directory]::Delete($installPath, $true)
}
[System.IO.Directory]::CreateDirectory($installPath) | Out-Null
Copy-Item -Path (Join-Path $sourcePath '*') -Destination $installPath -Recurse -Force

if ($service) {
    Start-Service -Name 'OpenGuardNative'
    (Get-Service -Name 'OpenGuardNative').WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
} else {
    & (Join-Path $installPath 'OpenGuardCLI.exe') service install --pretty
    if ($LASTEXITCODE -ne 0) {
        throw "OpenGuardNative installation failed with exit code $LASTEXITCODE"
    }
}

Write-Host "OpenGuard deployed to $installPath"
& (Join-Path $installPath 'OpenGuardCLI.exe') service status --pretty
