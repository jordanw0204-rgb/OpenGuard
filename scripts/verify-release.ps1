[CmdletBinding()]
param(
    [string]$DistDirectory,
    [string]$ReleaseDirectory,
    [switch]$RequireSigned
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$dist = if ($DistDirectory) { (Resolve-Path -LiteralPath $DistDirectory).Path } else { (Resolve-Path -LiteralPath (Join-Path $projectRoot 'dist\OpenGuard')).Path }
$release = if ($ReleaseDirectory) { (Resolve-Path -LiteralPath $ReleaseDirectory).Path } else { (Resolve-Path -LiteralPath (Join-Path $projectRoot 'release')).Path }
$required = 'OpenGuard.exe','OpenGuardCLI.exe','OpenGuardService.exe','OpenGuardScanner.exe','OpenGuardETW.exe'
foreach ($name in $required) {
    $path = Join-Path $dist $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing release executable: $name" }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($RequireSigned -and $signature.Status -ne 'Valid') {
        throw "$name is not signed by a currently trusted Authenticode certificate: $($signature.Status)"
    }
}

$python = Get-ChildItem -LiteralPath $dist -Recurse -File | Where-Object {
    $_.Extension -in @('.py', '.pyw', '.pyc', '.pyd') -or $_.Name -match 'python|pyinstaller'
}
if ($python) { throw "Python artifacts found: $($python.FullName -join ', ')" }

$artifacts = Get-ChildItem -LiteralPath $release -File | Where-Object { $_.Extension -in @('.zip', '.msi') }
if ($artifacts.Count -lt 2) { throw 'Expected both ZIP and MSI release artifacts.' }
foreach ($artifact in $artifacts) {
    $checksumPath = "$($artifact.FullName).sha256"
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) { throw "Missing checksum for $($artifact.Name)" }
    $actual = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $recorded = (Get-Content -LiteralPath $checksumPath -Raw).Split(' ', [StringSplitOptions]::RemoveEmptyEntries)[0].ToLowerInvariant()
    if ($actual -ne $recorded) { throw "Checksum mismatch for $($artifact.Name)" }
    if ($artifact.Extension -eq '.msi') {
        $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
        if ($RequireSigned -and $signature.Status -ne 'Valid') {
            throw "$($artifact.Name) is not signed by a currently trusted Authenticode certificate: $($signature.Status)"
        }
    }
}
Write-Host "Verified $($required.Count) native executables and $($artifacts.Count) release artifacts. RequireSigned=$RequireSigned"
