[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [string]$PayloadDirectory,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$payload = if ($PayloadDirectory) {
    (Resolve-Path -LiteralPath $PayloadDirectory).Path
} else {
    (Resolve-Path -LiteralPath (Join-Path $projectRoot 'dist\OpenGuard')).Path
}
$output = if ($OutputDirectory) {
    [IO.Path]::GetFullPath($OutputDirectory)
} else {
    Join-Path $projectRoot 'release'
}
$expectedPayloadPrefix = (Join-Path $projectRoot 'dist').TrimEnd('\') + '\'
$expectedOutputPrefix = $projectRoot.TrimEnd('\') + '\'
if (-not $payload.StartsWith($expectedPayloadPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Installer payload must be inside the project dist directory: $payload"
}
if (-not $output.StartsWith($expectedOutputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Installer output must stay inside the project: $output"
}

$localDotnet = Join-Path $projectRoot '.tools\dotnet\dotnet.exe'
$dotnet = if (Test-Path -LiteralPath $localDotnet) { $localDotnet } else { 'dotnet' }
if (Test-Path -LiteralPath $localDotnet) {
    $env:DOTNET_ROOT = Split-Path -Parent $localDotnet
    $env:DOTNET_CLI_HOME = Join-Path $projectRoot '.tools\dotnet-home'
    $env:NUGET_PACKAGES = Join-Path $projectRoot '.tools\nuget'
}
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
Set-Location -LiteralPath $projectRoot
& $dotnet tool restore
if ($LASTEXITCODE -ne 0) { throw 'WiX tool restore failed.' }

New-Item -ItemType Directory -Path $output -Force | Out-Null
$installer = Join-Path $output "OpenGuard-$Version-win-x64.msi"
if (Test-Path -LiteralPath $installer) {
    Remove-Item -LiteralPath $installer -Force
}
& $dotnet tool run wix -- build `
    (Join-Path $projectRoot 'installer\Product.wxs') `
    -arch x64 `
    -d "Version=$Version" `
    -d "PayloadDirectory=$payload" `
    -pdbtype none `
    -intermediateFolder (Join-Path $projectRoot 'build\wix') `
    -out $installer
if ($LASTEXITCODE -ne 0) { throw "WiX installer build failed with exit code $LASTEXITCODE" }

if ($env:OPENGUARD_SIGN_PFX -and (Test-Path -LiteralPath $env:OPENGUARD_SIGN_PFX)) {
    & (Join-Path $projectRoot 'scripts\sign.ps1') `
        -CertificatePath $env:OPENGUARD_SIGN_PFX `
        -CertificatePassword $env:OPENGUARD_SIGN_PASSWORD `
        -Files $installer
}

$hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
$checksum = "$installer.sha256"
Set-Content -LiteralPath $checksum -Value "$hash  $([IO.Path]::GetFileName($installer))" -Encoding ascii -NoNewline
Write-Host "Installer: $installer"
Write-Host "Installer SHA-256: $hash"
