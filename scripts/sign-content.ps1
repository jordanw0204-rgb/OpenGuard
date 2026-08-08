[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$BaseUrl,
    [string]$ContentRoot = 'security-content',
    [string]$Output = 'security-content\manifest.json',
    [string]$PublishedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
)

$ErrorActionPreference = 'Stop'
if (-not $env:OPENGUARD_UPDATE_PRIVATE_KEY) {
    throw 'OPENGUARD_UPDATE_PRIVATE_KEY is required and must contain a base64-encoded 32-byte Ed25519 private key.'
}
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $projectRoot
cargo run --locked -p openguard-updates --example sign_manifest -- `
    --version $Version `
    --base-url $BaseUrl `
    --published-at $PublishedAt `
    --content-root $ContentRoot `
    --output $Output
if ($LASTEXITCODE -ne 0) {
    throw "Native content-manifest signing failed with exit code $LASTEXITCODE"
}
