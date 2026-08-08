[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CertificatePath,
    [Parameter(Mandatory)][AllowEmptyString()][string]$CertificatePassword,
    [Parameter(Mandatory)][string[]]$Files,
    [string]$TimestampUrl = 'https://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$certificate = (Resolve-Path -LiteralPath $CertificatePath).Path
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$signTool = @(
    Get-ChildItem -LiteralPath 'C:\Program Files (x86)\Windows Kits\10\bin' -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath (Join-Path $projectRoot '.tools\nuget\microsoft.windows.sdk.buildtools') -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue
) |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $signTool) {
    throw 'SignTool x64 was not found in the Windows SDK or restored SDK BuildTools package.'
}
foreach ($file in $Files) {
    $resolved = (Resolve-Path -LiteralPath $file).Path
    & $signTool.FullName sign /fd SHA256 /tr $TimestampUrl /td SHA256 /f $certificate /p $CertificatePassword /d OpenGuard $resolved
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode signing failed for $resolved"
    }
    & $signTool.FullName verify /pa /all $resolved
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode verification failed for $resolved"
    }
}
