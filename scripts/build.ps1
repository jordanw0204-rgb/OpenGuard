[CmdletBinding()]
param(
    [switch]$SkipTests,
    [ValidateSet('x64')][string]$Architecture = 'x64'
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$buildRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'build\native-release'))
$distRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'dist'))
$releaseRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'release'))
$appDirectory = Join-Path $distRoot 'OpenGuard'
$docsDirectory = Join-Path $appDirectory 'docs'
$scriptsDirectory = Join-Path $appDirectory 'scripts'
$expectedPrefix = $projectRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar

foreach ($target in @($buildRoot, $distRoot, $releaseRoot)) {
    if (-not $target.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean a path outside the project: $target"
    }
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

New-Item -ItemType Directory -Path $buildRoot, $appDirectory, $docsDirectory, $scriptsDirectory, $releaseRoot -Force | Out-Null
Set-Location -LiteralPath $projectRoot

$localDotnet = Join-Path $projectRoot '.tools\dotnet\dotnet.exe'
$dotnet = if (Test-Path -LiteralPath $localDotnet) { $localDotnet } else { 'dotnet' }
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
if (Test-Path -LiteralPath $localDotnet) {
    $env:DOTNET_ROOT = Split-Path -Parent $localDotnet
    $env:DOTNET_CLI_HOME = Join-Path $projectRoot '.tools\dotnet-home'
    $env:NUGET_PACKAGES = Join-Path $projectRoot '.tools\nuget'
}

if (-not $SkipTests) {
    cargo fmt --all --check
    if ($LASTEXITCODE -ne 0) { throw 'cargo fmt failed.' }
    cargo clippy --workspace --all-targets --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'cargo clippy failed.' }
    cargo test --workspace --all-targets --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust tests failed.' }
}

& (Join-Path $projectRoot 'native\etw-helper\build.ps1') -Output (Join-Path $buildRoot 'etw')
if ($LASTEXITCODE -ne 0) { throw "Native ETW helper build failed with exit code $LASTEXITCODE" }

cargo build --workspace --release --locked
if ($LASTEXITCODE -ne 0) { throw "Native release build failed with exit code $LASTEXITCODE" }

& $dotnet publish (Join-Path $projectRoot 'apps\OpenGuard.App\OpenGuard.App.csproj') `
    -c Release `
    -r win-x64 `
    -p:Platform=$Architecture `
    --self-contained true `
    --output $appDirectory
if ($LASTEXITCODE -ne 0) { throw "WinUI publish failed with exit code $LASTEXITCODE" }

$nativeExecutables = @(
    (Join-Path $projectRoot 'target\release\OpenGuardCLI.exe'),
    (Join-Path $projectRoot 'target\release\OpenGuardService.exe'),
    (Join-Path $projectRoot 'target\release\OpenGuardScanner.exe'),
    (Join-Path $buildRoot 'etw\OpenGuardETW.exe')
)
foreach ($executable in $nativeExecutables) {
    if (-not (Test-Path -LiteralPath $executable)) {
        throw "Expected native executable is missing: $executable"
    }
    Copy-Item -LiteralPath $executable -Destination $appDirectory
}

foreach ($document in @('README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $document) -Destination $appDirectory
}
foreach ($document in @('ARCHITECTURE.md', 'NATIVE_ARCHITECTURE.md', 'PRODUCT_PLAN.md')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot "docs\$document") -Destination $docsDirectory
}
foreach ($script in @('deploy-local.ps1', 'verify-release.ps1')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot "scripts\$script") -Destination $scriptsDirectory
}

$executables = Get-ChildItem -LiteralPath $appDirectory -Filter '*.exe' -File |
    Select-Object -ExpandProperty FullName
$signingConfigured = $env:OPENGUARD_SIGN_PFX -and (Test-Path -LiteralPath $env:OPENGUARD_SIGN_PFX)
if ($signingConfigured) {
    & (Join-Path $projectRoot 'scripts\sign.ps1') `
        -CertificatePath $env:OPENGUARD_SIGN_PFX `
        -CertificatePassword $env:OPENGUARD_SIGN_PASSWORD `
        -Files $executables
} else {
    Write-Warning 'No Authenticode certificate configured; producing an unsigned development build.'
}
$signingStatus = if ($signingConfigured) {
    'Authenticode status: signed and verified with the configured certificate and RFC 3161 timestamp.'
} else {
    'Authenticode status: UNSIGNED DEVELOPMENT BUILD. A CA-issued Windows code-signing certificate was not configured.'
}
Set-Content -LiteralPath (Join-Path $appDirectory 'SIGNING_STATUS.txt') -Value $signingStatus -Encoding utf8 -NoNewline

$pythonArtifacts = Get-ChildItem -LiteralPath $appDirectory -Recurse -File |
    Where-Object {
        $_.Extension -in @('.py', '.pyw', '.pyc', '.pyd') -or
        $_.Name -match 'python|pyinstaller'
    }
if ($pythonArtifacts) {
    throw "Python artifacts were found in the native release: $($pythonArtifacts.FullName -join ', ')"
}

$metadata = cargo metadata --no-deps --format-version 1 --locked | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Unable to read Cargo workspace metadata.' }
$version = ($metadata.packages | Where-Object name -eq 'openguard-service' | Select-Object -First 1).version
if (-not $version) { throw 'Unable to determine the OpenGuard version.' }

$archive = Join-Path $releaseRoot "OpenGuard-$version-win-x64.zip"
Compress-Archive -Path (Join-Path $appDirectory '*') -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumPath = "$archive.sha256"
Set-Content -LiteralPath $checksumPath -Value "$hash  $([System.IO.Path]::GetFileName($archive))" -Encoding ascii -NoNewline

& (Join-Path $projectRoot 'scripts\build-installer.ps1') `
    -Version $version `
    -PayloadDirectory $appDirectory `
    -OutputDirectory $releaseRoot
if ($LASTEXITCODE -ne 0) { throw "Installer build failed with exit code $LASTEXITCODE" }

& (Join-Path $projectRoot 'scripts\verify-release.ps1') `
    -DistDirectory $appDirectory `
    -ReleaseDirectory $releaseRoot `
    -RequireSigned:$signingConfigured

Write-Host "Release archive: $archive"
Write-Host "SHA-256: $hash"
