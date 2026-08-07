[CmdletBinding()]
param(
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$buildRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'build\pyinstaller'))
$distRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'dist'))
$releaseRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'release'))
$expectedPrefix = $projectRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar

foreach ($target in @($buildRoot, $distRoot, $releaseRoot)) {
    if (-not $target.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean a path outside the project: $target"
    }
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

New-Item -ItemType Directory -Path $buildRoot, $distRoot, $releaseRoot -Force | Out-Null
Set-Location -LiteralPath $projectRoot

& (Join-Path $projectRoot 'native\etw-helper\build.ps1') -Output (Join-Path $buildRoot 'native')
if ($LASTEXITCODE -ne 0) {
    throw "Native ETW helper build failed with exit code $LASTEXITCODE"
}

if (-not $SkipTests) {
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) {
        throw "Tests failed with exit code $LASTEXITCODE"
    }
}

python -c "import PyInstaller; print('Building with PyInstaller', PyInstaller.__version__)"
if ($LASTEXITCODE -ne 0) {
    throw 'PyInstaller is required. Install the pinned build dependency from requirements-build.txt.'
}

$common = @(
    '--noconfirm',
    '--clean',
    '--paths', (Join-Path $projectRoot 'src'),
    '--add-data', "$(Join-Path $projectRoot 'src\openguard\data\known_hashes.json'):openguard\data",
    '--add-data', "$(Join-Path $projectRoot 'src\openguard\data\builtin.yar'):openguard\data",
    '--add-data', "$(Join-Path $projectRoot 'src\openguard\data\reputation.json'):openguard\data",
    '--add-data', "$(Join-Path $projectRoot 'src\openguard\data\update_public_key.txt'):openguard\data",
    '--collect-all', 'yara_x',
    '--collect-all', 'cryptography',
    '--workpath', $buildRoot,
    '--specpath', $buildRoot,
    '--version-file', (Join-Path $projectRoot 'packaging\version_info.txt')
)

$guiArgs = $common + @(
    '--onedir',
    '--windowed',
    '--name', 'OpenGuard',
    '--distpath', $distRoot,
    (Join-Path $projectRoot 'OpenGuard.pyw')
)
python -m PyInstaller @guiArgs
if ($LASTEXITCODE -ne 0) {
    throw "GUI packaging failed with exit code $LASTEXITCODE"
}

$cliDist = Join-Path $distRoot 'cli'
$cliArgs = $common + @(
    '--onefile',
    '--console',
    '--name', 'OpenGuardCLI',
    '--distpath', $cliDist,
    (Join-Path $projectRoot 'openguard_cli.py')
)
python -m PyInstaller @cliArgs
if ($LASTEXITCODE -ne 0) {
    throw "CLI packaging failed with exit code $LASTEXITCODE"
}

$serviceDist = Join-Path $distRoot 'service'
$serviceArgs = $common + @(
    '--onefile',
    '--windowed',
    '--name', 'OpenGuardService',
    '--distpath', $serviceDist,
    (Join-Path $projectRoot 'openguard_service.py')
)
python -m PyInstaller @serviceArgs
if ($LASTEXITCODE -ne 0) {
    throw "Service packaging failed with exit code $LASTEXITCODE"
}

$appDirectory = Join-Path $distRoot 'OpenGuard'
Copy-Item -LiteralPath (Join-Path $cliDist 'OpenGuardCLI.exe') -Destination $appDirectory
Copy-Item -LiteralPath (Join-Path $serviceDist 'OpenGuardService.exe') -Destination $appDirectory
Copy-Item -LiteralPath (Join-Path $buildRoot 'native\OpenGuardETW.exe') -Destination $appDirectory
Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') -Destination $appDirectory
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination $appDirectory
Copy-Item -LiteralPath (Join-Path $projectRoot 'SECURITY.md') -Destination $appDirectory
Copy-Item -LiteralPath (Join-Path $projectRoot 'CHANGELOG.md') -Destination $appDirectory

$executables = @(
    (Join-Path $appDirectory 'OpenGuard.exe'),
    (Join-Path $appDirectory 'OpenGuardCLI.exe'),
    (Join-Path $appDirectory 'OpenGuardService.exe'),
    (Join-Path $appDirectory 'OpenGuardETW.exe')
)
if ($env:OPENGUARD_SIGN_PFX -and (Test-Path -LiteralPath $env:OPENGUARD_SIGN_PFX)) {
    & (Join-Path $projectRoot 'scripts\sign.ps1') `
        -CertificatePath $env:OPENGUARD_SIGN_PFX `
        -CertificatePassword $env:OPENGUARD_SIGN_PASSWORD `
        -Files $executables
} else {
    Write-Warning 'No Authenticode certificate configured; producing an unsigned development build.'
}

$version = python -c "import sys; sys.path.insert(0, 'src'); from openguard.config import VERSION; print(VERSION)"
if ($LASTEXITCODE -ne 0 -or -not $version) {
    throw 'Unable to determine OpenGuard version.'
}
$archive = Join-Path $releaseRoot "OpenGuard-$version-win-x64.zip"
Compress-Archive -Path (Join-Path $appDirectory '*') -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
$checksum = "$hash  $([System.IO.Path]::GetFileName($archive))"
$checksumPath = "$archive.sha256"
Set-Content -LiteralPath $checksumPath -Value $checksum -Encoding ascii -NoNewline

Write-Host "Release archive: $archive"
Write-Host "SHA-256: $hash"
