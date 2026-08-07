[CmdletBinding()]
param([string]$Output = "")

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Output) {
    $Output = Join-Path $projectRoot 'build\native'
}
$Output = [System.IO.Path]::GetFullPath($Output)
$prefix = $projectRoot.TrimEnd('\') + '\'
if (-not $Output.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Native helper output must stay inside the project: $Output"
}
New-Item -ItemType Directory -Path $Output -Force | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer vswhere.exe was not found.'
}
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) {
    throw 'Visual C++ x64 build tools are required for the ETW helper.'
}
$vcvars = Get-Item -LiteralPath (Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat') -ErrorAction Stop
$source = Join-Path $PSScriptRoot 'openguard_etw.cpp'
$target = Join-Path $Output 'OpenGuardETW.exe'
$object = Join-Path $Output 'openguard_etw.obj'
$command = '"{0}" >nul && cl.exe /nologo /std:c++20 /EHsc /O2 /W4 /DUNICODE /D_UNICODE /Fo"{3}" "{1}" /link /out:"{2}"' -f $vcvars.FullName, $source, $target, $object
cmd.exe /d /s /c $command
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target)) {
    throw "ETW helper build failed with exit code $LASTEXITCODE"
}
Write-Host $target
