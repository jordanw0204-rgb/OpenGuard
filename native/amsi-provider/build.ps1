[CmdletBinding()]
param([string]$Output = "")

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Output) { $Output = Join-Path $projectRoot 'build\amsi-provider' }
$Output = [IO.Path]::GetFullPath($Output)
$prefix = $projectRoot.TrimEnd('\') + '\'
if (-not $Output.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "AMSI provider output must stay inside the project: $Output"
}
New-Item -ItemType Directory -Path $Output -Force | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio Installer was not found.' }
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'Visual C++ x64 build tools are required.' }
$vcvars = Get-Item -LiteralPath (Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat') -ErrorAction Stop
$source = Join-Path $PSScriptRoot 'openguard_amsi.cpp'
$target = Join-Path $Output 'OpenGuardAmsiProvider.dll'
$object = Join-Path $Output 'openguard_amsi.obj'
$command = '"{0}" >nul && cl.exe /nologo /std:c++20 /EHsc /O2 /W4 /WX /DUNICODE /D_UNICODE /Fo"{3}" "{1}" /link /dll /out:"{2}" /export:DllGetClassObject,PRIVATE /export:DllCanUnloadNow,PRIVATE ole32.lib && dumpbin.exe /exports "{2}" | findstr.exe /c:"DllGetClassObject" >nul && dumpbin.exe /exports "{2}" | findstr.exe /c:"DllCanUnloadNow" >nul' -f $vcvars.FullName, $source, $target, $object
cmd.exe /d /s /c $command
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target)) {
    throw "AMSI provider build failed with exit code $LASTEXITCODE"
}
Write-Host $target
