#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ProviderPath,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'
$provider = [IO.Path]::GetFullPath($ProviderPath)
$installRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'OpenGuard')).TrimEnd('\')
if (-not $provider.StartsWith($installRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "The provider must be installed beneath $installRoot"
}
$clsid = '{5F39A65E-3D26-4D78-923D-3848695AD061}'
$comKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$clsid"
$amsiKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AMSI\Providers\$clsid"

if ($Unregister) {
    if ($PSCmdlet.ShouldProcess($clsid, 'Unregister OpenGuard AMSI provider')) {
        Remove-Item -LiteralPath $amsiKey -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $comKey -Recurse -Force -ErrorAction SilentlyContinue
    }
    return
}
if (-not (Test-Path -LiteralPath $provider -PathType Leaf)) { throw "Provider not found: $provider" }
$signature = Get-AuthenticodeSignature -LiteralPath $provider
if ($signature.Status -ne 'Valid') {
    throw "Refusing to register an unsigned or untrusted AMSI provider: $($signature.Status)"
}
if ($PSCmdlet.ShouldProcess($provider, 'Register signed OpenGuard AMSI provider')) {
    New-Item -Path (Join-Path $comKey 'InprocServer32') -Force | Out-Null
    Set-Item -LiteralPath (Join-Path $comKey 'InprocServer32') -Value $provider
    New-ItemProperty -LiteralPath (Join-Path $comKey 'InprocServer32') -Name 'ThreadingModel' -Value 'Both' -PropertyType String -Force | Out-Null
    New-Item -Path $amsiKey -Force | Out-Null
}
