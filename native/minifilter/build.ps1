[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if ($env:OPENGUARD_ENABLE_MINIFILTER_BUILD -ne 'SIGNED_REVIEWED_DRIVER') {
    throw 'Minifilter build is disabled. Set OPENGUARD_ENABLE_MINIFILTER_BUILD=SIGNED_REVIEWED_DRIVER only in the audited driver pipeline.'
}
if (-not $env:OPENGUARD_MINIFILTER_ALTITUDE -or $env:OPENGUARD_MINIFILTER_ALTITUDE -notmatch '^\d{6}(\.\d+)?$') {
    throw 'A Microsoft-assigned minifilter altitude is required.'
}
if (-not $env:OPENGUARD_DRIVER_SIGN_PFX -or -not (Test-Path -LiteralPath $env:OPENGUARD_DRIVER_SIGN_PFX)) {
    throw 'A protected driver-signing certificate input is required.'
}
throw 'The protocol boundary is ready, but the kernel implementation is intentionally not present until altitude assignment, independent review, HLK/Verifier plans, and Microsoft signing are complete.'
