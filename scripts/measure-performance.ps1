[CmdletBinding()]
param(
    [string]$CliPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist\OpenGuard\OpenGuardCLI.exe'),
    [ValidateRange(10, 200)][int]$Samples = 30,
    [switch]$Enforce
)

$ErrorActionPreference = 'Stop'
$cli = (Resolve-Path -LiteralPath $CliPath).Path
$service = Get-CimInstance Win32_Service -Filter "Name='OpenGuardNative'"
if (-not $service -or $service.State -ne 'Running' -or -not $service.ProcessId) {
    throw 'OpenGuardNative must be running for the performance audit.'
}
$process = Get-Process -Id $service.ProcessId -ErrorAction Stop
$cpuStart = $process.TotalProcessorTime.TotalSeconds
$wall = [Diagnostics.Stopwatch]::StartNew()
$latencies = [Collections.Generic.List[double]]::new()
for ($index = 0; $index -lt $Samples; $index++) {
    $sample = [Diagnostics.Stopwatch]::StartNew()
    & $cli snapshot | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Snapshot sample $index failed." }
    $sample.Stop()
    $latencies.Add($sample.Elapsed.TotalMilliseconds)
}
$wall.Stop()
$process.Refresh()
$cpuSeconds = [Math]::Max(0, $process.TotalProcessorTime.TotalSeconds - $cpuStart)
$logicalProcessors = [Math]::Max(1, [Environment]::ProcessorCount)
$cpuPercent = 100 * $cpuSeconds / [Math]::Max(0.001, $wall.Elapsed.TotalSeconds * $logicalProcessors)
$ordered = $latencies | Sort-Object
$p95Index = [Math]::Min($ordered.Count - 1, [Math]::Ceiling($ordered.Count * 0.95) - 1)
$result = [ordered]@{
    samples = $Samples
    snapshot_process_p95_ms = [Math]::Round($ordered[$p95Index], 2)
    snapshot_process_average_ms = [Math]::Round(($latencies | Measure-Object -Average).Average, 2)
    service_cpu_percent_during_samples = [Math]::Round($cpuPercent, 2)
    service_working_set_mib = [Math]::Round($process.WorkingSet64 / 1MB, 2)
}
$result | ConvertTo-Json
if ($Enforce) {
    if ($result.snapshot_process_p95_ms -gt 250) { throw 'Snapshot process p95 exceeded 250 ms.' }
    if ($result.service_working_set_mib -gt 150) { throw 'Service working set exceeded 150 MiB.' }
}
