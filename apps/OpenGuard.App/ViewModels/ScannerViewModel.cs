using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OpenGuard.App.Services;

namespace OpenGuard.App.ViewModels;

public partial class ScannerViewModel : ObservableObject
{
    private readonly NativeServiceClient serviceClient = new();
    private string? activeScanId;
    private NativeScanFinding? latestFinding;

    public static ScannerViewModel Instance { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanStartScan))]
    [NotifyPropertyChangedFor(nameof(CanCancelScan))]
    [NotifyPropertyChangedFor(nameof(CanQuarantine))]
    public partial bool IsScanning { get; set; }

    public bool CanStartScan => !IsScanning;

    public bool CanCancelScan => IsScanning && activeScanId is not null;

    public bool CanQuarantine => !IsScanning && latestFinding is not null &&
        latestFinding.Verdict is "suspicious" or "malicious";

    [ObservableProperty]
    public partial string StatusHeadline { get; set; } = "Ready for a local scan";

    [ObservableProperty]
    public partial string StatusDetail { get; set; } =
        "Choose a file. OpenGuard analyzes it locally and returns the evidence behind its verdict.";

    [ObservableProperty]
    public partial string VerdictText { get; set; } = "NO RESULT";

    [ObservableProperty]
    public partial string ScoreText { get; set; } = "Risk score —";

    [ObservableProperty]
    public partial string TargetPath { get; set; } = "No file selected";

    [ObservableProperty]
    public partial string HashText { get; set; } = "SHA-256 will appear after a completed scan";

    [ObservableProperty]
    public partial string EngineText { get; set; } = "YARA-X ready · Windows AMSI ready";

    [ObservableProperty]
    public partial IReadOnlyList<string> Evidence { get; set; } =
        ["No configured local detection signal has been evaluated yet."];

    public Task StartPathScanAsync(string path) => RunScanAsync(
        path,
        token => serviceClient.StartPathScanAsync(path, token));

    public Task StartProfileScanAsync(string profile) => RunScanAsync(
        $"{char.ToUpperInvariant(profile[0])}{profile[1..]} profile",
        token => serviceClient.StartProfileScanAsync(profile, token));

    private async Task RunScanAsync(
        string targetLabel,
        Func<CancellationToken, Task<string>> startScan)
    {
        if (IsScanning)
        {
            return;
        }

        IsScanning = true;
        latestFinding = null;
        OnPropertyChanged(nameof(CanQuarantine));
        QuarantineLatestCommand.NotifyCanExecuteChanged();
        TargetPath = targetLabel;
        VerdictText = "SCANNING";
        ScoreText = "Risk score —";
        HashText = "Calculating SHA-256…";
        EngineText = "Native scanner is analyzing this file";
        Evidence = ["Hashing and content inspection are in progress."];
        StatusHeadline = "Scan in progress";
        StatusDetail = "The UI remains responsive while the native service does the work.";
        try
        {
            activeScanId = await startScan(CancellationToken.None);
            OnPropertyChanged(nameof(CanCancelScan));
            while (true)
            {
                NativeScanStatus status = await serviceClient.GetScanAsync(
                    activeScanId,
                    CancellationToken.None);
                switch (status.State)
                {
                    case "queued":
                    case "running":
                        StatusDetail = status.TotalFiles == 0
                            ? "Discovering files without following symbolic links…"
                            : $"{status.FilesScanned:N0} of {status.TotalFiles:N0} · {status.CurrentPath}";
                        await Task.Delay(250);
                        continue;
                    case "completed" when status.Finding is not null:
                        ApplyFinding(status.Finding);
                        return;
                    case "completed":
                        ApplyFolderResult(status);
                        return;
                    case "cancelled":
                        VerdictText = "CANCELLED";
                        StatusHeadline = "Scan cancelled";
                        StatusDetail = "No action was taken on the selected file.";
                        Evidence = ["The native scanner received a cancellation request."];
                        return;
                    default:
                        throw new NativeServiceException(status.Error ?? "Native scan failed.");
                }
            }
        }
        catch (Exception error) when (error is IOException or TimeoutException or NativeServiceException or System.Text.Json.JsonException)
        {
            VerdictText = "SCAN ERROR";
            StatusHeadline = "The scan could not finish";
            StatusDetail = error.Message;
            HashText = "No completed digest";
            Evidence = [error.Message];
        }
        finally
        {
            activeScanId = null;
            IsScanning = false;
            OnPropertyChanged(nameof(CanCancelScan));
        }
    }

    [RelayCommand(CanExecute = nameof(CanCancelScan))]
    private async Task CancelScanAsync()
    {
        if (activeScanId is null)
        {
            return;
        }
        await serviceClient.CancelScanAsync(activeScanId, CancellationToken.None);
        StatusDetail = "Cancellation requested; waiting for the current read block to finish.";
    }

    [RelayCommand(CanExecute = nameof(CanQuarantine))]
    private async Task QuarantineLatestAsync()
    {
        NativeScanFinding? finding = latestFinding;
        if (finding is null)
        {
            return;
        }
        IsScanning = true;
        StatusHeadline = "Moving file into quarantine";
        StatusDetail = "OpenGuard is re-scanning, defanging, and verifying the file before removing the original.";
        try
        {
            NativeQuarantineRecord record = await serviceClient.QuarantineAsync(
                finding,
                CancellationToken.None);
            latestFinding = null;
            VerdictText = "ISOLATED";
            StatusHeadline = "Threat moved to quarantine";
            StatusDetail = $"{Path.GetFileName(record.OriginalPath)} is recoverable from the Quarantine page.";
            Evidence = [.. Evidence, "The quarantine payload passed its SHA-256 integrity check."];
        }
        catch (Exception error) when (error is IOException or TimeoutException or NativeServiceException or System.Text.Json.JsonException)
        {
            StatusHeadline = "Quarantine did not complete";
            StatusDetail = error.Message;
            Evidence = [.. Evidence, $"Quarantine stopped safely: {error.Message}"];
        }
        finally
        {
            IsScanning = false;
            OnPropertyChanged(nameof(CanQuarantine));
            QuarantineLatestCommand.NotifyCanExecuteChanged();
        }
    }

    partial void OnIsScanningChanged(bool value)
    {
        CancelScanCommand.NotifyCanExecuteChanged();
        QuarantineLatestCommand.NotifyCanExecuteChanged();
    }

    private void ApplyFinding(NativeScanFinding finding)
    {
        latestFinding = finding;
        OnPropertyChanged(nameof(CanQuarantine));
        QuarantineLatestCommand.NotifyCanExecuteChanged();
        VerdictText = finding.Verdict.Replace('_', ' ').ToUpperInvariant();
        ScoreText = $"Risk score {finding.Score}/100";
        TargetPath = finding.Path;
        HashText = finding.Sha256;
        EngineText = $"YARA-X {finding.YaraStatus.Replace('_', ' ')} · AMSI {finding.AmsiResult.Replace('_', ' ')}";
        Evidence = finding.Reasons.Count == 0
            ? ["No configured local detection signal matched."]
            : finding.Reasons;
        StatusHeadline = finding.Verdict switch
        {
            "malicious" => "Malicious content detected",
            "suspicious" => "Suspicious content needs review",
            "low_risk" => "Low-risk signals found",
            _ => "Scan complete",
        };
        StatusDetail = $"Scanned {ShellViewModel.FormatBytes(finding.SizeBytes)} locally. Nothing was uploaded or removed.";
    }

    private void ApplyFolderResult(NativeScanStatus status)
    {
        latestFinding = null;
        OnPropertyChanged(nameof(CanQuarantine));
        QuarantineLatestCommand.NotifyCanExecuteChanged();
        int detections = status.Findings.Count;
        VerdictText = detections == 0 ? "CLEAN" : "REVIEW";
        ScoreText = $"{detections:N0} retained finding{(detections == 1 ? string.Empty : "s")}";
        HashText = "Per-file hashes are stored in the local scan history";
        EngineText = "YARA-X active · AMSI active when an installed provider responds";
        Evidence = detections == 0
            ? ["No configured detection signal matched the scanned files."]
            : status.Findings
                .SelectMany(finding => finding.Reasons.Select(reason => $"{Path.GetFileName(finding.Path)} · {reason}"))
                .Take(200)
                .ToArray();
        StatusHeadline = detections == 0 ? "Folder scan complete" : "Folder scan needs review";
        StatusDetail = $"Scanned {status.FilesScanned:N0} of {status.TotalFiles:N0} files locally. Clean results remain in history.";
    }
}
