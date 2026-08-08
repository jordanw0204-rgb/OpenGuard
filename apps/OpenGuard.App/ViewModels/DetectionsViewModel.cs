using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OpenGuard.App.Services;

namespace OpenGuard.App.ViewModels;

public sealed partial class DetectionsViewModel : ObservableObject
{
    private readonly NativeServiceClient serviceClient = new();

    public static DetectionsViewModel Instance { get; } = new();

    public ObservableCollection<DetectionEventViewModel> Events { get; } = [];

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Loading the local evidence timeline…";

    [RelayCommand]
    public async Task RefreshAsync()
    {
        if (IsBusy)
        {
            return;
        }
        IsBusy = true;
        try
        {
            IReadOnlyList<NativeSecurityEvent> events =
                await serviceClient.GetRecentEventsAsync(1000, CancellationToken.None);
            Events.Clear();
            foreach (NativeSecurityEvent securityEvent in events)
            {
                Events.Add(new DetectionEventViewModel(securityEvent));
            }
            StatusText = Events.Count == 0
                ? "No evidence-backed detections have been recorded for this Windows user."
                : $"{Events.Count:N0} local event{(Events.Count == 1 ? string.Empty : "s")}, newest first.";
        }
        catch (Exception error) when (error is IOException or TimeoutException or NativeServiceException or System.Text.Json.JsonException)
        {
            StatusText = $"Detection history is unavailable: {error.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}

public sealed class DetectionEventViewModel
{
    internal DetectionEventViewModel(NativeSecurityEvent securityEvent)
    {
        Severity = securityEvent.Severity.ToUpperInvariant();
        Title = securityEvent.Title;
        Detail = securityEvent.Detail;
        Path = string.IsNullOrWhiteSpace(securityEvent.Path) ? "No file path" : securityEvent.Path;
        ProcessText = securityEvent.ProcessId is uint pid ? $"PID {pid:N0}" : "File or service event";
        StateText = securityEvent.Resolved ? "RESOLVED" : "OPEN";
        CreatedText = FormatTimestamp(securityEvent.CreatedAt);
    }

    public string Severity { get; }
    public string Title { get; }
    public string Detail { get; }
    public string Path { get; }
    public string ProcessText { get; }
    public string StateText { get; }
    public string CreatedText { get; }

    private static string FormatTimestamp(string timestamp)
    {
        if (timestamp.StartsWith("unix:", StringComparison.Ordinal) &&
            long.TryParse(timestamp.AsSpan(5), out long seconds))
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds).ToLocalTime().ToString("g");
        }
        return timestamp;
    }
}
