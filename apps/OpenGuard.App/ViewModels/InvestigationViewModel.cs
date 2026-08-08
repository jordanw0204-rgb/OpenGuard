using CommunityToolkit.Mvvm.ComponentModel;
using OpenGuard.App.Services;
using System.Collections.ObjectModel;

namespace OpenGuard.App.ViewModels;

public sealed partial class InvestigationViewModel : ObservableObject
{
    private readonly NativeServiceClient serviceClient = new();
    private long? nextBeforeId;

    public static InvestigationViewModel Instance { get; } = new();

    public ObservableCollection<TimelineItemViewModel> Timeline { get; } = [];

    public ObservableCollection<PersistenceItemViewModel> Persistence { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanLoadOlder))]
    public partial bool IsTimelineBusy { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRefreshPersistence))]
    public partial bool IsPersistenceBusy { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanDisableSelected))]
    public partial PersistenceItemViewModel? SelectedPersistence { get; set; }

    [ObservableProperty]
    public partial string TimelineStatus { get; set; } = "Loading historical evidence…";

    [ObservableProperty]
    public partial string PersistenceStatus { get; set; } = "Loading startup mechanisms…";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRestoreLast))]
    public partial string LastRollbackId { get; set; } = string.Empty;

    public bool CanLoadOlder => !IsTimelineBusy && nextBeforeId.HasValue;

    public bool CanRefreshPersistence => !IsPersistenceBusy;

    public bool CanDisableSelected =>
        !IsPersistenceBusy && SelectedPersistence?.ResponseCapability == "disable_restore";

    public bool CanRestoreLast => !IsPersistenceBusy && !string.IsNullOrWhiteSpace(LastRollbackId);

    public async Task RefreshTimelineAsync(string? search, string? category)
    {
        if (IsTimelineBusy)
        {
            return;
        }
        IsTimelineBusy = true;
        try
        {
            NativeTimelinePage page = await serviceClient.GetTimelineAsync(
                null,
                250,
                NormalizeCategory(category),
                null,
                string.IsNullOrWhiteSpace(search) ? null : search.Trim(),
                CancellationToken.None);
            Timeline.Clear();
            foreach (NativeTimelineEvent item in page.Events)
            {
                Timeline.Add(new TimelineItemViewModel(item));
            }
            nextBeforeId = page.NextBeforeId;
            TimelineStatus = Timeline.Count == 0
                ? "No matching historical evidence has been recorded."
                : $"{Timeline.Count:N0} event{(Timeline.Count == 1 ? string.Empty : "s")} loaded, newest first.";
        }
        catch (Exception error) when (IsServiceError(error))
        {
            TimelineStatus = $"Timeline unavailable: {error.Message}";
        }
        finally
        {
            IsTimelineBusy = false;
            OnPropertyChanged(nameof(CanLoadOlder));
        }
    }

    public async Task LoadOlderAsync(string? search, string? category)
    {
        if (IsTimelineBusy || nextBeforeId is not long cursor)
        {
            return;
        }
        IsTimelineBusy = true;
        try
        {
            NativeTimelinePage page = await serviceClient.GetTimelineAsync(
                cursor,
                250,
                NormalizeCategory(category),
                null,
                string.IsNullOrWhiteSpace(search) ? null : search.Trim(),
                CancellationToken.None);
            foreach (NativeTimelineEvent item in page.Events)
            {
                Timeline.Add(new TimelineItemViewModel(item));
            }
            nextBeforeId = page.NextBeforeId;
            TimelineStatus = $"{Timeline.Count:N0} historical events loaded.";
        }
        catch (Exception error) when (IsServiceError(error))
        {
            TimelineStatus = $"Could not load older evidence: {error.Message}";
        }
        finally
        {
            IsTimelineBusy = false;
            OnPropertyChanged(nameof(CanLoadOlder));
        }
    }

    public async Task RefreshPersistenceAsync(bool force)
    {
        if (IsPersistenceBusy)
        {
            return;
        }
        IsPersistenceBusy = true;
        try
        {
            NativePersistenceInventory inventory =
                await serviceClient.GetPersistenceAsync(force, CancellationToken.None);
            Persistence.Clear();
            foreach (NativePersistenceItem item in inventory.Items)
            {
                Persistence.Add(new PersistenceItemViewModel(item));
            }
            SelectedPersistence = Persistence.FirstOrDefault();
            int limited = inventory.Coverage.Count(note => note.State != "active");
            PersistenceStatus = $"{Persistence.Count:N0} active registrations · " +
                (limited == 0 ? "all collectors active" : $"{limited} collector{(limited == 1 ? string.Empty : "s")} limited");
        }
        catch (Exception error) when (IsServiceError(error))
        {
            PersistenceStatus = $"Persistence inventory unavailable: {error.Message}";
        }
        finally
        {
            IsPersistenceBusy = false;
            OnPropertyChanged(nameof(CanRefreshPersistence));
            OnPropertyChanged(nameof(CanDisableSelected));
            OnPropertyChanged(nameof(CanRestoreLast));
        }
    }

    internal void ApplyResponseResult(NativeResponseActionResult result)
    {
        LastRollbackId = result.RollbackId ?? string.Empty;
        PersistenceStatus = result.Outcome;
    }

    partial void OnSelectedPersistenceChanged(PersistenceItemViewModel? value) =>
        OnPropertyChanged(nameof(CanDisableSelected));

    private static string? NormalizeCategory(string? value) =>
        string.IsNullOrWhiteSpace(value) || value == "all" ? null : value;

    private static bool IsServiceError(Exception error) =>
        error is IOException or TimeoutException or NativeServiceException or System.Text.Json.JsonException;
}

public sealed class TimelineItemViewModel
{
    internal TimelineItemViewModel(NativeTimelineEvent item)
    {
        Category = item.Category.ToUpperInvariant();
        Severity = item.Severity.ToUpperInvariant();
        Title = item.Title;
        Detail = item.Detail;
        Context = BuildContext(item);
        OccurredText = FormatTimestamp(item.OccurredAt);
    }

    public string Category { get; }
    public string Severity { get; }
    public string Title { get; }
    public string Detail { get; }
    public string Context { get; }
    public string OccurredText { get; }

    private static string BuildContext(NativeTimelineEvent item)
    {
        List<string> values = [];
        if (item.ProcessId is uint pid) values.Add($"PID {pid:N0}");
        if (!string.IsNullOrWhiteSpace(item.Path)) values.Add(item.Path);
        if (!string.IsNullOrWhiteSpace(item.RemoteAddress)) values.Add(item.RemoteAddress);
        return values.Count == 0 ? item.Action.Replace('_', ' ') : string.Join(" · ", values);
    }

    private static string FormatTimestamp(string timestamp) =>
        timestamp.StartsWith("unix:", StringComparison.Ordinal) &&
        long.TryParse(timestamp.AsSpan(5), out long seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds).ToLocalTime().ToString("g")
            : timestamp;
}

public sealed class PersistenceItemViewModel
{
    internal PersistenceItemViewModel(NativePersistenceItem item)
    {
        Id = item.Id;
        Category = item.Category.Replace('_', ' ').ToUpperInvariant();
        Name = item.Name;
        Command = item.Command;
        Location = item.Location;
        State = item.State.ToUpperInvariant();
        Risk = item.Risk.ToUpperInvariant();
        Evidence = string.Join("; ", item.Evidence);
        ResponseCapability = item.ResponseCapability;
    }

    public string Id { get; }
    public string Category { get; }
    public string Name { get; }
    public string Command { get; }
    public string Location { get; }
    public string State { get; }
    public string Risk { get; }
    public string Evidence { get; }
    public string ResponseCapability { get; }
}
