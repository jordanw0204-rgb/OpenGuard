using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OpenGuard.App.Services;

namespace OpenGuard.App.ViewModels;

public sealed partial class QuarantineViewModel : ObservableObject
{
    private readonly NativeServiceClient serviceClient = new();

    public static QuarantineViewModel Instance { get; } = new();

    public ObservableCollection<QuarantineItemViewModel> Items { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRestore))]
    public partial QuarantineItemViewModel? SelectedItem { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRestore))]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Loading recoverable quarantine records…";

    public bool CanRestore => !IsBusy && SelectedItem is { IsRestored: false };

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
            IReadOnlyList<NativeQuarantineRecord> records =
                await serviceClient.GetQuarantinesAsync(500, CancellationToken.None);
            Items.Clear();
            foreach (NativeQuarantineRecord record in records)
            {
                Items.Add(new QuarantineItemViewModel(record));
            }
            SelectedItem = Items.FirstOrDefault(item => !item.IsRestored) ?? Items.FirstOrDefault();
            StatusText = Items.Count == 0
                ? "No files are isolated. OpenGuard never deletes a detection automatically."
                : $"{Items.Count:N0} audited quarantine record{(Items.Count == 1 ? string.Empty : "s")}.";
        }
        catch (Exception error) when (error is IOException or TimeoutException or NativeServiceException or System.Text.Json.JsonException)
        {
            StatusText = $"Quarantine is unavailable: {error.Message}";
        }
        finally
        {
            IsBusy = false;
            RestoreSelectedCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand(CanExecute = nameof(CanRestore))]
    private async Task RestoreSelectedAsync()
    {
        QuarantineItemViewModel? selected = SelectedItem;
        if (selected is null || selected.IsRestored)
        {
            return;
        }
        IsBusy = true;
        RestoreSelectedCommand.NotifyCanExecuteChanged();
        StatusText = $"Restoring {selected.FileName} after integrity verification…";
        try
        {
            NativeQuarantineRecord restored = await serviceClient.RestoreQuarantineAsync(
                selected.Id,
                null,
                CancellationToken.None);
            int index = Items.IndexOf(selected);
            QuarantineItemViewModel replacement = new(restored);
            Items[index] = replacement;
            SelectedItem = replacement;
            StatusText = $"Restored to {restored.RestoredPath}.";
        }
        catch (Exception error) when (error is IOException or TimeoutException or NativeServiceException or System.Text.Json.JsonException)
        {
            StatusText = $"Restore failed safely: {error.Message}";
        }
        finally
        {
            IsBusy = false;
            RestoreSelectedCommand.NotifyCanExecuteChanged();
        }
    }

    partial void OnSelectedItemChanged(QuarantineItemViewModel? value) =>
        RestoreSelectedCommand.NotifyCanExecuteChanged();

    partial void OnIsBusyChanged(bool value) => RestoreSelectedCommand.NotifyCanExecuteChanged();
}

public sealed class QuarantineItemViewModel
{
    internal QuarantineItemViewModel(NativeQuarantineRecord record)
    {
        Id = record.Id;
        OriginalPath = record.OriginalPath;
        FileName = Path.GetFileName(record.OriginalPath);
        Sha256 = record.Sha256;
        Reason = record.Reason;
        CreatedText = FormatTimestamp(record.CreatedAt);
        RestoredPath = record.RestoredPath ?? string.Empty;
        IsRestored = record.RestoredAt is not null;
        StateText = IsRestored ? "RESTORED" : "ISOLATED";
    }

    public string Id { get; }
    public string OriginalPath { get; }
    public string FileName { get; }
    public string Sha256 { get; }
    public string Reason { get; }
    public string CreatedText { get; }
    public string RestoredPath { get; }
    public bool IsRestored { get; }
    public string StateText { get; }

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
