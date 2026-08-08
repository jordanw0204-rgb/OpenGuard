using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OpenGuard.App.Services;

namespace OpenGuard.App.ViewModels;

public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly NativeServiceClient serviceClient = new();

    public static SettingsViewModel Instance { get; } = new();

    public ObservableCollection<ExclusionItemViewModel> Exclusions { get; } = [];

    public ObservableCollection<AllowedHashItemViewModel> AllowedHashes { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanManageContent))]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string ContentVersion { get; set; } = "Loading…";

    [ObservableProperty]
    public partial string ContentSource { get; set; } = "Checking the authenticated local service";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRollback))]
    public partial bool HasRollback { get; set; }

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Security-content status has not been loaded.";

    [ObservableProperty]
    public partial string PolicyStatusText { get; set; } = "Loading user protection policy…";

    public bool CanManageContent => !IsBusy;
    public bool CanRollback => !IsBusy && HasRollback;

    public async Task RefreshAsync()
    {
        await RefreshContentAsync();
        await RefreshPolicyAsync();
    }

    [RelayCommand]
    public async Task RefreshContentAsync() => await RunContentActionAsync(
        serviceClient.GetContentStatusAsync,
        "Security-content status refreshed.");

    [RelayCommand(CanExecute = nameof(CanManageContent))]
    private async Task InstallContentUpdateAsync() => await RunContentActionAsync(
        serviceClient.InstallContentUpdateAsync,
        "Signed security content verified and activated.");

    [RelayCommand(CanExecute = nameof(CanRollback))]
    private async Task RollbackContentUpdateAsync() => await RunContentActionAsync(
        serviceClient.RollbackContentUpdateAsync,
        "Rolled back to the previous verified content version.");

    private async Task RunContentActionAsync(
        Func<CancellationToken, Task<NativeContentStatus>> action,
        string successMessage)
    {
        if (IsBusy)
        {
            return;
        }
        IsBusy = true;
        StatusText = "Contacting the signed content service…";
        try
        {
            NativeContentStatus status = await action(CancellationToken.None);
            ContentVersion = status.ActiveVersion;
            ContentSource = status.Source == "signed_update"
                ? "Strict Ed25519 signature verified"
                : "Reviewed rules bundled with this OpenGuard build";
            HasRollback = !string.IsNullOrWhiteSpace(status.PreviousVersion);
            StatusText = successMessage;
        }
        catch (Exception error) when (error is IOException or TimeoutException or NativeServiceException or System.Text.Json.JsonException)
        {
            StatusText = $"Content action failed safely: {error.Message}";
        }
        finally
        {
            IsBusy = false;
            InstallContentUpdateCommand.NotifyCanExecuteChanged();
            RollbackContentUpdateCommand.NotifyCanExecuteChanged();
        }
    }

    partial void OnIsBusyChanged(bool value)
    {
        InstallContentUpdateCommand.NotifyCanExecuteChanged();
        RollbackContentUpdateCommand.NotifyCanExecuteChanged();
    }

    partial void OnHasRollbackChanged(bool value) =>
        RollbackContentUpdateCommand.NotifyCanExecuteChanged();

    public async Task RefreshPolicyAsync()
    {
        if (IsBusy)
        {
            return;
        }
        IsBusy = true;
        PolicyStatusText = "Reading user-scoped protection policy…";
        try
        {
            await RefreshPolicyCoreAsync();
            PolicyStatusText = $"{Exclusions.Count:N0} exclusion{(Exclusions.Count == 1 ? string.Empty : "s")} · " +
                $"{AllowedHashes.Count:N0} allowed hash{(AllowedHashes.Count == 1 ? string.Empty : "es")}.";
        }
        catch (Exception error) when (error is IOException or TimeoutException or NativeServiceException or System.Text.Json.JsonException)
        {
            PolicyStatusText = $"Protection policy is unavailable: {error.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    public Task AddExclusionAsync(string path, bool recursive) => RunPolicyMutationAsync(
        token => serviceClient.AddExclusionAsync(path, recursive, token),
        "Path exclusion saved.");

    public Task RemoveExclusionAsync(string path) => RunPolicyMutationAsync(
        token => serviceClient.RemoveExclusionAsync(path, token),
        "Path exclusion removed.");

    public Task AddAllowedHashAsync(string sha256, string label) => RunPolicyMutationAsync(
        token => serviceClient.AllowHashAsync(sha256, label, token),
        "Exact SHA-256 allow-list entry saved.");

    public Task RemoveAllowedHashAsync(string sha256) => RunPolicyMutationAsync(
        token => serviceClient.RemoveAllowedHashAsync(sha256, token),
        "SHA-256 allow-list entry removed.");

    private async Task RunPolicyMutationAsync(
        Func<CancellationToken, Task> mutation,
        string successMessage)
    {
        if (IsBusy)
        {
            return;
        }
        IsBusy = true;
        PolicyStatusText = "Applying policy through the authenticated local service…";
        try
        {
            await mutation(CancellationToken.None);
            await RefreshPolicyCoreAsync();
            PolicyStatusText = successMessage;
        }
        catch (Exception error) when (error is IOException or TimeoutException or NativeServiceException or System.Text.Json.JsonException)
        {
            PolicyStatusText = $"Policy change failed safely: {error.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RefreshPolicyCoreAsync()
    {
        IReadOnlyList<NativeExclusionRecord> exclusions =
            await serviceClient.GetExclusionsAsync(CancellationToken.None);
        IReadOnlyList<NativeAllowedHashRecord> hashes =
            await serviceClient.GetAllowedHashesAsync(CancellationToken.None);
        Exclusions.Clear();
        foreach (NativeExclusionRecord record in exclusions)
        {
            Exclusions.Add(new ExclusionItemViewModel(record));
        }
        AllowedHashes.Clear();
        foreach (NativeAllowedHashRecord record in hashes)
        {
            AllowedHashes.Add(new AllowedHashItemViewModel(record));
        }
    }
}

public sealed class ExclusionItemViewModel
{
    internal ExclusionItemViewModel(NativeExclusionRecord record)
    {
        Path = record.Path;
        Scope = record.Recursive ? "Folder and descendants" : "Exact path only";
        CreatedAt = record.CreatedAt;
    }

    public string Path { get; }
    public string Scope { get; }
    public string CreatedAt { get; }
}

public sealed class AllowedHashItemViewModel
{
    internal AllowedHashItemViewModel(NativeAllowedHashRecord record)
    {
        Sha256 = record.Sha256;
        Label = string.IsNullOrWhiteSpace(record.Label) ? "Reviewed hash" : record.Label;
        CreatedAt = record.CreatedAt;
    }

    public string Sha256 { get; }
    public string Label { get; }
    public string CreatedAt { get; }
}
