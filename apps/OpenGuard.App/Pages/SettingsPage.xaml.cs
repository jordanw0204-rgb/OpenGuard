using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.Storage.Pickers;
using OpenGuard.App.ViewModels;

namespace OpenGuard.App.Pages;

public sealed partial class SettingsPage : Page
{
    public SettingsViewModel ViewModel { get; } = SettingsViewModel.Instance;

    public SettingsPage() => InitializeComponent();

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            await ViewModel.RefreshAsync();
        }
        catch (Exception error)
        {
            App.LogException(error);
        }
    }

    private async void OnAddExclusion(object sender, RoutedEventArgs e)
    {
        try
        {
            FolderPicker picker = new(App.Window.AppWindow.Id)
            {
                SuggestedStartLocation = PickerLocationId.Downloads,
                CommitButtonText = "Exclude selected folder",
                ViewMode = PickerViewMode.List,
            };
            PickFolderResult? result = await picker.PickSingleFolderAsync();
            if (result is not null)
            {
                await ViewModel.AddExclusionAsync(result.Path, recursive: true);
            }
        }
        catch (Exception error)
        {
            App.LogException(error);
            ViewModel.PolicyStatusText = $"Could not select the folder: {error.Message}";
        }
    }

    private async void OnRemoveExclusion(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path })
        {
            await ViewModel.RemoveExclusionAsync(path);
        }
    }

    private async void OnAddAllowedHash(object sender, RoutedEventArgs e)
    {
        string sha256 = HashInput.Text.Trim();
        if (sha256.Length != 64 || sha256.Any(character => !Uri.IsHexDigit(character)))
        {
            ViewModel.PolicyStatusText = "Enter an exact 64-character SHA-256 digest.";
            return;
        }
        await ViewModel.AddAllowedHashAsync(sha256, HashLabelInput.Text.Trim());
        HashInput.Text = string.Empty;
        HashLabelInput.Text = string.Empty;
    }

    private async void OnRemoveAllowedHash(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string sha256 })
        {
            await ViewModel.RemoveAllowedHashAsync(sha256);
        }
    }
}
