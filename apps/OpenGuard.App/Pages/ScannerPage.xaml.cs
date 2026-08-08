using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.Storage.Pickers;
using OpenGuard.App.ViewModels;

namespace OpenGuard.App.Pages;

public sealed partial class ScannerPage : Page
{
    public ScannerViewModel ViewModel { get; } = ScannerViewModel.Instance;

    public ScannerPage() => InitializeComponent();

    private async void OnSelectFile(object sender, RoutedEventArgs e)
    {
        try
        {
            FileOpenPicker picker = new(App.Window.AppWindow.Id)
            {
                SuggestedStartLocation = PickerLocationId.Downloads,
                CommitButtonText = "Scan selected file",
                ViewMode = PickerViewMode.List,
            };
            PickFileResult? result = await picker.PickSingleFileAsync();
            if (result is not null)
            {
                await ViewModel.StartPathScanAsync(result.Path);
            }
        }
        catch (Exception error)
        {
            App.LogException(error);
        }
    }

    private async void OnSelectFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            FolderPicker picker = new(App.Window.AppWindow.Id)
            {
                SuggestedStartLocation = PickerLocationId.Downloads,
                CommitButtonText = "Scan selected folder",
                ViewMode = PickerViewMode.List,
            };
            PickFolderResult? result = await picker.PickSingleFolderAsync();
            if (result is not null)
            {
                await ViewModel.StartPathScanAsync(result.Path);
            }
        }
        catch (Exception error)
        {
            App.LogException(error);
        }
    }

    private async void OnScanProfile(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string profile })
        {
            return;
        }
        try
        {
            if (profile == "full")
            {
                ContentDialog confirmation = new()
                {
                    XamlRoot = XamlRoot,
                    Title = "Scan the full system drive?",
                    Content = "A full scan can inspect hundreds of thousands of files and may take a long time. You can cancel it at any point.",
                    PrimaryButtonText = "Start full scan",
                    CloseButtonText = "Cancel",
                    DefaultButton = ContentDialogButton.Close,
                };
                if (await confirmation.ShowAsync() != ContentDialogResult.Primary)
                {
                    return;
                }
            }
            await ViewModel.StartProfileScanAsync(profile);
        }
        catch (Exception error)
        {
            App.LogException(error);
        }
    }
}
