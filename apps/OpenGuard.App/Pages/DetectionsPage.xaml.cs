using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using OpenGuard.App.ViewModels;

namespace OpenGuard.App.Pages;

public sealed partial class DetectionsPage : Page
{
    public DetectionsViewModel ViewModel { get; } = DetectionsViewModel.Instance;

    public DetectionsPage() => InitializeComponent();

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
}
