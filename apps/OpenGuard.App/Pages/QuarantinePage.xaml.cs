using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using OpenGuard.App.ViewModels;

namespace OpenGuard.App.Pages;

public sealed partial class QuarantinePage : Page
{
    public QuarantineViewModel ViewModel { get; } = QuarantineViewModel.Instance;

    public QuarantinePage() => InitializeComponent();

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
