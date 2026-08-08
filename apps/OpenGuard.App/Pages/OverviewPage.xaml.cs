using Microsoft.UI.Xaml.Controls;
using OpenGuard.App.ViewModels;

namespace OpenGuard.App.Pages;

public sealed partial class OverviewPage : Page
{
    public ShellViewModel ViewModel { get; } = ShellViewModel.Instance;

    public OverviewPage()
    {
        InitializeComponent();
    }

    private async void OnRefreshClick(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        await ViewModel.RefreshSnapshotAsync(CancellationToken.None);
    }
}
