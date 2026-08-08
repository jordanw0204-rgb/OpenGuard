using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using OpenGuard.App.Pages;
using OpenGuard.App.ViewModels;

namespace OpenGuard.App;

public sealed partial class MainPage : Page
{
    private readonly DispatcherTimer refreshTimer = new()
    {
        Interval = TimeSpan.FromSeconds(2),
    };

    public ShellViewModel ViewModel { get; } = ShellViewModel.Instance;

    public MainPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        refreshTimer.Tick += OnRefreshTimerTick;
        Navigation.SelectedItem = Navigation.MenuItems[0];
        ContentFrame.Navigate(typeof(OverviewPage));
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await ViewModel.RefreshServiceStatusAsync();
        refreshTimer.Start();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        refreshTimer.Stop();
    }

    private async void OnRefreshTimerTick(object? sender, object e)
    {
        await ViewModel.RefreshSnapshotAsync(CancellationToken.None);
    }

    private void OnSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer?.Tag is not string tag)
        {
            return;
        }

        Type page = tag switch
        {
            "processes" => typeof(ProcessesPage),
            "network" => typeof(NetworkPage),
            "scanner" => typeof(ScannerPage),
            "detections" => typeof(DetectionsPage),
            "quarantine" => typeof(QuarantinePage),
            "settings" => typeof(SettingsPage),
            _ => typeof(OverviewPage),
        };
        if (ContentFrame.CurrentSourcePageType != page)
        {
            ContentFrame.Navigate(page);
        }
    }
}
