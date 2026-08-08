using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using OpenGuard.App.Services;
using OpenGuard.App.ViewModels;

namespace OpenGuard.App.Pages;

public sealed partial class NetworkPage : Page
{
    private int investigationRunning;

    public ShellViewModel ViewModel { get; } = ShellViewModel.Instance;

    public NetworkPage()
    {
        InitializeComponent();
        UpdateSortHeaders();
    }

    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        if (NetworkFilter is not null && ProtocolFilter is not null)
        {
            ViewModel.FilterNetwork(NetworkFilter.Text, ProtocolFilter.SelectedIndex);
        }
    }

    private void OnSortHeaderClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string tag } && Enum.TryParse(tag, out NetworkSortColumn column))
        {
            ViewModel.SortNetwork(column);
            UpdateSortHeaders();
        }
    }

    private void UpdateSortHeaders()
    {
        SetHeader(ApplicationHeader, NetworkSortColumn.Application, "APPLICATION");
        SetHeader(DownloadHeader, NetworkSortColumn.Download, "DOWNLOAD");
        SetHeader(UploadHeader, NetworkSortColumn.Upload, "UPLOAD");
        SetHeader(DestinationHeader, NetworkSortColumn.Destination, "DESTINATION");
        SetHeader(ReputationHeader, NetworkSortColumn.Reputation, "REPUTATION");
        SetHeader(ProtocolHeader, NetworkSortColumn.Protocol, "PROTOCOL");
    }

    private void SetHeader(Button button, NetworkSortColumn column, string label) =>
        button.Content = ViewModel.ActiveNetworkSortColumn == column
            ? $"{label} {(ViewModel.NetworkSortDescending ? "▼" : "▲")}" : label;

    private async void OnInvestigateFromMenu(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuFlyoutItem { Tag: uint pid }
            || ViewModel.FindProcess(pid) is not ProcessRow process
            || Interlocked.Exchange(ref investigationRunning, 1) != 0)
        {
            return;
        }
        try
        {
            ProcessInvestigationReport report = await ViewModel.InvestigateProcessAsync(process);
            ProcessInvestigationDialog dialog = new(report) { XamlRoot = XamlRoot };
            await dialog.ShowAsync();
        }
        finally
        {
            Interlocked.Exchange(ref investigationRunning, 0);
        }
    }

    private async void OnScanFromMenu(object sender, RoutedEventArgs e)
    {
        if (sender is MenuFlyoutItem { Tag: string path } && !string.IsNullOrWhiteSpace(path))
        {
            Frame.Navigate(typeof(ScannerPage));
            await ScannerViewModel.Instance.StartPathScanAsync(path);
        }
    }

    private void OnOpenFileLocation(object sender, RoutedEventArgs e)
    {
        if (sender is MenuFlyoutItem { Tag: string path })
        {
            ProcessActions.OpenFileLocation(path);
        }
    }

    private void OnSearchWeb(object sender, RoutedEventArgs e)
    {
        if (sender is MenuFlyoutItem { Tag: string application })
        {
            ProcessActions.SearchWeb(application);
        }
    }

    private void OnCopyText(object sender, RoutedEventArgs e)
    {
        if (sender is MenuFlyoutItem { Tag: string text })
        {
            ProcessActions.CopyText(text);
        }
    }

    private async void OnBlockDestination(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuFlyoutItem { Tag: NetworkRow { CanBlockRemote: true } row })
        {
            return;
        }
        NativeResponseActionRequest request = InvestigationPage.EmptyRequest("block_remote_address") with
        {
            ProcessId = row.ProcessId,
            ExpectedPath = row.ProcessPath,
            Target = row.Destination,
            RemoteAddress = row.RemoteAddress,
            DurationMinutes = 15,
        };
        try
        {
            NativeResponseActionResult? result = await ResponseActionService.ConfirmAsync(
                XamlRoot,
                request,
                $"Temporarily block {row.RemoteAddress}?",
                "OpenGuard will add a program-scoped outbound Windows Firewall rule and remove it after 15 minutes.",
                "Block 15 minutes");
            if (result is not null)
            {
                await ResponseActionService.ShowResultAsync(XamlRoot, result);
            }
        }
        catch (Exception error)
        {
            await ResponseActionService.ShowErrorAsync(XamlRoot, "Network response failed safely", error);
        }
    }
}
