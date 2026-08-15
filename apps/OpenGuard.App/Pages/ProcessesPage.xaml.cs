using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using OpenGuard.App.Services;
using OpenGuard.App.ViewModels;

namespace OpenGuard.App.Pages;

public sealed partial class ProcessesPage : Page
{
    private int investigationRunning;

    public ShellViewModel ViewModel { get; } = ShellViewModel.Instance;

    public ProcessesPage()
    {
        InitializeComponent();
        UpdateSortHeaders();
    }

    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        if (ProcessFilter is not null && RiskFilter is not null)
        {
            ViewModel.FilterProcesses(ProcessFilter.Text, RiskFilter.SelectedIndex);
        }
    }

    private void OnSortHeaderClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string tag } && Enum.TryParse(tag, out ProcessSortColumn column))
        {
            ViewModel.SortProcesses(column);
            UpdateSortHeaders();
        }
    }

    private void UpdateSortHeaders()
    {
        SetHeader(ApplicationHeader, ProcessSortColumn.Application, "APPLICATION");
        SetHeader(PidHeader, ProcessSortColumn.Pid, "PID");
        SetHeader(CpuHeader, ProcessSortColumn.Cpu, "CPU");
        SetHeader(MemoryHeader, ProcessSortColumn.Memory, "MEMORY");
        SetHeader(TrustHeader, ProcessSortColumn.Trust, "TRUST");
        SetHeader(RiskHeader, ProcessSortColumn.Risk, "RISK");
    }

    private void SetHeader(Button button, ProcessSortColumn column, string label) =>
        button.Content = ViewModel.ActiveProcessSortColumn == column
            ? $"{label} {(ViewModel.ProcessSortDescending ? "▼" : "▲")}" : label;

    private void OnProcessSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        InvestigateSelectedButton.IsEnabled = ProcessList.SelectedItem is ProcessRow;
        ScanSelectedButton.IsEnabled = ProcessList.SelectedItem is ProcessRow { HasProcessPath: true };
    }

    private async void OnInvestigateSelected(object sender, RoutedEventArgs e)
    {
        if (ProcessList.SelectedItem is ProcessRow selected)
        {
            await ShowInvestigationAsync(selected);
        }
    }

    private async void OnInvestigateFromMenu(object sender, RoutedEventArgs e)
    {
        if (sender is MenuFlyoutItem { Tag: uint pid } && ViewModel.FindProcess(pid) is ProcessRow process)
        {
            ProcessList.SelectedItem = process;
            await ShowInvestigationAsync(process);
        }
    }

    private async void OnProcessDoubleTapped(object sender, Microsoft.UI.Xaml.Input.DoubleTappedRoutedEventArgs e)
    {
        if (ProcessList.SelectedItem is ProcessRow selected)
        {
            await ShowInvestigationAsync(selected);
        }
    }

    private async Task ShowInvestigationAsync(ProcessRow process)
    {
        if (Interlocked.Exchange(ref investigationRunning, 1) != 0)
        {
            return;
        }
        InvestigateSelectedButton.IsEnabled = false;
        try
        {
            ProcessInvestigationReport report = await ViewModel.InvestigateProcessAsync(process);
            ProcessInvestigationDialog dialog = new(report) { XamlRoot = XamlRoot };
            await dialog.ShowAsync();
        }
        finally
        {
            Interlocked.Exchange(ref investigationRunning, 0);
            InvestigateSelectedButton.IsEnabled = ProcessList.SelectedItem is ProcessRow;
        }
    }

    private async void OnScanSelected(object sender, RoutedEventArgs e)
    {
        if (ProcessList.SelectedItem is ProcessRow { HasProcessPath: true } selected)
        {
            await ScanPathAsync(selected.ScanPath);
        }
    }

    private async void OnScanFromMenu(object sender, RoutedEventArgs e)
    {
        if (sender is MenuFlyoutItem { Tag: string path } && !string.IsNullOrWhiteSpace(path))
        {
            await ScanPathAsync(path);
        }
    }

    private async Task ScanPathAsync(string path)
    {
        Frame.Navigate(typeof(ScannerPage));
        await ScannerViewModel.Instance.StartPathScanAsync(path);
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

    private async void OnSuspendProcess(object sender, RoutedEventArgs e) =>
        await RunProcessResponseAsync(sender, "suspend_process", "Suspend this process?",
            "Windows will suspend the process's currently visible threads. New threads are not automatically suspended.", "Suspend");

    private async void OnResumeProcess(object sender, RoutedEventArgs e) =>
        await RunProcessResponseAsync(sender, "resume_process", "Resume this process?",
            "Windows will resume the process's currently visible suspended threads.", "Resume");

    private async void OnTerminateProcess(object sender, RoutedEventArgs e) =>
        await RunProcessResponseAsync(sender, "terminate_process", "Terminate this process?",
            "The process will be ended immediately after OpenGuard revalidates its PID and executable path. Unsaved application data may be lost.", "Terminate");

    private async void OnTerminateProcessTree(object sender, RoutedEventArgs e) =>
        await RunProcessResponseAsync(sender, "terminate_process_tree", "Terminate this process tree?",
            "OpenGuard will snapshot descendants, revalidate each accessible executable identity, terminate children first, and terminate the selected root last. Inaccessible or changed descendants are skipped.", "Terminate tree");

    private async void OnQuarantineExecutable(object sender, RoutedEventArgs e) =>
        await RunProcessResponseAsync(sender, "quarantine_file", "Scan and quarantine this executable?",
            "OpenGuard will rescan the exact file and only isolate it if the current result is suspicious or malicious.", "Scan and quarantine");

    private async Task RunProcessResponseAsync(
        object sender,
        string action,
        string title,
        string explanation,
        string buttonText)
    {
        if (sender is not MenuFlyoutItem { Tag: uint pid } ||
            ViewModel.FindProcess(pid) is not ProcessRow { HasProcessPath: true } process)
        {
            return;
        }
        NativeResponseActionRequest request = InvestigationPage.EmptyRequest(action) with
        {
            ProcessId = pid,
            ExpectedPath = process.ScanPath,
            Target = process.ScanPath,
        };
        try
        {
            NativeResponseActionResult? result = await ResponseActionService.ConfirmAsync(
                XamlRoot, request, title, explanation, buttonText);
            if (result is not null)
            {
                await ResponseActionService.ShowResultAsync(XamlRoot, result);
            }
        }
        catch (Exception error)
        {
            await ResponseActionService.ShowErrorAsync(XamlRoot, "Response failed safely", error);
        }
    }
}
