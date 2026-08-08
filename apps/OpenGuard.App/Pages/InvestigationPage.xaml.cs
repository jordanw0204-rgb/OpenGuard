using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using OpenGuard.App.Services;
using OpenGuard.App.ViewModels;
using Windows.System;

namespace OpenGuard.App.Pages;

public sealed partial class InvestigationPage : Page
{
    public InvestigationViewModel ViewModel { get; } = InvestigationViewModel.Instance;

    public InvestigationPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await ViewModel.RefreshTimelineAsync(null, null);
        await ViewModel.RefreshPersistenceAsync(false);
    }

    private async void OnRefreshTimeline(object sender, RoutedEventArgs e) =>
        await ViewModel.RefreshTimelineAsync(TimelineSearch.Text, SelectedCategory());

    private async void OnLoadOlder(object sender, RoutedEventArgs e) =>
        await ViewModel.LoadOlderAsync(TimelineSearch.Text, SelectedCategory());

    private async void OnSearchKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            await ViewModel.RefreshTimelineAsync(TimelineSearch.Text, SelectedCategory());
        }
    }

    private async void OnRefreshPersistence(object sender, RoutedEventArgs e) =>
        await ViewModel.RefreshPersistenceAsync(true);

    private async void OnDisablePersistence(object sender, RoutedEventArgs e)
    {
        PersistenceItemViewModel? selected = ViewModel.SelectedPersistence;
        if (selected is null)
        {
            return;
        }
        try
        {
            NativeResponseActionResult? result = await ResponseActionService.ConfirmAsync(
                XamlRoot,
                EmptyRequest("disable_persistence") with { PersistenceId = selected.Id, Target = selected.Name },
                $"Disable {selected.Name}?",
                "This disables the service or scheduled-task startup registration without deleting it. OpenGuard records rollback data.",
                "Disable startup");
            if (result is not null)
            {
                ViewModel.ApplyResponseResult(result);
                await Task.WhenAll(ViewModel.RefreshPersistenceAsync(true), ViewModel.RefreshTimelineAsync(null, null));
            }
        }
        catch (Exception error)
        {
            ViewModel.PersistenceStatus = $"Disable failed safely: {error.Message}";
        }
    }

    private async void OnRestorePersistence(object sender, RoutedEventArgs e)
    {
        try
        {
            NativeResponseActionResult? result = await ResponseActionService.ConfirmAsync(
                XamlRoot,
                EmptyRequest("restore_persistence") with { RollbackId = ViewModel.LastRollbackId },
                "Restore the last startup change?",
                "This re-enables the service or scheduled task using its recorded prior startup state.",
                "Restore startup");
            if (result is not null)
            {
                ViewModel.ApplyResponseResult(result);
                await Task.WhenAll(ViewModel.RefreshPersistenceAsync(true), ViewModel.RefreshTimelineAsync(null, null));
            }
        }
        catch (Exception error)
        {
            ViewModel.PersistenceStatus = $"Restore failed safely: {error.Message}";
        }
    }

    private string? SelectedCategory() =>
        (CategoryFilter.SelectedItem as ComboBoxItem)?.Tag?.ToString();

    internal static NativeResponseActionRequest EmptyRequest(string action) =>
        new(action, null, string.Empty, string.Empty, string.Empty, null, string.Empty, string.Empty, string.Empty);
}
