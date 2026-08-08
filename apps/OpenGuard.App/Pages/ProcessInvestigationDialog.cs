using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using OpenGuard.App.Services;

namespace OpenGuard.App.Pages;

internal sealed class ProcessInvestigationDialog : ContentDialog
{
    internal ProcessInvestigationDialog(ProcessInvestigationReport report)
    {
        Title = $"Investigate {report.Application}";
        PrimaryButtonText = "Copy report";
        SecondaryButtonText = File.Exists(report.Path) ? "Open file location" : string.Empty;
        CloseButtonText = "Close";
        DefaultButton = ContentDialogButton.Close;
        MinWidth = 720;
        PrimaryButtonClick += (_, _) => ProcessActions.CopyText(report.ToReportText());
        SecondaryButtonClick += (_, _) => ProcessActions.OpenFileLocation(report.Path);

        StackPanel content = new() { Spacing = 12 };
        content.Children.Add(Header(report));
        content.Children.Add(Section("IDENTITY", Details(
            ("Executable", report.Path),
            ("SHA-256", report.Sha256),
            ("Signature", report.Signature),
            ("Identity", report.Identity),
            ("Baseline", report.BaselineStatus))));
        content.Children.Add(Section("PROCESS TREE", Details(
            ("Parent", report.Parent),
            ("Children", report.Children),
            ("Threads", report.ThreadCount.ToString("N0")),
            ("Resources", report.ResourceUsage))));
        content.Children.Add(Section("NETWORK", TextList(report.NetworkSummary, report.Destinations)));
        content.Children.Add(Section(
            "STARTUP PERSISTENCE",
            report.Persistence.Count == 0
                ? TextList("No matching Run, RunOnce, or Startup-folder entry was found.", [])
                : TextList(
                    $"{report.Persistence.Count:N0} matching common startup entries",
                    report.Persistence.Select(entry => $"{entry.Source} · {entry.Name}\n{entry.Command}").ToArray())));
        content.Children.Add(Section("EXPLAINABLE EVIDENCE", TextList(report.Risk, report.Evidence)));

        Content = new ScrollViewer
        {
            MaxHeight = 640,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Content = content,
        };
    }

    private static UIElement Header(ProcessInvestigationReport report)
    {
        Grid grid = new() { ColumnSpacing = 16 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        StackPanel identity = new() { Spacing = 3 };
        identity.Children.Add(new TextBlock
        {
            Text = report.Application,
            FontSize = 22,
            FontWeight = new Windows.UI.Text.FontWeight { Weight = 600 },
        });
        identity.Children.Add(new TextBlock
        {
            Text = $"PID {report.Pid} · {report.Signature} · {report.BaselineStatus}",
            Foreground = ResourceBrush("OpenGuardMutedBrush"),
        });
        Border risk = new()
        {
            Padding = new Thickness(12, 7, 12, 7),
            CornerRadius = new CornerRadius(16),
            BorderThickness = new Thickness(1),
            BorderBrush = ResourceBrush("OpenGuardWarningBrush"),
            Child = new TextBlock
            {
                Text = report.Risk,
                FontFamily = new FontFamily("Cascadia Mono"),
                Foreground = ResourceBrush("OpenGuardWarningBrush"),
            },
        };
        Grid.SetColumn(risk, 1);
        grid.Children.Add(identity);
        grid.Children.Add(risk);
        return grid;
    }

    private static UIElement Section(string title, UIElement body)
    {
        StackPanel panel = new() { Spacing = 9 };
        panel.Children.Add(new TextBlock
        {
            Text = title,
            FontFamily = new FontFamily("Cascadia Mono"),
            FontSize = 11,
            CharacterSpacing = 110,
            Foreground = ResourceBrush("OpenGuardMutedBrush"),
        });
        panel.Children.Add(body);
        return new Border
        {
            Padding = new Thickness(14),
            CornerRadius = new CornerRadius(10),
            Background = ResourceBrush("OpenGuardSurfaceBrush"),
            BorderBrush = ResourceBrush("OpenGuardBorderBrush"),
            BorderThickness = new Thickness(1),
            Child = panel,
        };
    }

    private static UIElement Details(params (string Label, string Value)[] rows)
    {
        Grid grid = new() { ColumnSpacing = 18, RowSpacing = 7 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(110) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (int index = 0; index < rows.Length; index++)
        {
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            TextBlock label = new()
            {
                Text = rows[index].Label,
                Foreground = ResourceBrush("OpenGuardMutedBrush"),
            };
            TextBlock value = new()
            {
                Text = rows[index].Value,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true,
            };
            Grid.SetRow(label, index);
            Grid.SetRow(value, index);
            Grid.SetColumn(value, 1);
            grid.Children.Add(label);
            grid.Children.Add(value);
        }
        return grid;
    }

    private static UIElement TextList(string summary, IReadOnlyList<string> items)
    {
        StackPanel panel = new() { Spacing = 6 };
        panel.Children.Add(new TextBlock { Text = summary, TextWrapping = TextWrapping.Wrap });
        foreach (string item in items)
        {
            panel.Children.Add(new TextBlock
            {
                Text = $"• {item}",
                TextWrapping = TextWrapping.Wrap,
                Foreground = ResourceBrush("OpenGuardMutedBrush"),
                IsTextSelectionEnabled = true,
            });
        }
        return panel;
    }

    private static Brush ResourceBrush(string key) =>
        (Brush)Application.Current.Resources[key];
}
