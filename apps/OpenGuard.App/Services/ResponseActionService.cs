using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace OpenGuard.App.Services;

internal static class ResponseActionService
{
    internal static async Task<NativeResponseActionResult?> ConfirmAsync(
        XamlRoot xamlRoot,
        NativeResponseActionRequest request,
        string title,
        string explanation,
        string buttonText)
    {
        ContentDialog dialog = new()
        {
            XamlRoot = xamlRoot,
            Title = title,
            Content = new TextBlock
            {
                Text = $"{explanation}\n\nTarget: {DisplayTarget(request)}\n\nOpenGuard will audit this action. It will not run automatically.",
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 560,
            },
            PrimaryButtonText = buttonText,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return null;
        }
        string confirmation = $"confirm:{request.Action}";
        return await new NativeServiceClient().ExecuteResponseAsync(
            request with { Confirmation = confirmation },
            CancellationToken.None);
    }

    internal static async Task ShowResultAsync(XamlRoot xamlRoot, NativeResponseActionResult result)
    {
        ContentDialog dialog = new()
        {
            XamlRoot = xamlRoot,
            Title = "Response completed",
            Content = new TextBlock
            {
                Text = $"{result.Outcome}\n\nAudit event: {result.AuditEventId:N0}" +
                    (result.ExpiresAt is null ? string.Empty : $"\nExpires: {FormatTimestamp(result.ExpiresAt)}"),
                TextWrapping = TextWrapping.Wrap,
            },
            CloseButtonText = "Done",
        };
        await dialog.ShowAsync();
    }

    internal static async Task ShowErrorAsync(XamlRoot xamlRoot, string title, Exception error)
    {
        ContentDialog dialog = new()
        {
            XamlRoot = xamlRoot,
            Title = title,
            Content = new TextBlock { Text = error.Message, TextWrapping = TextWrapping.Wrap },
            CloseButtonText = "Close",
        };
        await dialog.ShowAsync();
    }

    private static string DisplayTarget(NativeResponseActionRequest request)
    {
        if (request.ProcessId is uint pid)
        {
            return $"PID {pid:N0} · {request.ExpectedPath}";
        }
        if (!string.IsNullOrWhiteSpace(request.RemoteAddress))
        {
            return request.RemoteAddress;
        }
        return string.IsNullOrWhiteSpace(request.Target) ? request.PersistenceId : request.Target;
    }

    private static string FormatTimestamp(string timestamp) =>
        timestamp.StartsWith("unix:", StringComparison.Ordinal) &&
        long.TryParse(timestamp.AsSpan(5), out long seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds).ToLocalTime().ToString("g")
            : timestamp;
}
