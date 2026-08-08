using System.Diagnostics;
using System.Runtime.InteropServices;
using Windows.ApplicationModel.DataTransfer;

namespace OpenGuard.App.Services;

internal static class ProcessActions
{
    internal static void OpenFileLocation(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"/select,\"{path}\"",
                UseShellExecute = true,
            });
        }
        catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // A process may exit or its file may disappear between snapshot and invocation.
        }
    }

    internal static void SearchWeb(string application)
    {
        string query = Uri.EscapeDataString($"{application} Windows process security");
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = $"https://www.google.com/search?q={query}",
                UseShellExecute = true,
            });
        }
        catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // The default browser can be unavailable or blocked by local policy.
        }
    }

    internal static void CopyText(string text)
    {
        try
        {
            DataPackage package = new();
            package.SetText(text);
            Clipboard.SetContent(package);
            Clipboard.Flush();
        }
        catch (Exception error) when (error is UnauthorizedAccessException or InvalidOperationException or COMException)
        {
            // Clipboard ownership may be denied temporarily by the foreground application.
        }
    }
}
