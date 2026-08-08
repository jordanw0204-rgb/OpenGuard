using Microsoft.Win32;
using OpenGuard.App.ViewModels;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace OpenGuard.App.Services;

internal sealed record PersistenceEvidence(string Source, string Name, string Command);

internal sealed record ProcessInvestigationReport(
    string Application,
    uint Pid,
    string Path,
    string Sha256,
    string Signature,
    string Identity,
    string BaselineStatus,
    string Risk,
    string Parent,
    string Children,
    uint ThreadCount,
    string ResourceUsage,
    string NetworkSummary,
    IReadOnlyList<string> Destinations,
    IReadOnlyList<PersistenceEvidence> Persistence,
    IReadOnlyList<string> Evidence)
{
    internal string ToReportText()
    {
        StringBuilder text = new();
        text.AppendLine($"OpenGuard investigation: {Application}");
        text.AppendLine($"PID: {Pid}");
        text.AppendLine($"Path: {Path}");
        text.AppendLine($"SHA-256: {Sha256}");
        text.AppendLine($"Signature: {Signature}");
        text.AppendLine($"Identity: {Identity}");
        text.AppendLine($"Baseline: {BaselineStatus}");
        text.AppendLine($"Risk: {Risk}");
        text.AppendLine($"Parent: {Parent}");
        text.AppendLine($"Children: {Children}");
        text.AppendLine($"Threads: {ThreadCount}");
        text.AppendLine($"Resources: {ResourceUsage}");
        text.AppendLine($"Network: {NetworkSummary}");
        foreach (string destination in Destinations)
        {
            text.AppendLine($"  Destination: {destination}");
        }
        foreach (PersistenceEvidence entry in Persistence)
        {
            text.AppendLine($"  Persistence: {entry.Source} / {entry.Name} / {entry.Command}");
        }
        foreach (string signal in Evidence)
        {
            text.AppendLine($"  Evidence: {signal}");
        }
        return text.ToString().TrimEnd();
    }
}

internal static class ProcessInvestigationService
{
    private static readonly string[] StartupRegistryPaths =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    internal static async Task<ProcessInvestigationReport> BuildAsync(
        ProcessRow selected,
        IReadOnlyList<ProcessRow> processes,
        IReadOnlyList<NetworkRow> endpoints,
        CancellationToken cancellationToken)
    {
        Task<string> hashTask = HashExecutableAsync(selected.ScanPath, cancellationToken);
        Task<IReadOnlyList<PersistenceEvidence>> persistenceTask = Task.Run(
            () => FindPersistence(selected.ScanPath, selected.Application), cancellationToken);

        ProcessRow? parent = processes.FirstOrDefault(process => process.PidValue == selected.ParentPidValue);
        string parentText = selected.ParentPidValue == 0
            ? "No parent reported"
            : parent is null
                ? $"PID {selected.ParentPidValue} (no longer running or protected)"
                : $"{parent.Application} · PID {parent.PidValue} · {parent.Trust}";
        string[] children = processes
            .Where(process => process.ParentPidValue == selected.PidValue)
            .OrderBy(process => process.Application, StringComparer.OrdinalIgnoreCase)
            .Select(process => $"{process.Application} ({process.PidValue})")
            .Take(12)
            .ToArray();
        NetworkRow[] connections = endpoints
            .Where(endpoint => endpoint.ProcessId == selected.PidValue)
            .ToArray();
        string[] destinations = connections
            .Where(endpoint => !endpoint.Destination.StartsWith("Destination not", StringComparison.Ordinal))
            .Select(endpoint => $"{endpoint.Destination} · {endpoint.Protocol} · {endpoint.Reputation} · ↓ {endpoint.Download} · ↑ {endpoint.Upload}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(24)
            .ToArray();

        IReadOnlyList<PersistenceEvidence> persistence = await persistenceTask;
        List<string> evidence = [.. selected.RiskReasons];
        if (persistence.Count > 0)
        {
            evidence.Add("Persistence: executable is referenced by a common Windows startup entry");
        }
        if (connections.Any(endpoint => endpoint.Reputation.Equals("malicious", StringComparison.OrdinalIgnoreCase)))
        {
            evidence.Add("Network: an active destination is locally classified as malicious");
        }
        else if (connections.Any(endpoint => endpoint.Reputation.Equals("suspicious", StringComparison.OrdinalIgnoreCase)))
        {
            evidence.Add("Network: an active destination is locally classified as suspicious");
        }
        if (evidence.Count == 0)
        {
            evidence.Add("No heuristic or correlated evidence currently requires review");
        }

        double download = connections.Sum(endpoint => endpoint.DownloadBps);
        double upload = connections.Sum(endpoint => endpoint.UploadBps);
        return new ProcessInvestigationReport(
            selected.Application,
            selected.PidValue,
            selected.Path,
            await hashTask,
            selected.Trust,
            string.IsNullOrWhiteSpace(selected.Identity) ? "Unavailable" : selected.Identity,
            selected.IsNew ? "New executable identity" : "Previously observed executable identity",
            selected.Risk,
            parentText,
            children.Length == 0 ? "No running children" : string.Join(", ", children),
            selected.ThreadCount,
            $"CPU {selected.Cpu} · memory {selected.Memory}",
            $"{connections.Length:N0} active records · ↓ {ShellViewModel.FormatRate(download)} · ↑ {ShellViewModel.FormatRate(upload)}",
            destinations,
            persistence,
            evidence.Distinct(StringComparer.Ordinal).ToArray());
    }

    private static async Task<string> HashExecutableAsync(string path, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return "Unavailable";
        }
        try
        {
            await using FileStream stream = new(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                1024 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken);
            return Convert.ToHexStringLower(hash);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException)
        {
            return $"Unavailable ({error.Message})";
        }
    }

    private static IReadOnlyList<PersistenceEvidence> FindPersistence(string path, string application)
    {
        List<PersistenceEvidence> results = [];
        foreach (RegistryHive hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                foreach (string keyPath in StartupRegistryPaths)
                {
                    CollectRegistryEntries(hive, view, keyPath, path, application, results);
                }
            }
        }
        CollectStartupFolder(Environment.SpecialFolder.Startup, "Current user Startup folder", path, application, results);
        CollectStartupFolder(Environment.SpecialFolder.CommonStartup, "All users Startup folder", path, application, results);
        return results
            .DistinctBy(entry => $"{entry.Source}|{entry.Name}|{entry.Command}", StringComparer.OrdinalIgnoreCase)
            .OrderBy(entry => entry.Source, StringComparer.OrdinalIgnoreCase)
            .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static void CollectRegistryEntries(
        RegistryHive hive,
        RegistryView view,
        string keyPath,
        string path,
        string application,
        ICollection<PersistenceEvidence> results)
    {
        try
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
            using RegistryKey? key = baseKey.OpenSubKey(keyPath, writable: false);
            if (key is null)
            {
                return;
            }
            foreach (string valueName in key.GetValueNames())
            {
                string command = key.GetValue(valueName)?.ToString() ?? string.Empty;
                if (MatchesProcess(command, path, application))
                {
                    results.Add(new PersistenceEvidence(
                        $"{hive} {view}\\{keyPath}",
                        string.IsNullOrWhiteSpace(valueName) ? "(default)" : valueName,
                        command));
                }
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException)
        {
            // Registry visibility varies by token and policy; other locations remain useful.
        }
    }

    private static void CollectStartupFolder(
        Environment.SpecialFolder folder,
        string source,
        string path,
        string application,
        ICollection<PersistenceEvidence> results)
    {
        try
        {
            string directory = Environment.GetFolderPath(folder);
            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            {
                return;
            }
            foreach (string entry in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
            {
                if (MatchesProcess(Path.GetFileName(entry), path, application))
                {
                    results.Add(new PersistenceEvidence(source, Path.GetFileName(entry), entry));
                }
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException)
        {
            // Startup folders can be redirected or access controlled.
        }
    }

    private static bool MatchesProcess(string candidate, string path, string application)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }
        string normalized = candidate.Replace('/', '\\');
        if (!string.IsNullOrWhiteSpace(path)
            && normalized.Contains(path.Replace('/', '\\'), StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        string executable = Path.GetFileName(path);
        return (!string.IsNullOrWhiteSpace(executable)
                && normalized.Contains(executable, StringComparison.OrdinalIgnoreCase))
            || (!string.IsNullOrWhiteSpace(application)
                && normalized.Contains(application, StringComparison.OrdinalIgnoreCase));
    }
}
