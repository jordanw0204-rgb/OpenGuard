using CommunityToolkit.Mvvm.ComponentModel;
using OpenGuard.App.Services;
using System.Collections.ObjectModel;
using System.Globalization;

namespace OpenGuard.App.ViewModels;

public enum ProcessSortColumn
{
    Application,
    Pid,
    Cpu,
    Memory,
    Trust,
    Risk,
}

public enum NetworkSortColumn
{
    Application,
    Download,
    Upload,
    Destination,
    Reputation,
    Protocol,
}

public partial class ShellViewModel : ObservableObject
{
    private const int MaximumHistorySamples = 90;
    private readonly NativeServiceClient serviceClient = new();
    private readonly Dictionary<uint, ProcessRow> processRows = [];
    private readonly Dictionary<string, NetworkRow> networkRows = [];
    private int refreshRunning;
    private IReadOnlyList<ProcessRow> allProcesses = [];
    private IReadOnlyList<NetworkRow> allNetworkEndpoints = [];
    private string processQuery = string.Empty;
    private int processRiskFilter;
    private string networkQuery = string.Empty;
    private int networkProtocolFilter;
    private bool processOrderInitialized;
    private bool networkOrderInitialized;

    public static ShellViewModel Instance { get; } = new();

    public ObservableCollection<ProcessRow> Processes { get; } = [];

    public ObservableCollection<NetworkRow> NetworkEndpoints { get; } = [];

    public ObservableCollection<double> ProcessCpuHistory { get; } = [];

    public ObservableCollection<double> ProcessMemoryHistory { get; } = [];

    public ObservableCollection<double> NetworkDownloadHistory { get; } = [];

    public ObservableCollection<double> NetworkUploadHistory { get; } = [];

    public ProcessSortColumn ActiveProcessSortColumn { get; private set; } = ProcessSortColumn.Cpu;

    public bool ProcessSortDescending { get; private set; } = true;

    public NetworkSortColumn ActiveNetworkSortColumn { get; private set; } = NetworkSortColumn.Download;

    public bool NetworkSortDescending { get; private set; } = true;

    [ObservableProperty]
    public partial string ServiceStatus { get; set; } = "Checking native service…";

    [ObservableProperty]
    public partial string ServiceHeadline { get; set; } = "Connecting to native engine";

    [ObservableProperty]
    public partial string ServiceBadgeText { get; set; } = "CONNECTING";

    [ObservableProperty]
    public partial string ProcessCountText { get; set; } = "—";

    [ObservableProperty]
    public partial string ConnectionCountText { get; set; } = "—";

    [ObservableProperty]
    public partial string EventCountText { get; set; } = "0";

    [ObservableProperty]
    public partial string TransferRateText { get; set; } = "—";

    [ObservableProperty]
    public partial string DownloadRateText { get; set; } = "↓ —";

    [ObservableProperty]
    public partial string UploadRateText { get; set; } = "↑ —";

    [ObservableProperty]
    public partial string ProcessCpuValueText { get; set; } = "0.0% total";

    [ObservableProperty]
    public partial string ProcessMemoryValueText { get; set; } = "0 B working set";

    [ObservableProperty]
    public partial string ProcessSortText { get; set; } = "CPU · high to low";

    [ObservableProperty]
    public partial string NetworkSortText { get; set; } = "Download · high to low";

    [ObservableProperty]
    public partial string ProcessCoverageText { get; set; } = "PENDING";

    [ObservableProperty]
    public partial string NetworkCoverageText { get; set; } = "PENDING";

    [ObservableProperty]
    public partial string ContentCoverageText { get; set; } = "LIMITED";

    public async Task RefreshServiceStatusAsync() =>
        await RefreshSnapshotAsync(CancellationToken.None);

    public async Task RefreshSnapshotAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref refreshRunning, 1) != 0)
        {
            return;
        }
        try
        {
            NativeSnapshot snapshot = await serviceClient.GetSnapshotAsync(cancellationToken);
            ReconcileProcesses(snapshot.Processes);
            ReconcileNetworkEndpoints(snapshot.Endpoints);
            RefreshProcessMembership();
            RefreshNetworkMembership();

            double processCpu = Math.Clamp(snapshot.Processes.Sum(process => (double)process.CpuPercent), 0, 100);
            double processMemory = snapshot.Processes.Sum(process => (double)process.WorkingSetBytes);
            double download = snapshot.Endpoints.Sum(endpoint => endpoint.ReceiveRateBps ?? 0);
            double upload = snapshot.Endpoints.Sum(endpoint => endpoint.SendRateBps ?? 0);
            AppendSample(ProcessCpuHistory, processCpu);
            AppendSample(ProcessMemoryHistory, processMemory);
            AppendSample(NetworkDownloadHistory, download);
            AppendSample(NetworkUploadHistory, upload);

            int activeConnections = snapshot.Endpoints.Count(endpoint => endpoint.RemotePort > 0);
            ProcessCountText = snapshot.Processes.Count.ToString("N0", CultureInfo.CurrentCulture);
            ConnectionCountText = activeConnections.ToString("N0", CultureInfo.CurrentCulture);
            TransferRateText = FormatRate(download + upload);
            DownloadRateText = $"↓ {FormatRate(download)}";
            UploadRateText = $"↑ {FormatRate(upload)}";
            ProcessCpuValueText = $"{processCpu:N1}% total";
            ProcessMemoryValueText = $"{FormatBytes(processMemory)} working set";
            ProcessCoverageText = CoverageLabel(snapshot.Coverage, "process_snapshot");
            NetworkCoverageText = CoverageLabel(snapshot.Coverage, "network_snapshot");
            ContentCoverageText = CoverageLabel(snapshot.Coverage, "content_engine");
            ServiceHeadline = "Native engine online";
            ServiceBadgeText = snapshot.Elevated ? "FULL SERVICE" : "LIMITED MODE";
            ServiceStatus = snapshot.Elevated
                ? "Native service online · elevated collection"
                : "Native service online · TCP counters need elevation";
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            SetOffline("Native service is not responding");
        }
        catch (TimeoutException)
        {
            SetOffline("Native service is not responding");
        }
        catch (IOException)
        {
            SetOffline("Native service is offline");
        }
        catch (UnauthorizedAccessException)
        {
            SetOffline("Native service denied this session");
        }
        catch (Exception error) when (error is NativeServiceException or System.Text.Json.JsonException)
        {
            SetOffline(error.Message);
        }
        finally
        {
            Interlocked.Exchange(ref refreshRunning, 0);
        }
    }

    public void FilterProcesses(string query, int riskFilter)
    {
        processQuery = query.Trim();
        processRiskFilter = riskFilter;
        ApplyProcessFilter();
    }

    public void FilterNetwork(string query, int protocolFilter)
    {
        networkQuery = query.Trim();
        networkProtocolFilter = protocolFilter;
        ApplyNetworkFilter();
    }

    public void SortProcesses(ProcessSortColumn column)
    {
        if (ActiveProcessSortColumn == column)
        {
            ProcessSortDescending = !ProcessSortDescending;
        }
        else
        {
            ActiveProcessSortColumn = column;
            ProcessSortDescending = column is not ProcessSortColumn.Application and not ProcessSortColumn.Trust;
        }
        ProcessSortText = $"{ActiveProcessSortColumn} · {(ProcessSortDescending ? "high to low" : "low to high")}";
        OnPropertyChanged(nameof(ActiveProcessSortColumn));
        OnPropertyChanged(nameof(ProcessSortDescending));
        ApplyProcessFilter();
    }

    public void SortNetwork(NetworkSortColumn column)
    {
        if (ActiveNetworkSortColumn == column)
        {
            NetworkSortDescending = !NetworkSortDescending;
        }
        else
        {
            ActiveNetworkSortColumn = column;
            NetworkSortDescending = column is NetworkSortColumn.Download or NetworkSortColumn.Upload;
        }
        NetworkSortText = $"{ActiveNetworkSortColumn} · {(NetworkSortDescending ? "high to low" : "low to high")}";
        OnPropertyChanged(nameof(ActiveNetworkSortColumn));
        OnPropertyChanged(nameof(NetworkSortDescending));
        ApplyNetworkFilter();
    }

    internal Task<ProcessInvestigationReport> InvestigateProcessAsync(
        ProcessRow process,
        CancellationToken cancellationToken = default) =>
        ProcessInvestigationService.BuildAsync(
            process,
            allProcesses.ToArray(),
            allNetworkEndpoints.ToArray(),
            cancellationToken);

    internal ProcessRow? FindProcess(uint pid) =>
        processRows.GetValueOrDefault(pid);

    private void ReconcileProcesses(IReadOnlyList<NativeProcess> processes)
    {
        HashSet<uint> seen = [];
        foreach (NativeProcess process in processes)
        {
            seen.Add(process.Pid);
            if (processRows.TryGetValue(process.Pid, out ProcessRow? row))
            {
                row.Update(process);
            }
            else
            {
                processRows.Add(process.Pid, new ProcessRow(process));
            }
        }
        foreach (uint pid in processRows.Keys.Where(pid => !seen.Contains(pid)).ToArray())
        {
            processRows.Remove(pid);
        }
        allProcesses = processRows.Values.ToArray();
    }

    private void ReconcileNetworkEndpoints(IReadOnlyList<NativeEndpoint> endpoints)
    {
        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach (NativeEndpoint endpoint in endpoints.Where(endpoint =>
                     endpoint.RemotePort > 0 || endpoint.Protocol.StartsWith("UDP", StringComparison.Ordinal)))
        {
            string key = NetworkRow.KeyFor(endpoint);
            seen.Add(key);
            if (networkRows.TryGetValue(key, out NetworkRow? row))
            {
                row.Update(endpoint);
            }
            else
            {
                networkRows.Add(key, new NetworkRow(key, endpoint));
            }
        }
        foreach (string key in networkRows.Keys.Where(key => !seen.Contains(key)).ToArray())
        {
            networkRows.Remove(key);
        }
        allNetworkEndpoints = networkRows.Values.ToArray();
    }

    private void ApplyProcessFilter()
    {
        IEnumerable<ProcessRow> filtered = FilteredProcesses();
        IOrderedEnumerable<ProcessRow> sorted = (ActiveProcessSortColumn, ProcessSortDescending) switch
        {
            (ProcessSortColumn.Application, true) => filtered.OrderByDescending(item => item.Application, StringComparer.OrdinalIgnoreCase),
            (ProcessSortColumn.Application, false) => filtered.OrderBy(item => item.Application, StringComparer.OrdinalIgnoreCase),
            (ProcessSortColumn.Pid, true) => filtered.OrderByDescending(item => item.PidValue),
            (ProcessSortColumn.Pid, false) => filtered.OrderBy(item => item.PidValue),
            (ProcessSortColumn.Cpu, true) => filtered.OrderByDescending(item => item.CpuValue),
            (ProcessSortColumn.Cpu, false) => filtered.OrderBy(item => item.CpuValue),
            (ProcessSortColumn.Memory, true) => filtered.OrderByDescending(item => item.MemoryBytes),
            (ProcessSortColumn.Memory, false) => filtered.OrderBy(item => item.MemoryBytes),
            (ProcessSortColumn.Trust, true) => filtered.OrderByDescending(item => item.Trust, StringComparer.OrdinalIgnoreCase),
            (ProcessSortColumn.Trust, false) => filtered.OrderBy(item => item.Trust, StringComparer.OrdinalIgnoreCase),
            (ProcessSortColumn.Risk, true) => filtered.OrderByDescending(item => item.RiskScore),
            _ => filtered.OrderBy(item => item.RiskScore),
        };
        SynchronizeCollection(Processes, sorted.ThenBy(item => item.Application, StringComparer.OrdinalIgnoreCase).ToArray());
        processOrderInitialized = true;
    }

    private IEnumerable<ProcessRow> FilteredProcesses()
    {
        IEnumerable<ProcessRow> filtered = allProcesses;
        if (!string.IsNullOrWhiteSpace(processQuery))
        {
            filtered = filtered.Where(item =>
                item.Application.Contains(processQuery, StringComparison.OrdinalIgnoreCase) ||
                item.Pid.Contains(processQuery, StringComparison.OrdinalIgnoreCase) ||
                item.Path.Contains(processQuery, StringComparison.OrdinalIgnoreCase) ||
                item.Trust.Contains(processQuery, StringComparison.OrdinalIgnoreCase) ||
                item.RiskDetail.Contains(processQuery, StringComparison.OrdinalIgnoreCase));
        }
        filtered = processRiskFilter switch
        {
            1 => filtered.Where(item => item.RiskScore >= 15),
            2 => filtered.Where(item => item.IsNew),
            _ => filtered,
        };
        return filtered;
    }

    private void ApplyNetworkFilter()
    {
        IEnumerable<NetworkRow> filtered = FilteredNetworkEndpoints();
        IOrderedEnumerable<NetworkRow> sorted = (ActiveNetworkSortColumn, NetworkSortDescending) switch
        {
            (NetworkSortColumn.Application, true) => filtered.OrderByDescending(item => item.Application, StringComparer.OrdinalIgnoreCase),
            (NetworkSortColumn.Application, false) => filtered.OrderBy(item => item.Application, StringComparer.OrdinalIgnoreCase),
            (NetworkSortColumn.Download, true) => filtered.OrderByDescending(item => item.DownloadBps),
            (NetworkSortColumn.Download, false) => filtered.OrderBy(item => item.DownloadBps),
            (NetworkSortColumn.Upload, true) => filtered.OrderByDescending(item => item.UploadBps),
            (NetworkSortColumn.Upload, false) => filtered.OrderBy(item => item.UploadBps),
            (NetworkSortColumn.Destination, true) => filtered.OrderByDescending(item => item.Destination, StringComparer.OrdinalIgnoreCase),
            (NetworkSortColumn.Destination, false) => filtered.OrderBy(item => item.Destination, StringComparer.OrdinalIgnoreCase),
            (NetworkSortColumn.Reputation, true) => filtered.OrderByDescending(item => item.Reputation, StringComparer.OrdinalIgnoreCase),
            (NetworkSortColumn.Reputation, false) => filtered.OrderBy(item => item.Reputation, StringComparer.OrdinalIgnoreCase),
            (NetworkSortColumn.Protocol, true) => filtered.OrderByDescending(item => item.Protocol, StringComparer.OrdinalIgnoreCase),
            _ => filtered.OrderBy(item => item.Protocol, StringComparer.OrdinalIgnoreCase),
        };
        SynchronizeCollection(NetworkEndpoints, sorted.ThenBy(item => item.Application, StringComparer.OrdinalIgnoreCase).ToArray());
        networkOrderInitialized = true;
    }

    private IEnumerable<NetworkRow> FilteredNetworkEndpoints()
    {
        IEnumerable<NetworkRow> filtered = allNetworkEndpoints;
        if (!string.IsNullOrWhiteSpace(networkQuery))
        {
            filtered = filtered.Where(item =>
                item.Application.Contains(networkQuery, StringComparison.OrdinalIgnoreCase) ||
                item.ProcessDetail.Contains(networkQuery, StringComparison.OrdinalIgnoreCase) ||
                item.Destination.Contains(networkQuery, StringComparison.OrdinalIgnoreCase) ||
                item.DestinationDetail.Contains(networkQuery, StringComparison.OrdinalIgnoreCase) ||
                item.Reputation.Contains(networkQuery, StringComparison.OrdinalIgnoreCase) ||
                item.Protocol.Contains(networkQuery, StringComparison.OrdinalIgnoreCase));
        }
        filtered = networkProtocolFilter switch
        {
            1 => filtered.Where(item => item.Protocol.StartsWith("TCP", StringComparison.Ordinal)),
            2 => filtered.Where(item => item.Protocol.StartsWith("UDP", StringComparison.Ordinal)),
            _ => filtered,
        };
        return filtered;
    }

    private void RefreshProcessMembership()
    {
        if (!processOrderInitialized)
        {
            ApplyProcessFilter();
            return;
        }
        SynchronizeMembership(Processes, FilteredProcesses());
    }

    private void RefreshNetworkMembership()
    {
        if (!networkOrderInitialized)
        {
            ApplyNetworkFilter();
            return;
        }
        SynchronizeMembership(NetworkEndpoints, FilteredNetworkEndpoints());
    }

    private static void SynchronizeCollection<T>(ObservableCollection<T> collection, IReadOnlyList<T> target)
        where T : class
    {
        for (int index = 0; index < target.Count; index++)
        {
            T item = target[index];
            if (index < collection.Count && ReferenceEquals(collection[index], item))
            {
                continue;
            }
            int existingIndex = collection.IndexOf(item);
            if (existingIndex >= 0)
            {
                collection.Move(existingIndex, index);
            }
            else
            {
                collection.Insert(index, item);
            }
        }
        while (collection.Count > target.Count)
        {
            collection.RemoveAt(collection.Count - 1);
        }
    }

    private static void SynchronizeMembership<T>(ObservableCollection<T> collection, IEnumerable<T> candidates)
        where T : class
    {
        IReadOnlyList<T> target = candidates.ToArray();
        HashSet<T> targetSet = new(ReferenceEqualityComparer.Instance);
        targetSet.UnionWith(target);
        for (int index = collection.Count - 1; index >= 0; index--)
        {
            if (!targetSet.Contains(collection[index]))
            {
                collection.RemoveAt(index);
            }
        }
        HashSet<T> visible = new(ReferenceEqualityComparer.Instance);
        visible.UnionWith(collection);
        foreach (T item in target)
        {
            if (visible.Add(item))
            {
                collection.Add(item);
            }
        }
    }

    private static void AppendSample(ObservableCollection<double> history, double value)
    {
        history.Add(double.IsFinite(value) && value >= 0 ? value : 0);
        while (history.Count > MaximumHistorySamples)
        {
            history.RemoveAt(0);
        }
    }

    private void SetOffline(string status)
    {
        ServiceStatus = status;
        ServiceHeadline = "Native engine unavailable";
        ServiceBadgeText = "SERVICE OFFLINE";
        ProcessCoverageText = "OFFLINE";
        NetworkCoverageText = "OFFLINE";
    }

    private static string CoverageLabel(IReadOnlyList<NativeCoverage> coverage, string source)
    {
        string state = coverage.FirstOrDefault(item => item.Source == source)?.State ?? "unknown";
        return state.ToUpperInvariant();
    }

    internal static string FormatBytes(double bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        int unit = 0;
        while (bytes >= 1024 && unit < units.Length - 1)
        {
            bytes /= 1024;
            unit++;
        }
        return unit == 0
            ? $"{bytes:N0} {units[unit]}"
            : $"{bytes:N1} {units[unit]}";
    }

    internal static string FormatRate(double bytesPerSecond) =>
        bytesPerSecond <= 0 ? "0 B/s" : $"{FormatBytes(bytesPerSecond)}/s";
}

public sealed class ProcessRow : ObservableObject
{
    private string application = string.Empty;
    private string path = string.Empty;
    private string pid = string.Empty;
    private string cpu = string.Empty;
    private string memory = string.Empty;
    private string trust = string.Empty;
    private string risk = string.Empty;
    private string riskDetail = string.Empty;
    private string scanPath = string.Empty;
    private bool isNew;
    private byte riskScore;
    private double cpuValue;
    private ulong memoryBytes;
    private uint parentPidValue;
    private uint threadCount;
    private string identity = string.Empty;
    private bool accessible;
    private IReadOnlyList<string> riskReasons = [];

    internal ProcessRow(NativeProcess process)
    {
        PidValue = process.Pid;
        Update(process);
    }

    public uint PidValue { get; }

    public string Application { get => application; private set => SetProperty(ref application, value); }

    public string Path { get => path; private set => SetProperty(ref path, value); }

    public string Pid { get => pid; private set => SetProperty(ref pid, value); }

    public string Cpu { get => cpu; private set => SetProperty(ref cpu, value); }

    public string Memory { get => memory; private set => SetProperty(ref memory, value); }

    public string Trust { get => trust; private set => SetProperty(ref trust, value); }

    public string Risk { get => risk; private set => SetProperty(ref risk, value); }

    public string RiskDetail { get => riskDetail; private set => SetProperty(ref riskDetail, value); }

    public string ScanPath
    {
        get => scanPath;
        private set
        {
            if (SetProperty(ref scanPath, value))
            {
                OnPropertyChanged(nameof(HasProcessPath));
            }
        }
    }

    public bool IsNew { get => isNew; private set => SetProperty(ref isNew, value); }

    public byte RiskScore { get => riskScore; private set => SetProperty(ref riskScore, value); }

    public double CpuValue { get => cpuValue; private set => SetProperty(ref cpuValue, value); }

    public ulong MemoryBytes { get => memoryBytes; private set => SetProperty(ref memoryBytes, value); }

    public uint ParentPidValue { get => parentPidValue; private set => SetProperty(ref parentPidValue, value); }

    public uint ThreadCount { get => threadCount; private set => SetProperty(ref threadCount, value); }

    public string Identity { get => identity; private set => SetProperty(ref identity, value); }

    public bool Accessible { get => accessible; private set => SetProperty(ref accessible, value); }

    public IReadOnlyList<string> RiskReasons { get => riskReasons; private set => SetProperty(ref riskReasons, value); }

    public bool HasProcessPath => !string.IsNullOrWhiteSpace(ScanPath);

    public string DetailsText => $"{Application} · PID {Pid} · CPU {Cpu} · Memory {Memory} · Trust {Trust} · Risk {Risk}";

    internal void Update(NativeProcess process)
    {
        string severity = CultureInfo.InvariantCulture.TextInfo.ToTitleCase(process.Risk.Severity);
        Application = string.IsNullOrWhiteSpace(process.Name) ? $"PID {process.Pid}" : process.Name;
        Path = string.IsNullOrWhiteSpace(process.Path) ? "Protected or unavailable" : process.Path;
        Pid = process.Pid.ToString(CultureInfo.InvariantCulture);
        Cpu = $"{process.CpuPercent:N1}%";
        Memory = ShellViewModel.FormatBytes(process.WorkingSetBytes);
        Trust = process.Signature.Replace('_', ' ');
        Risk = $"{severity} · {process.Risk.Score}";
        RiskDetail = process.Risk.Reasons.Count == 0
            ? "No heuristic evidence"
            : string.Join("; ", process.Risk.Reasons);
        ScanPath = process.Path;
        IsNew = process.IsNew;
        RiskScore = process.Risk.Score;
        CpuValue = process.CpuPercent;
        MemoryBytes = process.WorkingSetBytes;
        ParentPidValue = process.ParentPid;
        ThreadCount = process.ThreadCount;
        Identity = process.Identity;
        Accessible = process.Accessible;
        RiskReasons = process.Risk.Reasons.ToArray();
        OnPropertyChanged(nameof(DetailsText));
    }
}

public sealed class NetworkRow : ObservableObject
{
    private string application = string.Empty;
    private string processDetail = string.Empty;
    private string download = string.Empty;
    private string upload = string.Empty;
    private string destination = string.Empty;
    private string destinationDetail = string.Empty;
    private string reputation = string.Empty;
    private string protocol = string.Empty;
    private string usageStatus = string.Empty;
    private string processPath = string.Empty;
    private double downloadBps;
    private double uploadBps;

    internal NetworkRow(string key, NativeEndpoint endpoint)
    {
        Key = key;
        ProcessId = endpoint.Pid;
        Update(endpoint);
    }

    public string Key { get; }

    public uint ProcessId { get; }

    public string Application { get => application; private set => SetProperty(ref application, value); }

    public string ProcessDetail { get => processDetail; private set => SetProperty(ref processDetail, value); }

    public string Download { get => download; private set => SetProperty(ref download, value); }

    public string Upload { get => upload; private set => SetProperty(ref upload, value); }

    public string Destination { get => destination; private set => SetProperty(ref destination, value); }

    public string DestinationDetail { get => destinationDetail; private set => SetProperty(ref destinationDetail, value); }

    public string Reputation { get => reputation; private set => SetProperty(ref reputation, value); }

    public string Protocol { get => protocol; private set => SetProperty(ref protocol, value); }

    public string UsageStatus { get => usageStatus; private set => SetProperty(ref usageStatus, value); }

    public string ProcessPath
    {
        get => processPath;
        private set
        {
            if (SetProperty(ref processPath, value))
            {
                OnPropertyChanged(nameof(HasProcessPath));
            }
        }
    }

    public double DownloadBps { get => downloadBps; private set => SetProperty(ref downloadBps, value); }

    public double UploadBps { get => uploadBps; private set => SetProperty(ref uploadBps, value); }

    public bool HasProcessPath => !string.IsNullOrWhiteSpace(ProcessPath);

    public string ConnectionSummary => $"{Application} · PID {ProcessId} · {Protocol} · {Destination} · ↓ {Download} · ↑ {Upload} · {Reputation}";

    internal static string KeyFor(NativeEndpoint endpoint) =>
        $"{endpoint.Protocol}|{endpoint.Pid}|{endpoint.LocalAddress}|{endpoint.LocalPort}|{endpoint.RemoteAddress}|{endpoint.RemotePort}";

    internal void Update(NativeEndpoint endpoint)
    {
        string host = string.IsNullOrWhiteSpace(endpoint.RemoteHostname)
            ? endpoint.RemoteAddress
            : endpoint.RemoteHostname;
        Application = string.IsNullOrWhiteSpace(endpoint.ProcessName)
            ? $"PID {endpoint.Pid}"
            : endpoint.ProcessName;
        ProcessDetail = $"PID {endpoint.Pid} · {endpoint.UsageStatus.Replace('_', ' ')}";
        Download = endpoint.ReceiveRateBps.HasValue
            ? ShellViewModel.FormatRate(endpoint.ReceiveRateBps.Value)
            : "—";
        Upload = endpoint.SendRateBps.HasValue
            ? ShellViewModel.FormatRate(endpoint.SendRateBps.Value)
            : "—";
        Destination = endpoint.RemotePort == 0
            ? "Destination not exposed"
            : $"{host}:{endpoint.RemotePort}";
        DestinationDetail = endpoint.RemotePort == 0
            ? $"{endpoint.State} on {endpoint.LocalAddress}:{endpoint.LocalPort}"
            : $"{endpoint.State} · local {endpoint.LocalAddress}:{endpoint.LocalPort}";
        Reputation = endpoint.Reputation.Replace('_', ' ');
        Protocol = endpoint.Protocol;
        UsageStatus = endpoint.UsageStatus.Replace('_', ' ');
        ProcessPath = endpoint.ProcessPath;
        DownloadBps = endpoint.ReceiveRateBps ?? 0;
        UploadBps = endpoint.SendRateBps ?? 0;
        OnPropertyChanged(nameof(ConnectionSummary));
    }
}
