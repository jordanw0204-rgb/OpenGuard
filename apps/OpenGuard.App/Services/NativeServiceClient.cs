using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenGuard.App.Services;

internal sealed class NativeServiceClient
{
    private const string PipeName = "OpenGuard.v1";
    private const int ProtocolVersion = 1;
    private const int MaximumFrameBytes = 4 * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public async Task<NativeServiceHealth> GetHealthAsync(CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(new RequestBody("get_health"), TimeSpan.FromMilliseconds(800), cancellationToken);
        EnsureDataType(data, "health");
        return data.GetProperty("value").Deserialize<NativeServiceHealth>(JsonOptions)
            ?? throw new NativeServiceException("Native service returned an empty health response.");
    }

    public async Task<NativeSnapshot> GetSnapshotAsync(CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(new RequestBody("get_snapshot"), TimeSpan.FromSeconds(3), cancellationToken);
        EnsureDataType(data, "snapshot");
        return data.GetProperty("value").Deserialize<NativeSnapshot>(JsonOptions)
            ?? throw new NativeServiceException("Native service returned an empty snapshot.");
    }

    public async Task<IReadOnlyList<NativeSecurityEvent>> GetRecentEventsAsync(
        uint limit,
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("recent_events", new LimitPayload(limit)),
            TimeSpan.FromSeconds(3),
            cancellationToken);
        EnsureDataType(data, "events");
        return data.GetProperty("value").Deserialize<IReadOnlyList<NativeSecurityEvent>>(JsonOptions)
            ?? [];
    }

    public async Task<NativeTimelinePage> GetTimelineAsync(
        long? beforeId,
        uint limit,
        string? category,
        uint? processId,
        string? search,
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody(
                "get_timeline",
                new TimelinePayload(beforeId, limit, category, processId, search)),
            TimeSpan.FromSeconds(5),
            cancellationToken);
        EnsureDataType(data, "timeline");
        return data.GetProperty("value").Deserialize<NativeTimelinePage>(JsonOptions)
            ?? throw new NativeServiceException("Native service returned an empty timeline page.");
    }

    public async Task<NativePersistenceInventory> GetPersistenceAsync(
        bool refresh,
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("get_persistence", new PersistencePayload(refresh)),
            TimeSpan.FromSeconds(25),
            cancellationToken);
        EnsureDataType(data, "persistence");
        return data.GetProperty("value").Deserialize<NativePersistenceInventory>(JsonOptions)
            ?? throw new NativeServiceException("Native service returned an empty persistence inventory.");
    }

    public async Task<NativeResponseActionResult> ExecuteResponseAsync(
        NativeResponseActionRequest request,
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("execute_response", new ExecuteResponsePayload(request)),
            TimeSpan.FromSeconds(45),
            cancellationToken);
        EnsureDataType(data, "response_action");
        return data.GetProperty("value").Deserialize<NativeResponseActionResult>(JsonOptions)
            ?? throw new NativeServiceException("Native service returned an empty response result.");
    }

    public async Task<string> GetStatusTextAsync(CancellationToken cancellationToken)
    {
        try
        {
            NativeServiceHealth health = await GetHealthAsync(cancellationToken);
            return $"Native service online · v{health.Version}";
        }
        catch (OperationCanceledException)
        {
            return "Native service is not responding";
        }
        catch (TimeoutException)
        {
            return "Native service is not responding";
        }
        catch (IOException)
        {
            return "Native service is offline";
        }
        catch (UnauthorizedAccessException)
        {
            return "Native service denied this session";
        }
        catch (JsonException)
        {
            return "Native service returned invalid data";
        }
        catch (NativeServiceException error)
        {
            return error.Message;
        }
    }

    public async Task<string> StartPathScanAsync(string target, CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("start_scan", new StartScanPayload(target, null)),
            TimeSpan.FromSeconds(5),
            cancellationToken);
        EnsureDataType(data, "scan_started");
        return data.GetProperty("value").GetProperty("scan_id").GetString()
            ?? throw new NativeServiceException("Native service returned an empty scan identifier.");
    }

    public async Task<string> StartProfileScanAsync(string profile, CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("start_scan", new StartScanPayload(string.Empty, profile)),
            TimeSpan.FromSeconds(5),
            cancellationToken);
        EnsureDataType(data, "scan_started");
        return data.GetProperty("value").GetProperty("scan_id").GetString()
            ?? throw new NativeServiceException("Native service returned an empty scan identifier.");
    }

    public async Task<NativeScanStatus> GetScanAsync(string scanId, CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("get_scan", new ScanIdPayload(scanId)),
            TimeSpan.FromSeconds(3),
            cancellationToken);
        EnsureDataType(data, "scan_status");
        return data.GetProperty("value").Deserialize<NativeScanStatus>(JsonOptions)
            ?? throw new NativeServiceException("Native service returned an empty scan status.");
    }

    public async Task CancelScanAsync(string scanId, CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("cancel_scan", new ScanIdPayload(scanId)),
            TimeSpan.FromSeconds(3),
            cancellationToken);
        EnsureDataType(data, "scan_cancelled");
    }

    public async Task<NativeQuarantineRecord> QuarantineAsync(
        NativeScanFinding finding,
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("quarantine", new QuarantinePayload(finding)),
            TimeSpan.FromSeconds(30),
            cancellationToken);
        EnsureDataType(data, "quarantine_changed");
        return data.GetProperty("value").Deserialize<NativeQuarantineRecord>(JsonOptions)
            ?? throw new NativeServiceException("Native service returned an empty quarantine record.");
    }

    public async Task<IReadOnlyList<NativeQuarantineRecord>> GetQuarantinesAsync(
        uint limit,
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("list_quarantine", new LimitPayload(limit)),
            TimeSpan.FromSeconds(3),
            cancellationToken);
        EnsureDataType(data, "quarantines");
        return data.GetProperty("value").Deserialize<IReadOnlyList<NativeQuarantineRecord>>(JsonOptions)
            ?? [];
    }

    public async Task<NativeQuarantineRecord> RestoreQuarantineAsync(
        string quarantineId,
        string? destination,
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody(
                "restore_quarantine",
                new RestoreQuarantinePayload(quarantineId, destination)),
            TimeSpan.FromSeconds(30),
            cancellationToken);
        EnsureDataType(data, "quarantine_changed");
        return data.GetProperty("value").Deserialize<NativeQuarantineRecord>(JsonOptions)
            ?? throw new NativeServiceException("Native service returned an empty restore record.");
    }

    public Task<NativeContentStatus> GetContentStatusAsync(CancellationToken cancellationToken) =>
        ContentRequestAsync("get_content_status", TimeSpan.FromSeconds(3), cancellationToken);

    public Task<NativeContentStatus> InstallContentUpdateAsync(CancellationToken cancellationToken) =>
        ContentRequestAsync("install_content_update", TimeSpan.FromSeconds(45), cancellationToken);

    public Task<NativeContentStatus> RollbackContentUpdateAsync(CancellationToken cancellationToken) =>
        ContentRequestAsync("rollback_content_update", TimeSpan.FromSeconds(10), cancellationToken);

    public async Task<IReadOnlyList<NativeExclusionRecord>> GetExclusionsAsync(
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("list_exclusions"),
            TimeSpan.FromSeconds(3),
            cancellationToken);
        EnsureDataType(data, "exclusions");
        return data.GetProperty("value").Deserialize<IReadOnlyList<NativeExclusionRecord>>(JsonOptions)
            ?? [];
    }

    public Task AddExclusionAsync(string path, bool recursive, CancellationToken cancellationToken) =>
        PolicyMutationAsync(
            "add_exclusion",
            new ExclusionPayload(path, recursive),
            cancellationToken);

    public Task RemoveExclusionAsync(string path, CancellationToken cancellationToken) =>
        PolicyMutationAsync("remove_exclusion", new PathPayload(path), cancellationToken);

    public async Task<IReadOnlyList<NativeAllowedHashRecord>> GetAllowedHashesAsync(
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody("list_allowed_hashes"),
            TimeSpan.FromSeconds(3),
            cancellationToken);
        EnsureDataType(data, "allowed_hashes");
        return data.GetProperty("value").Deserialize<IReadOnlyList<NativeAllowedHashRecord>>(JsonOptions)
            ?? [];
    }

    public Task AllowHashAsync(
        string sha256,
        string label,
        CancellationToken cancellationToken) =>
        PolicyMutationAsync(
            "allow_hash",
            new AllowedHashPayload(sha256, label),
            cancellationToken);

    public Task RemoveAllowedHashAsync(string sha256, CancellationToken cancellationToken) =>
        PolicyMutationAsync("remove_allowed_hash", new HashPayload(sha256), cancellationToken);

    private static async Task PolicyMutationAsync(
        string operation,
        object payload,
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(
            new RequestBody(operation, payload),
            TimeSpan.FromSeconds(5),
            cancellationToken);
        EnsureDataType(data, "policy_changed");
    }

    private async Task<NativeContentStatus> ContentRequestAsync(
        string operation,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        JsonElement data = await SendAsync(new RequestBody(operation), timeout, cancellationToken);
        EnsureDataType(data, "content_status");
        return data.GetProperty("value").Deserialize<NativeContentStatus>(JsonOptions)
            ?? throw new NativeServiceException("Native service returned an empty content status.");
    }

    private static async Task<JsonElement> SendAsync(
        RequestBody requestBody,
        TimeSpan timeoutDuration,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(timeoutDuration);
        using NamedPipeClientStream pipe = new(
            ".",
            PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        try
        {
            await pipe.ConnectAsync(timeout.Token);
            string requestId = Guid.NewGuid().ToString("N");
            await WriteFrameAsync(
                pipe,
                new RequestEnvelope(ProtocolVersion, requestId, requestBody),
                timeout.Token);
            using JsonDocument response = await ReadFrameAsync(pipe, timeout.Token);
            JsonElement root = response.RootElement;
            if (root.GetProperty("protocol").GetInt32() != ProtocolVersion ||
                root.GetProperty("request_id").GetString() != requestId)
            {
                throw new NativeServiceException("Native service protocol mismatch");
            }
            JsonElement body = root.GetProperty("body");
            string status = body.GetProperty("status").GetString() ?? string.Empty;
            if (status == "error")
            {
                JsonElement error = body.GetProperty("error");
                string message = error.GetProperty("message").GetString()
                    ?? "Native service rejected the request.";
                throw new NativeServiceException(message);
            }
            if (status != "success")
            {
                throw new NativeServiceException("Native service returned an unknown status.");
            }
            return body.GetProperty("data").Clone();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("Native service request timed out.");
        }
    }

    private static void EnsureDataType(JsonElement data, string expected)
    {
        if (data.GetProperty("type").GetString() != expected)
        {
            throw new NativeServiceException($"Native service returned the wrong response type for {expected}.");
        }
    }

    private static async Task WriteFrameAsync<T>(
        Stream stream,
        T value,
        CancellationToken cancellationToken)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        if (payload.Length is <= 0 or > MaximumFrameBytes)
        {
            throw new InvalidDataException("IPC frame is outside the allowed size.");
        }
        byte[] header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(payload, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async Task<JsonDocument> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        byte[] header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, cancellationToken);
        int size = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (size is <= 0 or > MaximumFrameBytes)
        {
            throw new InvalidDataException("IPC frame is outside the allowed size.");
        }
        byte[] payload = GC.AllocateUninitializedArray<byte>(size);
        await stream.ReadExactlyAsync(payload, cancellationToken);
        return JsonDocument.Parse(payload);
    }

    private sealed record RequestEnvelope(int Protocol, string RequestId, RequestBody Body);

    private sealed record RequestBody(string Operation, object? Payload = null);

    private sealed record StartScanPayload(string Target, string? Profile);

    private sealed record ScanIdPayload(string ScanId);

    private sealed record QuarantinePayload(NativeScanFinding Finding);

    private sealed record LimitPayload(uint Limit);

    private sealed record TimelinePayload(
        long? BeforeId,
        uint Limit,
        string? Category,
        uint? ProcessId,
        string? Search);

    private sealed record PersistencePayload(bool Refresh);

    private sealed record ExecuteResponsePayload(NativeResponseActionRequest Request);

    private sealed record RestoreQuarantinePayload(string QuarantineId, string? Destination);

    private sealed record ExclusionPayload(string Path, bool Recursive);

    private sealed record PathPayload(string Path);

    private sealed record AllowedHashPayload(string Sha256, string Label);

    private sealed record HashPayload(string Sha256);
}

internal sealed class NativeServiceException(string message) : Exception(message);

internal sealed record NativeServiceHealth(
    string Version,
    int Protocol,
    string ServiceState,
    string DatabaseState,
    string ContentVersion,
    ulong UptimeSeconds,
    IReadOnlyList<NativeCoverage> Coverage);

internal sealed record NativeSnapshot(
    IReadOnlyList<NativeProcess> Processes,
    IReadOnlyList<NativeEndpoint> Endpoints,
    string CapturedAt,
    bool Elevated,
    IReadOnlyList<NativeCoverage> Coverage);

internal sealed record NativeCoverage(string Source, string State, string Detail);

internal sealed record NativeRisk(byte Score, string Severity, IReadOnlyList<string> Reasons);

internal sealed record NativeProcess(
    uint Pid,
    uint ParentPid,
    string Name,
    string Path,
    uint ThreadCount,
    ulong WorkingSetBytes,
    float CpuPercent,
    string Signature,
    bool Accessible,
    string Identity,
    bool IsNew,
    NativeRisk Risk);

internal sealed record NativeEndpoint(
    string Protocol,
    string LocalAddress,
    ushort LocalPort,
    string RemoteAddress,
    ushort RemotePort,
    string State,
    uint Pid,
    string ProcessName,
    string ProcessPath,
    string RemoteHostname,
    string Reputation,
    string ReputationReason,
    ulong? BytesSent,
    ulong? BytesReceived,
    double? SendRateBps,
    double? ReceiveRateBps,
    string UsageStatus);

internal sealed record NativeScanStatus(
    string ScanId,
    string Target,
    string State,
    NativeScanFinding? Finding,
    IReadOnlyList<NativeScanFinding> Findings,
    ulong FilesScanned,
    ulong TotalFiles,
    string CurrentPath,
    string? Error);

internal sealed record NativeScanFinding(
    string Path,
    string Verdict,
    byte Score,
    IReadOnlyList<string> Reasons,
    string Sha256,
    ulong SizeBytes,
    string Signature,
    string AmsiResult,
    string YaraStatus,
    IReadOnlyList<string> YaraMatches,
    IReadOnlyList<NativeThreatCapability> Capabilities,
    string ScannedAt);

internal sealed record NativeThreatCapability(
    string Category,
    string MitreTechnique,
    byte Confidence,
    IReadOnlyList<string> Evidence);

internal sealed record NativeQuarantineRecord(
    string Id,
    string OriginalPath,
    string Sha256,
    string Reason,
    string CreatedAt,
    string? RestoredAt,
    string? RestoredPath);

internal sealed record NativeSecurityEvent(
    long? Id,
    string EventType,
    string Severity,
    string Title,
    string Detail,
    uint? ProcessId,
    string Path,
    string CreatedAt,
    bool Resolved);

internal sealed record NativeTimelineEvent(
    long? Id,
    string Category,
    string Action,
    string Severity,
    string Title,
    string Detail,
    uint? ProcessId,
    string Path,
    string RemoteAddress,
    string CorrelationId,
    string OccurredAt);

internal sealed record NativeTimelinePage(
    IReadOnlyList<NativeTimelineEvent> Events,
    long? NextBeforeId);

internal sealed record NativePersistenceItem(
    string Id,
    string Category,
    string Name,
    string Command,
    string Location,
    string State,
    string Risk,
    IReadOnlyList<string> Evidence,
    string DetectedAt,
    string ResponseCapability);

internal sealed record NativePersistenceInventory(
    IReadOnlyList<NativePersistenceItem> Items,
    string CollectedAt,
    IReadOnlyList<NativeCoverage> Coverage);

internal sealed record NativeResponseActionRequest(
    string Action,
    uint? ProcessId,
    string ExpectedPath,
    string Target,
    string RemoteAddress,
    uint? DurationMinutes,
    string PersistenceId,
    string RollbackId,
    string Confirmation);

internal sealed record NativeResponseActionResult(
    string Action,
    string Target,
    string Outcome,
    string? RollbackId,
    string? ExpiresAt,
    long AuditEventId);

internal sealed record NativeContentStatus(
    string ActiveVersion,
    string? PreviousVersion,
    string Source,
    string ManifestUrl);

internal sealed record NativeExclusionRecord(string Path, bool Recursive, string CreatedAt);

internal sealed record NativeAllowedHashRecord(string Sha256, string Label, string CreatedAt);
