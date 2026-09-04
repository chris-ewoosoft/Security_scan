using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Common.Interfaces;

public interface IServerScanRepository
{
    Task AddAsync(ServerScan scan, CancellationToken cancellationToken = default);
    Task<ServerScan?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ServerScan>> GetRecentAsync(int take, CancellationToken cancellationToken = default);
    Task<int> PurgeExpiredRawOutputAsync(DateTime utcNow, CancellationToken cancellationToken = default);
}

/// <summary>Runs the SSH triage checks against a target server and returns the result.</summary>
public interface IServerScanExecutor
{
    Task<ServerScanExecutionResult> ExecuteAsync(ServerScanExecutionRequest request, CancellationToken cancellationToken = default);
}

public record ServerScanExecutionRequest(
    string Host,
    int Port,
    string Username,
    Domain.Entities.ServerAuthType AuthType,
    string Secret,
    string? Passphrase);

public record ServerScanFinding(
    string Id,
    string Name,
    string Severity,
    string Status,
    string Detail,
    string? Category = null,
    string? Confidence = null,
    string? Recommendation = null,
    string? Analysis = null);

public record ServerScanExecutionResult(bool Success, string? ErrorMessage, string Summary, IReadOnlyList<ServerScanFinding> Findings);
