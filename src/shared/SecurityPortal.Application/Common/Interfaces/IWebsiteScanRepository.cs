using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Common.Interfaces;

public interface IWebsiteScanRepository
{
    Task AddAsync(WebsiteScan scan, CancellationToken cancellationToken = default);
    Task<WebsiteScan?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<WebsiteScan?> GetByIdAsNoTrackingAsync(Guid id, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<WebsiteScan>> GetQueuedAsync(int take, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<WebsiteScan>> GetRecentAsync(int take, CancellationToken cancellationToken = default);
    Task<int> DeleteByIdsAsync(IReadOnlyList<Guid> ids, CancellationToken cancellationToken = default);

    /// <summary>Atomically mark Queued/Running scan as Cancelled. Returns false if not cancellable.</summary>
    Task<bool> TryCancelAsync(Guid id, string reason, CancellationToken cancellationToken = default);
}

/// <summary>Signals an in-flight processor to abort a scan immediately.</summary>
public interface IScanAbortSignal
{
    void Abort(Guid scanId);
}
