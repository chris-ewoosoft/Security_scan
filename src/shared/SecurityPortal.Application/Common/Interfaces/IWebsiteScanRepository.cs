using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Common.Interfaces;

public interface IWebsiteScanRepository
{
    Task AddAsync(WebsiteScan scan, CancellationToken cancellationToken = default);
    Task<WebsiteScan?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<WebsiteScan>> GetQueuedAsync(int take, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<WebsiteScan>> GetRecentAsync(int take, CancellationToken cancellationToken = default);
}
