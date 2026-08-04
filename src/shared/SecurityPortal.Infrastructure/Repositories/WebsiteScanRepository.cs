using Microsoft.EntityFrameworkCore;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Domain.Entities;
using SecurityPortal.Infrastructure.Persistence;

namespace SecurityPortal.Infrastructure.Repositories;

public class WebsiteScanRepository(ApplicationDbContext context) : IWebsiteScanRepository
{
    public async Task AddAsync(WebsiteScan scan, CancellationToken cancellationToken = default) =>
        await context.WebsiteScans.AddAsync(scan, cancellationToken);

    public Task<WebsiteScan?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        context.WebsiteScans.FirstOrDefaultAsync(s => s.Id == id, cancellationToken);

    public async Task<IReadOnlyList<WebsiteScan>> GetQueuedAsync(int take, CancellationToken cancellationToken = default) =>
        await context.WebsiteScans
            .Where(s => s.Status == ScanStatus.Queued)
            .OrderBy(s => s.CreatedAt)
            .Take(take)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<WebsiteScan>> GetRecentAsync(int take, CancellationToken cancellationToken = default) =>
        await context.WebsiteScans
            .OrderByDescending(s => s.CreatedAt)
            .Take(take)
            .ToListAsync(cancellationToken);

    public async Task<int> DeleteByIdsAsync(IReadOnlyList<Guid> ids, CancellationToken cancellationToken = default)
    {
        if (ids.Count == 0) return 0;
        return await context.WebsiteScans
            .Where(s => ids.Contains(s.Id))
            .ExecuteDeleteAsync(cancellationToken);
    }
}
