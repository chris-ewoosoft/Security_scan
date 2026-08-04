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

    public Task<WebsiteScan?> GetByIdAsNoTrackingAsync(Guid id, CancellationToken cancellationToken = default) =>
        context.WebsiteScans.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, cancellationToken);

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

    public async Task<bool> TryCancelAsync(Guid id, string reason, CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var message = string.IsNullOrWhiteSpace(reason) ? "Scan cancelled by user." : reason.Trim();
        var updated = await context.WebsiteScans
            .Where(s => s.Id == id && (s.Status == ScanStatus.Queued || s.Status == ScanStatus.Running))
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(s => s.Status, ScanStatus.Cancelled)
                .SetProperty(s => s.ErrorMessage, message)
                .SetProperty(s => s.Summary, message)
                .SetProperty(s => s.CompletedAt, now)
                .SetProperty(s => s.UpdatedAt, now), cancellationToken);
        return updated > 0;
    }
}
