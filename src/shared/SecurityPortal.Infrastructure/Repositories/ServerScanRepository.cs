using Microsoft.EntityFrameworkCore;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Domain.Entities;
using SecurityPortal.Infrastructure.Persistence;

namespace SecurityPortal.Infrastructure.Repositories;

public class ServerScanRepository(ApplicationDbContext context) : IServerScanRepository
{
    public async Task AddAsync(ServerScan scan, CancellationToken cancellationToken = default) =>
        await context.ServerScans.AddAsync(scan, cancellationToken);

    public Task<ServerScan?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        context.ServerScans.FirstOrDefaultAsync(s => s.Id == id, cancellationToken);

    public async Task<IReadOnlyList<ServerScan>> GetRecentAsync(int take, CancellationToken cancellationToken = default) =>
        await context.ServerScans
            .OrderByDescending(s => s.CreatedAt)
            .Take(take)
            .ToListAsync(cancellationToken);

    public Task<int> PurgeExpiredRawOutputAsync(DateTime utcNow, CancellationToken cancellationToken = default) =>
        context.ServerScans
            .Where(s => s.RawOutputJson != null && s.RawOutputExpiresAt != null && s.RawOutputExpiresAt <= utcNow)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(s => s.RawOutputJson, (string?)null)
                .SetProperty(s => s.UpdatedAt, utcNow), cancellationToken);
}
