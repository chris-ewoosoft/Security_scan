using System.Text.Json;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Domain.Entities;
using SecurityPortal.Infrastructure.Persistence;

namespace SecurityPortal.Infrastructure.Services;

public sealed class AuditLogService(ApplicationDbContext context, ICurrentUser currentUser) : IAuditLogService
{
    public async Task LogAsync(string action, string resourceType, string? resourceId = null, string? oldValues = null, string? newValues = null, CancellationToken cancellationToken = default)
    {
        var sanitized = newValues is null ? null : JsonSerializer.Serialize(JsonSerializer.Deserialize<JsonElement>(newValues));
        context.AuditLogs.Add(AuditLog.Create(action, resourceType, resourceId, currentUser.UserId == Guid.Empty ? null : currentUser.UserId, null, oldValues, sanitized));
        await context.SaveChangesAsync(cancellationToken);
    }
}