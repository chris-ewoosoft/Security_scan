using SecurityPortal.Domain.Common;

namespace SecurityPortal.Domain.Entities;

public class AuditLog : BaseEntity
{
    public Guid? UserId { get; private set; }
    public string Action { get; private set; } = string.Empty;
    public string ResourceType { get; private set; } = string.Empty;
    public string? ResourceId { get; private set; }
    public string? OldValues { get; private set; }
    public string? NewValues { get; private set; }
    public string? IpAddress { get; private set; }
    public string? UserAgent { get; private set; }
    public string? CorrelationId { get; private set; }

    private AuditLog() { }

    public static AuditLog Create(string action, string resourceType, string? resourceId = null,
        Guid? userId = null, string? ipAddress = null, string? oldValues = null,
        string? newValues = null, string? correlationId = null) =>
        new()
        {
            Action = action,
            ResourceType = resourceType,
            ResourceId = resourceId,
            UserId = userId,
            IpAddress = ipAddress,
            OldValues = oldValues,
            NewValues = newValues,
            CorrelationId = correlationId
        };
}
