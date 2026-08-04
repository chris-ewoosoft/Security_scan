using SecurityPortal.Domain.Common;

namespace SecurityPortal.Domain.Entities;

public record UserCreatedEvent(Guid UserId, string Email) : DomainEvent;
public record UserDeactivatedEvent(Guid UserId) : DomainEvent;
public record UserPasswordChangedEvent(Guid UserId) : DomainEvent;
