using SecurityPortal.Domain.Common;
using SecurityPortal.Domain.Common.Exceptions;

namespace SecurityPortal.Domain.Entities;

public class User : AggregateRoot
{
    public Guid OrganizationId { get; private set; }
    public string Email { get; private set; } = string.Empty;
    public string Username { get; private set; } = string.Empty;
    public string PasswordHash { get; private set; } = string.Empty;
    public string FirstName { get; private set; } = string.Empty;
    public string LastName { get; private set; } = string.Empty;
    public string? AvatarUrl { get; private set; }
    public bool IsActive { get; private set; } = true;
    public bool EmailVerified { get; private set; }
    public DateTime? LastLoginAt { get; private set; }

    private readonly List<UserRole> _userRoles = [];
    public IReadOnlyList<UserRole> UserRoles => _userRoles.AsReadOnly();

    public string FullName => $"{FirstName} {LastName}".Trim();

    private User() { }

    public static User Create(Guid organizationId, string email, string username,
        string passwordHash, string firstName, string lastName)
    {
        if (string.IsNullOrWhiteSpace(email)) throw new DomainException("Email is required.");
        if (string.IsNullOrWhiteSpace(username)) throw new DomainException("Username is required.");
        if (string.IsNullOrWhiteSpace(passwordHash)) throw new DomainException("Password is required.");

        var user = new User
        {
            OrganizationId = organizationId,
            Email = email.ToLowerInvariant(),
            Username = username.ToLowerInvariant(),
            PasswordHash = passwordHash,
            FirstName = firstName,
            LastName = lastName
        };

        user.AddDomainEvent(new UserCreatedEvent(user.Id, user.Email));
        return user;
    }

    public void UpdateProfile(string firstName, string lastName, string? avatarUrl = null)
    {
        FirstName = firstName;
        LastName = lastName;
        AvatarUrl = avatarUrl;
        SetUpdatedAt();
    }

    public void ChangePassword(string newPasswordHash)
    {
        PasswordHash = newPasswordHash;
        SetUpdatedAt();
    }

    public void VerifyEmail()
    {
        EmailVerified = true;
        SetUpdatedAt();
    }

    public void Deactivate()
    {
        IsActive = false;
        SetUpdatedAt();
    }

    public void Activate()
    {
        IsActive = true;
        SetUpdatedAt();
    }

    public void RecordLogin()
    {
        LastLoginAt = DateTime.UtcNow;
        SetUpdatedAt();
    }

    public void AssignRole(Guid roleId)
    {
        if (_userRoles.Any(ur => ur.RoleId == roleId)) return;
        _userRoles.Add(UserRole.Create(Id, roleId));
        SetUpdatedAt();
    }

    public void RemoveRole(Guid roleId)
    {
        var userRole = _userRoles.FirstOrDefault(ur => ur.RoleId == roleId);
        if (userRole is null) return;
        _userRoles.Remove(userRole);
        SetUpdatedAt();
    }
}
