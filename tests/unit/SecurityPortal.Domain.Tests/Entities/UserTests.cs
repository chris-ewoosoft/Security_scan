using Xunit;
using SecurityPortal.Domain.Common.Exceptions;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Domain.Tests.Entities;

public class UserTests
{
    [Fact]
    public void Create_WithValidData_ShouldCreateUser()
    {
        var orgId = Guid.NewGuid();
        var user = User.Create(orgId, "test@example.com", "testuser",
            "hashedpw", "John", "Doe");

        Assert.Equal(orgId, user.OrganizationId);
        Assert.Equal("test@example.com", user.Email);
        Assert.Equal("testuser", user.Username);
        Assert.True(user.IsActive);
        Assert.False(user.EmailVerified);
        Assert.Equal("John Doe", user.FullName);
    }

    [Fact]
    public void Create_ShouldAddUserCreatedDomainEvent()
    {
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");

        Assert.Single(user.DomainEvents);
        Assert.IsType<UserCreatedEvent>(user.DomainEvents[0]);
    }

    [Fact]
    public void Create_WithEmptyEmail_ShouldThrowDomainException()
    {
        Assert.Throws<DomainException>(() =>
            User.Create(Guid.NewGuid(), "", "testuser", "hashedpw", "John", "Doe"));
    }

    [Fact]
    public void Create_WithEmptyUsername_ShouldThrowDomainException()
    {
        Assert.Throws<DomainException>(() =>
            User.Create(Guid.NewGuid(), "test@example.com", "", "hashedpw", "John", "Doe"));
    }

    [Fact]
    public void Email_ShouldBeNormalizedToLowercase()
    {
        var user = User.Create(Guid.NewGuid(), "TEST@EXAMPLE.COM", "testuser",
            "hashedpw", "John", "Doe");

        Assert.Equal("test@example.com", user.Email);
    }

    [Fact]
    public void UpdateProfile_ShouldUpdateFields()
    {
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");

        user.UpdateProfile("Jane", "Smith", "https://example.com/avatar.png");

        Assert.Equal("Jane", user.FirstName);
        Assert.Equal("Smith", user.LastName);
        Assert.Equal("https://example.com/avatar.png", user.AvatarUrl);
    }

    [Fact]
    public void AssignRole_ShouldAddUserRole()
    {
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");
        var roleId = Guid.NewGuid();

        user.AssignRole(roleId);

        Assert.Single(user.UserRoles);
        Assert.Equal(roleId, user.UserRoles[0].RoleId);
    }

    [Fact]
    public void AssignRole_SameRoleTwice_ShouldNotDuplicate()
    {
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");
        var roleId = Guid.NewGuid();

        user.AssignRole(roleId);
        user.AssignRole(roleId);

        Assert.Single(user.UserRoles);
    }

    [Fact]
    public void RemoveRole_ShouldRemoveUserRole()
    {
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");
        var roleId = Guid.NewGuid();
        user.AssignRole(roleId);

        user.RemoveRole(roleId);

        Assert.Empty(user.UserRoles);
    }

    [Fact]
    public void Deactivate_ShouldSetIsActiveFalse()
    {
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");
        user.Deactivate();
        Assert.False(user.IsActive);
    }

    [Fact]
    public void Activate_ShouldSetIsActiveTrue()
    {
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");
        user.Deactivate();
        user.Activate();
        Assert.True(user.IsActive);
    }

    [Fact]
    public void RecordLogin_ShouldSetLastLoginAt()
    {
        var before = DateTime.UtcNow;
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");
        user.RecordLogin();

        Assert.NotNull(user.LastLoginAt);
        Assert.True(user.LastLoginAt >= before);
    }

    [Fact]
    public void VerifyEmail_ShouldSetEmailVerifiedTrue()
    {
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");
        user.VerifyEmail();
        Assert.True(user.EmailVerified);
    }
}
