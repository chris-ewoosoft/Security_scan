using Xunit;
using Moq;
using SecurityPortal.Application.Common.Exceptions;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.Auth.Commands;
using SecurityPortal.Application.Features.Auth.DTOs;
using SecurityPortal.Application.Features.Auth.Handlers;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Tests.Features.Auth;

public class LoginCommandHandlerTests
{
    private readonly Mock<IUserRepository> _userRepositoryMock = new();
    private readonly Mock<IRefreshTokenRepository> _refreshTokenRepositoryMock = new();
    private readonly Mock<IPasswordHasher> _passwordHasherMock = new();
    private readonly Mock<IJwtService> _jwtServiceMock = new();
    private readonly Mock<IUnitOfWork> _unitOfWorkMock = new();

    private LoginCommandHandler CreateHandler() => new(
        _userRepositoryMock.Object,
        _refreshTokenRepositoryMock.Object,
        _passwordHasherMock.Object,
        _jwtServiceMock.Object,
        _unitOfWorkMock.Object);

    [Fact]
    public async Task Handle_WithValidCredentials_ShouldReturnAuthResponse()
    {
        var userId = Guid.NewGuid();
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");

        _userRepositoryMock.Setup(r => r.GetByEmailAsync("test@example.com", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _userRepositoryMock.Setup(r => r.GetWithRolesAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _userRepositoryMock.Setup(r => r.GetPermissionsAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(["projects:read"]);

        _passwordHasherMock.Setup(h => h.Verify("password123", "hashedpw")).Returns(true);
        _jwtServiceMock.Setup(j => j.GenerateAccessToken(user, It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>>()))
            .Returns("access-token");
        _jwtServiceMock.Setup(j => j.GenerateRefreshToken()).Returns("refresh-token");
        _jwtServiceMock.Setup(j => j.GetAccessTokenExpiry()).Returns(DateTime.UtcNow.AddMinutes(15));

        _refreshTokenRepositoryMock.Setup(r => r.AddAsync(It.IsAny<RefreshToken>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        _unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var handler = CreateHandler();
        var result = await handler.Handle(
            new LoginCommand("test@example.com", "password123", null, null),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("access-token", result.AccessToken);
        Assert.Equal("refresh-token", result.RefreshToken);
        Assert.Equal("test@example.com", result.User.Email);
    }

    [Fact]
    public async Task Handle_UserNotFound_ShouldThrowUnauthorized()
    {
        _userRepositoryMock.Setup(r => r.GetByEmailAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((User?)null);

        var handler = CreateHandler();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            handler.Handle(new LoginCommand("notfound@example.com", "pw", null, null), CancellationToken.None));
    }

    [Fact]
    public async Task Handle_WrongPassword_ShouldThrowUnauthorized()
    {
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");

        _userRepositoryMock.Setup(r => r.GetByEmailAsync("test@example.com", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _userRepositoryMock.Setup(r => r.GetWithRolesAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _passwordHasherMock.Setup(h => h.Verify("wrongpw", "hashedpw")).Returns(false);

        var handler = CreateHandler();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            handler.Handle(new LoginCommand("test@example.com", "wrongpw", null, null), CancellationToken.None));
    }

    [Fact]
    public async Task Handle_DeactivatedUser_ShouldThrowUnauthorized()
    {
        var user = User.Create(Guid.NewGuid(), "test@example.com", "testuser",
            "hashedpw", "John", "Doe");
        user.Deactivate();

        _userRepositoryMock.Setup(r => r.GetByEmailAsync("test@example.com", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _userRepositoryMock.Setup(r => r.GetWithRolesAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _passwordHasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var handler = CreateHandler();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            handler.Handle(new LoginCommand("test@example.com", "password123", null, null), CancellationToken.None));
    }
}
