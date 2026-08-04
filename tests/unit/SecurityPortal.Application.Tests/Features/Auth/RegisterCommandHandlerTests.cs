using Xunit;
using Moq;
using SecurityPortal.Application.Common.Exceptions;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.Auth.Commands;
using SecurityPortal.Application.Features.Auth.Handlers;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Tests.Features.Auth;

public class RegisterCommandHandlerTests
{
    private readonly Mock<IUserRepository> _userRepositoryMock = new();
    private readonly Mock<IRefreshTokenRepository> _refreshTokenRepositoryMock = new();
    private readonly Mock<IRoleRepository> _roleRepositoryMock = new();
    private readonly Mock<IPasswordHasher> _passwordHasherMock = new();
    private readonly Mock<IJwtService> _jwtServiceMock = new();
    private readonly Mock<IUnitOfWork> _unitOfWorkMock = new();

    private RegisterCommandHandler CreateHandler() => new(
        _userRepositoryMock.Object,
        _refreshTokenRepositoryMock.Object,
        _roleRepositoryMock.Object,
        _passwordHasherMock.Object,
        _jwtServiceMock.Object,
        _unitOfWorkMock.Object);

    [Fact]
    public async Task Handle_WithValidData_ShouldCreateUserAndReturnAuthResponse()
    {
        _userRepositoryMock.Setup(r => r.EmailExistsAsync("new@example.com", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);
        _userRepositoryMock.Setup(r => r.UsernameExistsAsync("newuser", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        _passwordHasherMock.Setup(h => h.Hash("Password1!")).Returns("hashedpw");

        _roleRepositoryMock.Setup(r => r.GetByNameAsync(Role.SystemRoles.SecurityEngineer, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Role?)null);

        User? capturedUser = null;
        _userRepositoryMock.Setup(r => r.AddAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()))
            .Callback<User, CancellationToken>((u, _) => capturedUser = u)
            .Returns(Task.CompletedTask);

        _userRepositoryMock.Setup(r => r.GetPermissionsAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);

        _jwtServiceMock.Setup(j => j.GenerateAccessToken(It.IsAny<User>(), It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>>()))
            .Returns("access-token");
        _jwtServiceMock.Setup(j => j.GenerateRefreshToken()).Returns("refresh-token");
        _jwtServiceMock.Setup(j => j.GetAccessTokenExpiry()).Returns(DateTime.UtcNow.AddMinutes(15));

        _refreshTokenRepositoryMock.Setup(r => r.AddAsync(It.IsAny<RefreshToken>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        _unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var handler = CreateHandler();
        var result = await handler.Handle(
            new RegisterCommand("new@example.com", "newuser", "Password1!", "John", "Doe", "Acme Corp"),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("access-token", result.AccessToken);
        Assert.NotNull(capturedUser);
        Assert.Equal("new@example.com", capturedUser!.Email);
    }

    [Fact]
    public async Task Handle_EmailAlreadyExists_ShouldThrowValidationException()
    {
        _userRepositoryMock.Setup(r => r.EmailExistsAsync("existing@example.com", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var handler = CreateHandler();
        await Assert.ThrowsAsync<ValidationException>(() =>
            handler.Handle(
                new RegisterCommand("existing@example.com", "user", "Password1!", "John", "Doe", "Org"),
                CancellationToken.None));
    }

    [Fact]
    public async Task Handle_UsernameAlreadyTaken_ShouldThrowValidationException()
    {
        _userRepositoryMock.Setup(r => r.EmailExistsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);
        _userRepositoryMock.Setup(r => r.UsernameExistsAsync("takenuser", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var handler = CreateHandler();
        await Assert.ThrowsAsync<ValidationException>(() =>
            handler.Handle(
                new RegisterCommand("new@example.com", "takenuser", "Password1!", "John", "Doe", "Org"),
                CancellationToken.None));
    }
}
