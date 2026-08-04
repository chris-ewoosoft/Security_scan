using MediatR;
using SecurityPortal.Application.Common.Exceptions;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.Auth.Commands;
using SecurityPortal.Application.Features.Auth.DTOs;
using SecurityPortal.Domain.Common.Exceptions;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Features.Auth.Handlers;

public class LoginCommandHandler(
    IUserRepository userRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IPasswordHasher passwordHasher,
    IJwtService jwtService,
    IUnitOfWork unitOfWork)
    : IRequestHandler<LoginCommand, AuthResponse>
{
    public async Task<AuthResponse> Handle(LoginCommand request, CancellationToken cancellationToken)
    {
        var lookupUser = await userRepository.GetByEmailAsync(request.Email, cancellationToken)
            ?? throw new UnauthorizedAccessException("Invalid credentials.");

        var user = await userRepository.GetWithRolesAsync(lookupUser.Id, cancellationToken)
            ?? throw new UnauthorizedAccessException("Invalid credentials.");

        if (!user.IsActive) throw new UnauthorizedAccessException("Account is deactivated.");
        if (!passwordHasher.Verify(request.Password, user.PasswordHash))
            throw new UnauthorizedAccessException("Invalid credentials.");

        var permissions = await userRepository.GetPermissionsAsync(user.Id, cancellationToken);
        var roles = user.UserRoles.Select(ur => ur.Role?.Name ?? string.Empty).Where(r => !string.IsNullOrEmpty(r));

        var accessToken = jwtService.GenerateAccessToken(user, roles, permissions);
        var rawRefreshToken = jwtService.GenerateRefreshToken();

        var refreshToken = RefreshToken.Create(user.Id, rawRefreshToken, 7, request.IpAddress, request.UserAgent);
        await refreshTokenRepository.AddAsync(refreshToken, cancellationToken);

        user.RecordLogin();
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return BuildResponse(accessToken, rawRefreshToken, user, roles, permissions);
    }

    private AuthResponse BuildResponse(string accessToken, string refreshToken, User user,
        IEnumerable<string> roles, IEnumerable<string> permissions) =>
        new(accessToken, refreshToken, jwtService.GetAccessTokenExpiry(),
            new UserDto(user.Id, user.Email, user.Username, user.FirstName, user.LastName,
                user.FullName, user.AvatarUrl, roles, permissions));
}

public class RegisterCommandHandler(
    IUserRepository userRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IRoleRepository roleRepository,
    IPasswordHasher passwordHasher,
    IJwtService jwtService,
    IUnitOfWork unitOfWork)
    : IRequestHandler<RegisterCommand, AuthResponse>
{
    public async Task<AuthResponse> Handle(RegisterCommand request, CancellationToken cancellationToken)
    {
        if (await userRepository.EmailExistsAsync(request.Email, cancellationToken))
            throw ValidationException.ForField("Email", "This email address is already registered.");

        if (await userRepository.UsernameExistsAsync(request.Username, cancellationToken))
            throw ValidationException.ForField("Username", "This username is already taken.");

        var org = Organization.Create(request.OrganizationName);
        var passwordHash = passwordHasher.Hash(request.Password);

        var user = User.Create(org.Id, request.Email, request.Username,
            passwordHash, request.FirstName, request.LastName);

        var viewerRole = await roleRepository.GetByNameAsync(Role.SystemRoles.SecurityEngineer, cancellationToken);
        if (viewerRole is not null) user.AssignRole(viewerRole.Id);

        await userRepository.AddAsync(user, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        var permissions = await userRepository.GetPermissionsAsync(user.Id, cancellationToken);
        var roles = user.UserRoles.Select(ur => ur.Role?.Name ?? string.Empty).Where(r => !string.IsNullOrEmpty(r));

        var accessToken = jwtService.GenerateAccessToken(user, roles, permissions);
        var rawRefreshToken = jwtService.GenerateRefreshToken();
        var refreshToken = RefreshToken.Create(user.Id, rawRefreshToken, 7);

        await refreshTokenRepository.AddAsync(refreshToken, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return new AuthResponse(accessToken, rawRefreshToken, jwtService.GetAccessTokenExpiry(),
            new UserDto(user.Id, user.Email, user.Username, user.FirstName, user.LastName,
                user.FullName, user.AvatarUrl, roles, permissions));
    }
}

public class RefreshTokenCommandHandler(
    IRefreshTokenRepository refreshTokenRepository,
    IUserRepository userRepository,
    IJwtService jwtService,
    IUnitOfWork unitOfWork)
    : IRequestHandler<RefreshTokenCommand, AuthResponse>
{
    public async Task<AuthResponse> Handle(RefreshTokenCommand request, CancellationToken cancellationToken)
    {
        var refreshToken = await refreshTokenRepository.GetByTokenAsync(request.RefreshToken, cancellationToken)
            ?? throw new UnauthorizedAccessException("Invalid refresh token.");

        if (!refreshToken.IsActive) throw new UnauthorizedAccessException("Refresh token has expired or been revoked.");

        var user = await userRepository.GetWithRolesAsync(refreshToken.UserId, cancellationToken)
            ?? throw new UnauthorizedAccessException("User not found.");

        var permissions = await userRepository.GetPermissionsAsync(user.Id, cancellationToken);
        var roles = user.UserRoles.Select(ur => ur.Role?.Name ?? string.Empty).Where(r => !string.IsNullOrEmpty(r));

        var newAccessToken = jwtService.GenerateAccessToken(user, roles, permissions);
        var newRawRefreshToken = jwtService.GenerateRefreshToken();

        refreshToken.Revoke();
        var newRefreshToken = RefreshToken.Create(user.Id, newRawRefreshToken, 7, request.IpAddress);
        await refreshTokenRepository.AddAsync(newRefreshToken, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return new AuthResponse(newAccessToken, newRawRefreshToken, jwtService.GetAccessTokenExpiry(),
            new UserDto(user.Id, user.Email, user.Username, user.FirstName, user.LastName,
                user.FullName, user.AvatarUrl, roles, permissions));
    }
}

public class RevokeTokenCommandHandler(
    IRefreshTokenRepository refreshTokenRepository,
    IUnitOfWork unitOfWork)
    : IRequestHandler<RevokeTokenCommand>
{
    public async Task Handle(RevokeTokenCommand request, CancellationToken cancellationToken)
    {
        var token = await refreshTokenRepository.GetByTokenAsync(request.RefreshToken, cancellationToken);
        if (token is null || !token.IsActive) return;
        token.Revoke();
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }
}

public class ChangePasswordCommandHandler(
    IUserRepository userRepository,
    IPasswordHasher passwordHasher,
    IUnitOfWork unitOfWork)
    : IRequestHandler<ChangePasswordCommand>
{
    public async Task Handle(ChangePasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await userRepository.GetByIdAsync(request.UserId, cancellationToken)
            ?? throw new NotFoundException(nameof(User), request.UserId);

        if (!passwordHasher.Verify(request.CurrentPassword, user.PasswordHash))
            throw ValidationException.ForField("CurrentPassword", "Current password is incorrect.");

        user.ChangePassword(passwordHasher.Hash(request.NewPassword));
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }
}

public class UpdateProfileCommandHandler(
    IUserRepository userRepository,
    IUnitOfWork unitOfWork)
    : IRequestHandler<UpdateProfileCommand, UserDto>
{
    public async Task<UserDto> Handle(UpdateProfileCommand request, CancellationToken cancellationToken)
    {
        var user = await userRepository.GetWithRolesAsync(request.UserId, cancellationToken)
            ?? throw new NotFoundException(nameof(User), request.UserId);

        user.UpdateProfile(request.FirstName, request.LastName, request.AvatarUrl);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        var roles = user.UserRoles.Select(ur => ur.Role?.Name ?? string.Empty).Where(r => !string.IsNullOrEmpty(r));
        return new UserDto(user.Id, user.Email, user.Username, user.FirstName, user.LastName,
            user.FullName, user.AvatarUrl, roles, []);
    }
}
