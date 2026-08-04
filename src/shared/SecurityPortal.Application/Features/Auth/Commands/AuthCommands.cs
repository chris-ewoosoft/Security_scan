using MediatR;
using SecurityPortal.Application.Features.Auth.DTOs;

namespace SecurityPortal.Application.Features.Auth.Commands;

public record LoginCommand(string Email, string Password, string? IpAddress, string? UserAgent)
    : IRequest<AuthResponse>;

public record RegisterCommand(
    string Email,
    string Username,
    string Password,
    string FirstName,
    string LastName,
    string OrganizationName)
    : IRequest<AuthResponse>;

public record RefreshTokenCommand(string RefreshToken, string? IpAddress)
    : IRequest<AuthResponse>;

public record RevokeTokenCommand(string RefreshToken) : IRequest;

public record ChangePasswordCommand(Guid UserId, string CurrentPassword, string NewPassword)
    : IRequest;

public record UpdateProfileCommand(
    Guid UserId,
    string FirstName,
    string LastName,
    string? AvatarUrl)
    : IRequest<UserDto>;
