namespace SecurityPortal.Application.Features.Auth.DTOs;

public record LoginRequest(string Email, string Password);

public record RegisterRequest(
    string Email,
    string Username,
    string Password,
    string FirstName,
    string LastName,
    string OrganizationName);

public record RefreshTokenRequest(string RefreshToken);

public record AuthResponse(
    string AccessToken,
    string RefreshToken,
    DateTime AccessTokenExpiry,
    UserDto User);

public record UserDto(
    Guid Id,
    string Email,
    string Username,
    string FirstName,
    string LastName,
    string FullName,
    string? AvatarUrl,
    IEnumerable<string> Roles,
    IEnumerable<string> Permissions);

public record ChangePasswordRequest(string CurrentPassword, string NewPassword);

public record UpdateProfileRequest(string FirstName, string LastName, string? AvatarUrl);
