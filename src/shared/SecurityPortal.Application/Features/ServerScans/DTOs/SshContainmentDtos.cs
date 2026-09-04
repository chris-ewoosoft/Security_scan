namespace SecurityPortal.Application.Features.ServerScans.DTOs;

public record SshContainmentRequest(
    string Host,
    int Port,
    string Username,
    string AuthType,
    string? Password,
    string? PrivateKey,
    string? Passphrase,
    IReadOnlyList<string> Destinations,
    bool Confirm = false);

public record SshContainmentPreviewDto(
    string Host,
    IReadOnlyList<string> ResolvedAddresses,
    IReadOnlyList<string> Commands,
    DateTime ExpiresAt,
    bool CanApply);

public record SshContainmentResultDto(
    string Host,
    IReadOnlyList<string> ResolvedAddresses,
    DateTime ExpiresAt,
    bool Applied,
    string Message);