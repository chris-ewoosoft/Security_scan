namespace SecurityPortal.Application.Features.ServerScans.DTOs;

public record StartServerScanRequest(
    string Host,
    int Port,
    string Username,
    string AuthType,
    string? Password,
    string? PrivateKey,
    string? Passphrase);

public record ServerScanFindingDto(
    string Id,
    string Name,
    string Severity,
    string Status,
    string Detail,
    string? Category = null,
    string? Confidence = null,
    string? Recommendation = null,
    string? Analysis = null);

public record ServerScanDto(
    Guid Id,
    string Host,
    int Port,
    string Username,
    string Status,
    string? Summary,
    string? ErrorMessage,
    DateTime? StartedAt,
    DateTime? CompletedAt,
    DateTime CreatedAt,
    IReadOnlyList<ServerScanFindingDto> Findings,
    string? AccessToken = null);
