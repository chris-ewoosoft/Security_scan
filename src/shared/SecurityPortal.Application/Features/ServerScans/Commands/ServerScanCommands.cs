using MediatR;
using SecurityPortal.Application.Features.ServerScans.DTOs;

namespace SecurityPortal.Application.Features.ServerScans.Commands;

public record StartServerScanCommand(
    string Host,
    int Port,
    string Username,
    string AuthType,
    string? Password,
    string? PrivateKey,
    string? Passphrase,
    Guid? UserId = null,
    Guid? OrganizationId = null) : IRequest<ServerScanDto>;
