using MediatR;
using SecurityPortal.Application.Features.ServerScans.DTOs;

namespace SecurityPortal.Application.Features.ServerScans.Queries;

public record GetServerScanQuery(Guid Id, string? AccessToken = null) : IRequest<ServerScanDto>;

public record ListRecentServerScansQuery(
    int Take = 10,
    IReadOnlyDictionary<Guid, string>? AccessTokens = null) : IRequest<IReadOnlyList<ServerScanDto>>;
