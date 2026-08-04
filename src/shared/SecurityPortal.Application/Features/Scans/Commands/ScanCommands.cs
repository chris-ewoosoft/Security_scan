using MediatR;
using SecurityPortal.Application.Features.Scans.DTOs;

namespace SecurityPortal.Application.Features.Scans.Commands;

public record StartWebsiteScanCommand(
    string TargetUrl,
    IReadOnlyList<string>? Checks = null,
    IReadOnlyList<string>? Tools = null,
    string? ReportType = null,
    Guid? UserId = null,
    Guid? OrganizationId = null) : IRequest<WebsiteScanDto>;

public record DeleteWebsiteScansCommand(IReadOnlyList<Guid> Ids) : IRequest<DeleteWebsiteScansResultDto>;

public record CancelWebsiteScanCommand(Guid Id) : IRequest<WebsiteScanDto>;
