using MediatR;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.Scans.Commands;
using SecurityPortal.Application.Features.Scans.DTOs;
using SecurityPortal.Application.Features.Scans.Queries;
using SecurityPortal.Domain.Common.Exceptions;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Features.Scans.Handlers;

public class StartWebsiteScanCommandHandler(
    IWebsiteScanRepository scanRepository,
    IUnitOfWork unitOfWork)
    : IRequestHandler<StartWebsiteScanCommand, WebsiteScanDto>
{
    public async Task<WebsiteScanDto> Handle(StartWebsiteScanCommand request, CancellationToken cancellationToken)
    {
        var config = ScanConfiguration.CreateDefault();
        if (request.Checks is { Count: > 0 })
            config.Checks = request.Checks.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (request.Tools is { Count: > 0 })
            config.Tools = request.Tools.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (!string.IsNullOrWhiteSpace(request.ReportType))
            config.ReportType = request.ReportType;

        var scan = WebsiteScan.Create(request.TargetUrl, config, request.UserId, request.OrganizationId);
        await scanRepository.AddAsync(scan, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return WebsiteScanMappings.ToDto(scan);
    }
}

public class GetWebsiteScanQueryHandler(IWebsiteScanRepository scanRepository)
    : IRequestHandler<GetWebsiteScanQuery, WebsiteScanDto>
{
    public async Task<WebsiteScanDto> Handle(GetWebsiteScanQuery request, CancellationToken cancellationToken)
    {
        var scan = await scanRepository.GetByIdAsync(request.Id, cancellationToken)
            ?? throw new NotFoundException(nameof(WebsiteScan), request.Id);
        return WebsiteScanMappings.ToDto(scan);
    }
}

public class ListRecentWebsiteScansQueryHandler(IWebsiteScanRepository scanRepository)
    : IRequestHandler<ListRecentWebsiteScansQuery, IReadOnlyList<WebsiteScanDto>>
{
    public async Task<IReadOnlyList<WebsiteScanDto>> Handle(
        ListRecentWebsiteScansQuery request,
        CancellationToken cancellationToken)
    {
        var scans = await scanRepository.GetRecentAsync(Math.Clamp(request.Take, 1, 50), cancellationToken);
        return scans.Select(WebsiteScanMappings.ToDto).ToList();
    }
}

public class GetScanCatalogQueryHandler : IRequestHandler<GetScanCatalogQuery, ScanCatalogDto>
{
    public Task<ScanCatalogDto> Handle(GetScanCatalogQuery request, CancellationToken cancellationToken) =>
        Task.FromResult(WebsiteScanMappings.ToCatalogDto());
}

public class DeleteWebsiteScansCommandHandler(IWebsiteScanRepository scanRepository)
    : IRequestHandler<DeleteWebsiteScansCommand, DeleteWebsiteScansResultDto>
{
    public async Task<DeleteWebsiteScansResultDto> Handle(
        DeleteWebsiteScansCommand request,
        CancellationToken cancellationToken)
    {
        var ids = (request.Ids ?? [])
            .Where(id => id != Guid.Empty)
            .Distinct()
            .ToList();

        if (ids.Count == 0)
            return new DeleteWebsiteScansResultDto(0);

        var deleted = await scanRepository.DeleteByIdsAsync(ids, cancellationToken);
        return new DeleteWebsiteScansResultDto(deleted);
    }
}
