using MediatR;
using SecurityPortal.Application.Features.Scans.DTOs;

namespace SecurityPortal.Application.Features.Scans.Queries;

public record GetWebsiteScanQuery(Guid Id) : IRequest<WebsiteScanDto>;

public record ListRecentWebsiteScansQuery(int Take = 10) : IRequest<IReadOnlyList<WebsiteScanDto>>;

public record GetScanCatalogQuery : IRequest<ScanCatalogDto>;
