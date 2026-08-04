using MediatR;
using SecurityPortal.Application.Features.Scans.DTOs;

namespace SecurityPortal.Application.Features.Scans.Queries;

public record GetWebsiteScanQuery(Guid Id, string? Lang = null) : IRequest<WebsiteScanDto>;

public record ListRecentWebsiteScansQuery(int Take = 10, string? Lang = null) : IRequest<IReadOnlyList<WebsiteScanDto>>;

public record GetScanCatalogQuery(string? Lang = null) : IRequest<ScanCatalogDto>;
