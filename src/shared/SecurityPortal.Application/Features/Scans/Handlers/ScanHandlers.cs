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
    IUnitOfWork unitOfWork,
    IScanSecretProtector secretProtector)
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

        config.Auth = BuildAuth(request.Auth);
        config.Source = BuildSource(request.Source);

        var scan = WebsiteScan.Create(request.TargetUrl, config, request.UserId, request.OrganizationId);
        await scanRepository.AddAsync(scan, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return WebsiteScanMappings.ToDto(scan);
    }

    private ScanSourceConfiguration? BuildSource(StartScanSourceRequest? source)
    {
        if (source is null || string.IsNullOrWhiteSpace(source.RepositoryUrl))
            return null;

        return new ScanSourceConfiguration
        {
            RepositoryUrl = source.RepositoryUrl.Trim(),
            Branch = string.IsNullOrWhiteSpace(source.Branch) ? null : source.Branch.Trim(),
            TokenCipher = string.IsNullOrWhiteSpace(source.Token)
                ? null
                : secretProtector.Protect(source.Token),
        };
    }

    private ScanAuthConfiguration? BuildAuth(StartScanAuthRequest? auth)
    {
        if (auth is null) return null;
        var type = (auth.Type ?? ScanAuthConfiguration.TypeNone).Trim().ToLowerInvariant();
        if (type is "" or ScanAuthConfiguration.TypeNone)
            return null;

        if (string.IsNullOrWhiteSpace(auth.Password))
            throw new DomainException("Password is required for authenticated scans.");

        return new ScanAuthConfiguration
        {
            Type = type,
            LoginUrl = string.IsNullOrWhiteSpace(auth.LoginUrl) ? null : auth.LoginUrl.Trim(),
            Username = auth.Username?.Trim(),
            PasswordCipher = secretProtector.Protect(auth.Password),
            SuccessUrlContains = string.IsNullOrWhiteSpace(auth.SuccessUrlContains) ? null : auth.SuccessUrlContains.Trim(),
            UsernameField = string.IsNullOrWhiteSpace(auth.UsernameField) ? null : auth.UsernameField.Trim(),
            PasswordField = string.IsNullOrWhiteSpace(auth.PasswordField) ? null : auth.PasswordField.Trim(),
            ClinicId = string.IsNullOrWhiteSpace(auth.ClinicId) ? null : auth.ClinicId.Trim(),
        };
    }
}

public class GetWebsiteScanQueryHandler(IWebsiteScanRepository scanRepository)
    : IRequestHandler<GetWebsiteScanQuery, WebsiteScanDto>
{
    public async Task<WebsiteScanDto> Handle(GetWebsiteScanQuery request, CancellationToken cancellationToken)
    {
        var scan = await scanRepository.GetByIdAsync(request.Id, cancellationToken)
            ?? throw new NotFoundException(nameof(WebsiteScan), request.Id);
        return WebsiteScanMappings.ToDto(scan, request.Lang);
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
        return scans.Select(scan => WebsiteScanMappings.ToDto(scan, request.Lang)).ToList();
    }
}

public class GetScanCatalogQueryHandler : IRequestHandler<GetScanCatalogQuery, ScanCatalogDto>
{
    public Task<ScanCatalogDto> Handle(GetScanCatalogQuery request, CancellationToken cancellationToken) =>
        Task.FromResult(WebsiteScanMappings.ToCatalogDto(request.Lang));
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

public class CancelWebsiteScanCommandHandler(
    IWebsiteScanRepository scanRepository,
    IScanAbortSignal abortSignal)
    : IRequestHandler<CancelWebsiteScanCommand, WebsiteScanDto>
{
    public async Task<WebsiteScanDto> Handle(CancelWebsiteScanCommand request, CancellationToken cancellationToken)
    {
        var scan = await scanRepository.GetByIdAsync(request.Id, cancellationToken)
            ?? throw new NotFoundException(nameof(WebsiteScan), request.Id);

        if (scan.Status == ScanStatus.Cancelled)
            return WebsiteScanMappings.ToDto(scan);

        if (scan.Status is ScanStatus.Completed or ScanStatus.Failed)
            throw new DomainException("Only queued or running scans can be stopped.");

        // Abort in-flight work first so HTTP/TCP loops stop promptly.
        abortSignal.Abort(request.Id);

        await scanRepository.TryCancelAsync(
            request.Id,
            "Scan cancelled by user.",
            cancellationToken);

        var refreshed = await scanRepository.GetByIdAsNoTrackingAsync(request.Id, cancellationToken)
            ?? throw new NotFoundException(nameof(WebsiteScan), request.Id);

        // Processor may have persisted Cancelled after Abort; treat as success.
        if (refreshed.Status == ScanStatus.Cancelled)
            return WebsiteScanMappings.ToDto(refreshed);

        throw new DomainException("Only queued or running scans can be stopped.");
    }
}
