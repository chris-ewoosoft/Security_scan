using MediatR;
using SecurityPortal.Application.Common.Exceptions;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.ServerScans.Commands;
using SecurityPortal.Application.Features.ServerScans.DTOs;
using SecurityPortal.Application.Features.ServerScans.Queries;
using SecurityPortal.Domain.Common.Exceptions;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Features.ServerScans.Handlers;

public class StartServerScanCommandHandler(
    IServerScanRepository scanRepository,
    IServerScanExecutor executor,
    IUnitOfWork unitOfWork,
    IScanSecretProtector secretProtector)
    : IRequestHandler<StartServerScanCommand, ServerScanDto>
{
    public async Task<ServerScanDto> Handle(StartServerScanCommand request, CancellationToken cancellationToken)
    {
        var authType = (request.AuthType ?? "").Trim().Equals("privatekey", StringComparison.OrdinalIgnoreCase)
            ? ServerAuthType.PrivateKey
            : ServerAuthType.Password;

        var secret = authType == ServerAuthType.PrivateKey ? request.PrivateKey : request.Password;
        if (string.IsNullOrWhiteSpace(secret))
            throw new DomainException(authType == ServerAuthType.PrivateKey
                ? "Private key is required."
                : "Password is required.");

        var secretCipher = secretProtector.Protect(secret);
        var passphraseCipher = string.IsNullOrWhiteSpace(request.Passphrase)
            ? null
            : secretProtector.Protect(request.Passphrase);

        var accessToken = ServerScan.CreateOwnerToken();
        var scan = ServerScan.Create(
            request.Host,
            request.Port <= 0 ? 22 : request.Port,
            request.Username,
            authType,
            secretCipher,
            passphraseCipher,
            ServerScan.HashOwnerToken(accessToken),
            request.UserId,
            request.OrganizationId);

        scan.MarkRunning();
        await scanRepository.AddAsync(scan, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        ServerScanExecutionResult result;
        try
        {
            result = await executor.ExecuteAsync(new ServerScanExecutionRequest(
                scan.Host,
                scan.Port,
                scan.Username,
                authType,
                secret,
                request.Passphrase), cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            scan.Cancel();
            await unitOfWork.SaveChangesAsync(CancellationToken.None);
            throw;
        }

        if (result.Success)
        {
            var findingsJson = ServerScanMappings.SerializeFindings(result.Findings);
            scan.Complete(result.Summary, findingsJson, findingsJson);
        }
        else
            scan.Fail(result.ErrorMessage ?? "SSH scan failed.");

        await unitOfWork.SaveChangesAsync(cancellationToken);
        return ServerScanMappings.ToDto(scan, accessToken);
    }
}

public class GetServerScanQueryHandler(IServerScanRepository scanRepository, IUnitOfWork unitOfWork)
    : IRequestHandler<GetServerScanQuery, ServerScanDto>
{
    public async Task<ServerScanDto> Handle(GetServerScanQuery request, CancellationToken cancellationToken)
    {
        var scan = await scanRepository.GetByIdAsync(request.Id, cancellationToken)
            ?? throw new NotFoundException(nameof(ServerScan), request.Id);

        if (!scan.MatchesOwnerToken(request.AccessToken))
            throw new ForbiddenAccessException("Scan access token is missing or invalid.");

        if (scan.ExpireRawOutputIfNeeded(DateTime.UtcNow))
            await unitOfWork.SaveChangesAsync(cancellationToken);

        return ServerScanMappings.ToDto(scan);
    }
}

public class ListRecentServerScansQueryHandler(IServerScanRepository scanRepository)
    : IRequestHandler<ListRecentServerScansQuery, IReadOnlyList<ServerScanDto>>
{
    public async Task<IReadOnlyList<ServerScanDto>> Handle(
        ListRecentServerScansQuery request,
        CancellationToken cancellationToken)
    {
        var tokens = request.AccessTokens ?? new Dictionary<Guid, string>();
        if (tokens.Count == 0)
            return [];

        var take = Math.Clamp(request.Take, 1, 50);
        var recent = await scanRepository.GetRecentAsync(200, cancellationToken);
        return recent
            .Where(s => tokens.TryGetValue(s.Id, out var t) && s.MatchesOwnerToken(t))
            .OrderByDescending(s => s.CreatedAt)
            .Take(take)
            .Select(s => ServerScanMappings.ToDto(s))
            .ToList();
    }
}
