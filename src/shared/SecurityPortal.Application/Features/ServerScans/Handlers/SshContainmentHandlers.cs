using MediatR;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.ServerScans.Commands;
using SecurityPortal.Application.Features.ServerScans.DTOs;

namespace SecurityPortal.Application.Features.ServerScans.Handlers;

public sealed class PreviewSshContainmentHandler(ISshContainmentService service, IAuditLogService audit)
    : IRequestHandler<PreviewSshContainmentCommand, SshContainmentPreviewDto>
{
    public async Task<SshContainmentPreviewDto> Handle(PreviewSshContainmentCommand request, CancellationToken cancellationToken)
    {
        SshContainmentPreviewDto result;
        try { result = await service.PreviewAsync(request.Request, cancellationToken); }
        catch { await audit.LogAsync("ssh-containment-preview-failed", "server", request.Request.Host, newValues: "{\"outcome\":\"failed\"}", cancellationToken: cancellationToken); throw; }
        await audit.LogAsync("ssh-containment-preview", "server", request.Request.Host,
            newValues: $"{{\"addresses\":{System.Text.Json.JsonSerializer.Serialize(result.ResolvedAddresses)},\"expiresAt\":\"{result.ExpiresAt:O}\"}}",
            cancellationToken: cancellationToken);
        return result;
    }
}

public sealed class ApplySshContainmentHandler(ISshContainmentService service, IAuditLogService audit)
    : IRequestHandler<ApplySshContainmentCommand, SshContainmentResultDto>
{
    public async Task<SshContainmentResultDto> Handle(ApplySshContainmentCommand request, CancellationToken cancellationToken)
    {
        SshContainmentResultDto result;
        try { result = await service.ApplyAsync(request.Request, cancellationToken); }
        catch { await audit.LogAsync("ssh-containment-apply-failed", "server", request.Request.Host, newValues: "{\"outcome\":\"failed\"}", cancellationToken: cancellationToken); throw; }
        await audit.LogAsync("ssh-containment-apply", "server", request.Request.Host,
            newValues: $"{{\"addresses\":{System.Text.Json.JsonSerializer.Serialize(result.ResolvedAddresses)},\"expiresAt\":\"{result.ExpiresAt:O}\",\"applied\":{result.Applied.ToString().ToLowerInvariant()}}}",
            cancellationToken: cancellationToken);
        return result;
    }
}

public sealed class RollbackSshContainmentHandler(ISshContainmentService service, IAuditLogService audit)
    : IRequestHandler<RollbackSshContainmentCommand, SshContainmentResultDto>
{
    public async Task<SshContainmentResultDto> Handle(RollbackSshContainmentCommand request, CancellationToken cancellationToken)
    {
        SshContainmentResultDto result;
        try { result = await service.RollbackAsync(request.Request, cancellationToken); }
        catch { await audit.LogAsync("ssh-containment-rollback-failed", "server", request.Request.Host, newValues: "{\"outcome\":\"failed\"}", cancellationToken: cancellationToken); throw; }
        await audit.LogAsync("ssh-containment-rollback", "server", request.Request.Host,
            newValues: $"{{\"addresses\":{System.Text.Json.JsonSerializer.Serialize(result.ResolvedAddresses)},\"applied\":{result.Applied.ToString().ToLowerInvariant()}}}",
            cancellationToken: cancellationToken);
        return result;
    }
}