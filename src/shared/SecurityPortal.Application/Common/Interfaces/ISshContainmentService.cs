using SecurityPortal.Application.Features.ServerScans.DTOs;

namespace SecurityPortal.Application.Common.Interfaces;

public interface ISshContainmentService
{
    Task<SshContainmentPreviewDto> PreviewAsync(SshContainmentRequest request, CancellationToken cancellationToken = default);
    Task<SshContainmentResultDto> ApplyAsync(SshContainmentRequest request, CancellationToken cancellationToken = default);
    Task<SshContainmentResultDto> RollbackAsync(SshContainmentRequest request, CancellationToken cancellationToken = default);
}