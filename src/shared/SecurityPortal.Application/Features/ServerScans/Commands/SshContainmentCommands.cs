using MediatR;
using SecurityPortal.Application.Features.ServerScans.DTOs;

namespace SecurityPortal.Application.Features.ServerScans.Commands;

public record PreviewSshContainmentCommand(SshContainmentRequest Request) : IRequest<SshContainmentPreviewDto>;
public record ApplySshContainmentCommand(SshContainmentRequest Request) : IRequest<SshContainmentResultDto>;
public record RollbackSshContainmentCommand(SshContainmentRequest Request) : IRequest<SshContainmentResultDto>;