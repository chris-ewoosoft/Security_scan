using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityPortal.Application.Features.ServerScans.Commands;
using SecurityPortal.Application.Features.ServerScans.DTOs;
using SecurityPortal.Application.Features.ServerScans.Queries;

namespace SecurityPortal.API.Controllers.v1;

/// <summary>Internal Linux server triage scan performed directly over SSH.</summary>
[Microsoft.AspNetCore.Mvc.Route("api/v{version:apiVersion}/server-scans")]
public class ServerScansController(IMediator mediator) : BaseController(mediator)
{
    /// <summary>Connects over SSH with the given credentials and runs the triage checks immediately.</summary>
    [HttpPost]
    [ProducesResponseType(typeof(ServerScanDto), 201)]
    [ProducesResponseType(422)]
    public async Task<IActionResult> Start([FromBody] StartServerScanRequest request)
    {
        var userId = CurrentUserId == Guid.Empty ? (Guid?)null : CurrentUserId;
        var result = await Mediator.Send(new StartServerScanCommand(
            request.Host,
            request.Port,
            request.Username,
            request.AuthType,
            request.Password,
            request.PrivateKey,
            request.Passphrase,
            userId));
        return CreatedAtAction(nameof(GetById), new { id = result.Id, version = "1.0" }, result);
    }

    /// <summary>Get server scan status and findings (requires X-Scan-Token).</summary>
    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(ServerScanDto), 200)]
    [ProducesResponseType(404)]
    [ProducesResponseType(403)]
    public async Task<IActionResult> GetById(Guid id)
    {
        var token = Request.Headers["X-Scan-Token"].FirstOrDefault();
        var result = await Mediator.Send(new GetServerScanQuery(id, token));
        return Ok(result);
    }

    [Authorize(Policy = "SshContainmentOperators")]
    [HttpPost("containment/preview")]
    public async Task<IActionResult> PreviewContainment([FromBody] SshContainmentRequest request) =>
        Ok(await Mediator.Send(new PreviewSshContainmentCommand(request)));

    [Authorize(Policy = "SshContainmentOperators")]
    [HttpPost("containment/apply")]
    public async Task<IActionResult> ApplyContainment([FromBody] SshContainmentRequest request) =>
        Ok(await Mediator.Send(new ApplySshContainmentCommand(request)));

    [Authorize(Policy = "SshContainmentOperators")]
    [HttpPost("containment/rollback")]
    public async Task<IActionResult> RollbackContainment([FromBody] SshContainmentRequest request) =>
        Ok(await Mediator.Send(new RollbackSshContainmentCommand(request)));
}
