using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityPortal.Application.Features.Scans.Commands;
using SecurityPortal.Application.Features.Scans.DTOs;
using SecurityPortal.Application.Features.Scans.Queries;

namespace SecurityPortal.API.Controllers.v1;

public class ScansController(IMediator mediator) : BaseController(mediator)
{
    private string? Language => Request.Headers.AcceptLanguage.FirstOrDefault()?.Split(',')[0].Trim();

    /// <summary>Build stamp so local/UI can verify the running API binary</summary>
    [AllowAnonymous]
    [HttpGet("build-info")]
    [ProducesResponseType(200)]
    public IActionResult BuildInfo() => Ok(new
    {
        service = "SecurityPortal.API",
        fix = "cvmanager-graphql-discovery; MaxAutomaticRedirections-default",
        stamp = "2026-08-06.3",
        utc = DateTime.UtcNow
    });

    /// <summary>Catalog of security checks, tools, and report types</summary>
    [AllowAnonymous]
    [HttpGet("catalog")]
    [ProducesResponseType(typeof(ScanCatalogDto), 200)]
    public async Task<IActionResult> GetCatalog()
    {
        var result = await Mediator.Send(new GetScanCatalogQuery(Language));
        return Ok(result);
    }

    /// <summary>Start a website security scan with selected checks/tools/report</summary>
    [AllowAnonymous]
    [HttpPost]
    [ProducesResponseType(typeof(WebsiteScanDto), 201)]
    [ProducesResponseType(422)]
    public async Task<IActionResult> Start([FromBody] StartWebsiteScanRequest request)
    {
        var userId = CurrentUserId == Guid.Empty ? (Guid?)null : CurrentUserId;
        var result = await Mediator.Send(new StartWebsiteScanCommand(
            request.TargetUrl,
            request.Checks,
            request.Tools,
            request.ReportType,
            userId,
            Auth: request.Auth,
            Source: request.Source));
        return CreatedAtAction(nameof(GetById), new { id = result.Id, version = "1.0" }, result);
    }

    /// <summary>Get scan status, configuration, and security report</summary>
    [AllowAnonymous]
    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(WebsiteScanDto), 200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> GetById(Guid id)
    {
        var result = await Mediator.Send(new GetWebsiteScanQuery(id, Language));
        return Ok(result);
    }

    /// <summary>List recent website scans</summary>
    [AllowAnonymous]
    [HttpGet]
    [ProducesResponseType(typeof(IReadOnlyList<WebsiteScanDto>), 200)]
    public async Task<IActionResult> ListRecent([FromQuery] int take = 10)
    {
        var result = await Mediator.Send(new ListRecentWebsiteScansQuery(take, Language));
        return Ok(result);
    }

    /// <summary>Delete one or more website scans from history</summary>
    [AllowAnonymous]
    [HttpDelete]
    [ProducesResponseType(typeof(DeleteWebsiteScansResultDto), 200)]
    [ProducesResponseType(422)]
    public async Task<IActionResult> Delete([FromBody] DeleteWebsiteScansRequest request)
    {
        var ids = request?.Ids ?? [];
        if (ids.Count == 0)
            return UnprocessableEntity(new { detail = "Chọn ít nhất một scan để xóa." });

        var result = await Mediator.Send(new DeleteWebsiteScansCommand(ids));
        return Ok(result);
    }

    /// <summary>Stop a queued or running website scan</summary>
    [AllowAnonymous]
    [HttpPost("{id:guid}/cancel")]
    [ProducesResponseType(typeof(WebsiteScanDto), 200)]
    [ProducesResponseType(404)]
    [ProducesResponseType(422)]
    public async Task<IActionResult> Cancel(Guid id)
    {
        var result = await Mediator.Send(new CancelWebsiteScanCommand(id));
        return Ok(result);
    }
}
