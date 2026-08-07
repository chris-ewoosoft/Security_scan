using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityPortal.API.Services;
using SecurityPortal.Application.Features.Scans.Commands;
using SecurityPortal.Application.Features.Scans.DTOs;
using SecurityPortal.Application.Features.Scans.Queries;
using SecurityPortal.Domain.Entities;

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
        fix = "source-driven surface: ASP.NET route compose; runtime probes; secondary Nuclei URLs; loopback lab scan",
        stamp = Environment.GetEnvironmentVariable("SECURITYPORTAL_BUILD_STAMP") ?? "2026-08-07.6",
        allowAutoRedirect = false,
        maxAutomaticRedirections = ScanHttpClientFactory.DefaultMaxAutomaticRedirections,
        scannersPath = ExternalToolRunner.ToolsDirectory,
        utc = DateTime.UtcNow
    });

    /// <summary>Which catalog tools are actually available on this API host (PATH / SCANNER_TOOLS_PATH).</summary>
    [AllowAnonymous]
    [HttpGet("tools-status")]
    [ProducesResponseType(200)]
    public IActionResult ToolsStatus() => Ok(ExternalToolRunner.DescribeAvailability());

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
            Source: request.Source,
            ToolOptions: request.ToolOptions));
        return CreatedAtAction(nameof(GetById), new { id = result.Id, version = "1.0" }, result);
    }

    /// <summary>Get scan status, configuration, and security report (requires X-Scan-Token for hardened scans)</summary>
    [AllowAnonymous]
    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(WebsiteScanDto), 200)]
    [ProducesResponseType(404)]
    [ProducesResponseType(403)]
    public async Task<IActionResult> GetById(Guid id)
    {
        var token = Request.Headers["X-Scan-Token"].FirstOrDefault();
        var result = await Mediator.Send(new GetWebsiteScanQuery(id, Language, token));
        return Ok(result);
    }

    /// <summary>
    /// List scans the caller owns. Pass JSON body or header X-Scan-Access:
    /// {"tokens":{"guid":"token",...}} — empty tokens returns empty list (no global enumeration).
    /// </summary>
    [AllowAnonymous]
    [HttpPost("history")]
    [ProducesResponseType(typeof(IReadOnlyList<WebsiteScanDto>), 200)]
    public async Task<IActionResult> ListOwned([FromBody] ScanAccessListRequest? request, [FromQuery] int take = 50)
    {
        var tokens = ParseAccessTokens(request);
        var result = await Mediator.Send(new ListRecentWebsiteScansQuery(take, Language, tokens));
        return Ok(result);
    }

    /// <summary>Deprecated open list — returns empty to prevent IDOR enumeration.</summary>
    [AllowAnonymous]
    [HttpGet]
    [ProducesResponseType(typeof(IReadOnlyList<WebsiteScanDto>), 200)]
    public Task<IActionResult> ListRecent([FromQuery] int take = 10) =>
        Task.FromResult<IActionResult>(Ok(Array.Empty<WebsiteScanDto>()));

    /// <summary>Delete owned scans (requires matching access tokens)</summary>
    [AllowAnonymous]
    [HttpDelete]
    [ProducesResponseType(typeof(DeleteWebsiteScansResultDto), 200)]
    [ProducesResponseType(422)]
    public async Task<IActionResult> Delete([FromBody] DeleteWebsiteScansRequest request)
    {
        var ids = request?.Ids ?? [];
        if (ids.Count == 0)
            return UnprocessableEntity(new { detail = "Chọn ít nhất một scan để xóa." });

        var tokens = request?.AccessTokens ?? new Dictionary<Guid, string>();
        var result = await Mediator.Send(new DeleteWebsiteScansCommand(ids, tokens));
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
        var token = Request.Headers["X-Scan-Token"].FirstOrDefault();
        var result = await Mediator.Send(new CancelWebsiteScanCommand(id, token));
        return Ok(result);
    }

    private static IReadOnlyDictionary<Guid, string> ParseAccessTokens(ScanAccessListRequest? request)
    {
        if (request?.Tokens is { Count: > 0 })
            return request.Tokens;
        return new Dictionary<Guid, string>();
    }
}

public record ScanAccessListRequest(Dictionary<Guid, string>? Tokens = null);