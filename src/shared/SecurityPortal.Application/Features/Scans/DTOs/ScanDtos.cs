using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Features.Scans.DTOs;

public record StartWebsiteScanRequest(
    string TargetUrl,
    IReadOnlyList<string>? Checks = null,
    IReadOnlyList<string>? Tools = null,
    string? ReportType = null);

public record ScanCatalogDto(
    IReadOnlyList<ScanCheckDto> Checks,
    IReadOnlyList<ScanToolDto> Tools,
    IReadOnlyList<ScanReportDto> Reports);

public record ScanCheckDto(
    string Id,
    string Name,
    string Description,
    IReadOnlyList<string> Tools,
    bool EnabledByDefault,
    string Category,
    int Priority);

public record ScanToolDto(string Id, string Name, string Kind, string Description);

public record ScanReportDto(string Id, string Name, string Description);

public record DeleteWebsiteScansRequest(IReadOnlyList<Guid> Ids);

public record DeleteWebsiteScansResultDto(int Deleted);

public record ScanFindingDto(
    string CheckId,
    string CheckName,
    string Severity,
    string Title,
    string Detail,
    string? Evidence,
    string? Recommendation,
    IReadOnlyList<string> Tools,
    IReadOnlyList<string>? ReproductionSteps = null);

public record ScanReportPayloadDto(
    string ReportType,
    string ReportTitle,
    int RiskScore,
    string RiskLevel,
    IReadOnlyList<string> SelectedChecks,
    IReadOnlyList<string> SelectedTools,
    IReadOnlyList<ScanFindingDto> Findings,
    string ExecutiveSummary);

public record WebsiteScanDto(
    Guid Id,
    string TargetUrl,
    string NormalizedHost,
    string Status,
    DateTime CreatedAt,
    DateTime? StartedAt,
    DateTime? CompletedAt,
    string? Summary,
    string? ErrorMessage,
    int? HttpStatusCode,
    long? ResponseTimeMs,
    bool? HasHttps,
    string? ServerHeader,
    string ReportType,
    ScanConfigurationDto Configuration,
    ScanReportPayloadDto? Report);

public record ScanConfigurationDto(
    IReadOnlyList<string> Checks,
    IReadOnlyList<string> Tools,
    string ReportType);

public static class WebsiteScanMappings
{
    public static WebsiteScanDto ToDto(WebsiteScan scan)
    {
        var config = scan.GetConfiguration();
        ScanReportPayloadDto? report = null;
        if (!string.IsNullOrWhiteSpace(scan.FindingsJson))
        {
            report = System.Text.Json.JsonSerializer.Deserialize<ScanReportPayloadDto>(
                scan.FindingsJson,
                new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase });
        }

        return new WebsiteScanDto(
            scan.Id,
            scan.TargetUrl,
            scan.NormalizedHost,
            scan.Status.ToString(),
            scan.CreatedAt,
            scan.StartedAt,
            scan.CompletedAt,
            scan.Summary,
            scan.ErrorMessage,
            scan.HttpStatusCode,
            scan.ResponseTimeMs,
            scan.HasHttps,
            scan.ServerHeader,
            scan.ReportType,
            new ScanConfigurationDto(config.Checks, config.Tools, config.ReportType),
            report);
    }

    public static ScanCatalogDto ToCatalogDto() => new(
        ScanCatalog.Checks.Select(c => new ScanCheckDto(
            c.Id, c.Name, c.Description, c.Tools, c.EnabledByDefault, c.Category, c.Priority)).ToList(),
        ScanCatalog.Tools.Select(t => new ScanToolDto(t.Id, t.Name, t.Kind, t.Description)).ToList(),
        ScanCatalog.Reports.Select(r => new ScanReportDto(r.Id, r.Name, r.Description)).ToList());
}
