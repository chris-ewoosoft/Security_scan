using System.Text.Json;
using SecurityPortal.Domain.Common;
using SecurityPortal.Domain.Common.Exceptions;

namespace SecurityPortal.Domain.Entities;

public class WebsiteScan : AggregateRoot
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public string TargetUrl { get; private set; } = string.Empty;
    public string NormalizedHost { get; private set; } = string.Empty;
    public ScanStatus Status { get; private set; } = ScanStatus.Queued;
    public Guid? CreatedByUserId { get; private set; }
    public Guid? OrganizationId { get; private set; }
    public DateTime? StartedAt { get; private set; }
    public DateTime? CompletedAt { get; private set; }
    public string? ErrorMessage { get; private set; }
    public string? Summary { get; private set; }
    public int? HttpStatusCode { get; private set; }
    public long? ResponseTimeMs { get; private set; }
    public bool? HasHttps { get; private set; }
    public string? ServerHeader { get; private set; }

    /// <summary>JSON: selected checks, tools, report type.</summary>
    public string ConfigJson { get; private set; } = "{}";

    /// <summary>JSON: findings / report payload produced by the scanner.</summary>
    public string? FindingsJson { get; private set; }

    public string ReportType { get; private set; } = ScanCatalog.DefaultReportType;

    private WebsiteScan() { }

    public static WebsiteScan Create(
        string targetUrl,
        ScanConfiguration config,
        Guid? createdByUserId = null,
        Guid? organizationId = null)
    {
        if (string.IsNullOrWhiteSpace(targetUrl))
            throw new DomainException("Website URL is required.");

        if (!Uri.TryCreate(NormalizeUrl(targetUrl), UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new DomainException("Enter a valid http:// or https:// website address.");
        }

        config.Validate();

        return new WebsiteScan
        {
            TargetUrl = uri.GetLeftPart(UriPartial.Path).TrimEnd('/'),
            NormalizedHost = uri.Host.ToLowerInvariant(),
            CreatedByUserId = createdByUserId,
            OrganizationId = organizationId,
            Status = ScanStatus.Queued,
            ConfigJson = JsonSerializer.Serialize(config, JsonOptions),
            ReportType = config.ReportType
        };
    }

    public ScanConfiguration GetConfiguration()
    {
        if (string.IsNullOrWhiteSpace(ConfigJson))
            return ScanConfiguration.CreateDefault();

        return JsonSerializer.Deserialize<ScanConfiguration>(ConfigJson, JsonOptions)
               ?? ScanConfiguration.CreateDefault();
    }

    public void MarkRunning()
    {
        if (Status is ScanStatus.Completed or ScanStatus.Cancelled)
            throw new DomainException("Cannot restart a finished scan.");

        Status = ScanStatus.Running;
        StartedAt = DateTime.UtcNow;
        ErrorMessage = null;
        SetUpdatedAt();
    }

    public void MarkCompleted(
        string summary,
        int? httpStatusCode,
        long? responseTimeMs,
        bool hasHttps,
        string? serverHeader,
        string findingsJson)
    {
        if (Status == ScanStatus.Cancelled) return;

        Status = ScanStatus.Completed;
        Summary = summary;
        HttpStatusCode = httpStatusCode;
        ResponseTimeMs = responseTimeMs;
        HasHttps = hasHttps;
        ServerHeader = serverHeader;
        FindingsJson = findingsJson;
        CompletedAt = DateTime.UtcNow;
        ErrorMessage = null;
        SetUpdatedAt();
    }

    public void MarkFailed(string errorMessage)
    {
        if (Status == ScanStatus.Cancelled) return;

        Status = ScanStatus.Failed;
        ErrorMessage = errorMessage;
        CompletedAt = DateTime.UtcNow;
        SetUpdatedAt();
    }

    /// <summary>Stops a queued or running scan. Returns false if already terminal.</summary>
    public bool TryCancel(string? reason = null)
    {
        if (Status is not (ScanStatus.Queued or ScanStatus.Running))
            return false;

        Status = ScanStatus.Cancelled;
        ErrorMessage = string.IsNullOrWhiteSpace(reason) ? "Scan cancelled by user." : reason.Trim();
        Summary = ErrorMessage;
        CompletedAt = DateTime.UtcNow;
        SetUpdatedAt();
        return true;
    }

    private static string NormalizeUrl(string input)
    {
        var trimmed = input.Trim();
        if (!trimmed.Contains("://", StringComparison.Ordinal))
            trimmed = "https://" + trimmed;
        return trimmed;
    }
}

public sealed class ScanConfiguration
{
    public List<string> Checks { get; set; } = [];
    public List<string> Tools { get; set; } = [];
    public string ReportType { get; set; } = ScanCatalog.DefaultReportType;

    public static ScanConfiguration CreateDefault()
    {
        var checks = ScanCatalog.DefaultCheckIds.ToList();
        var tools = ScanCatalog.Checks
            .Where(c => checks.Contains(c.Id, StringComparer.OrdinalIgnoreCase))
            .SelectMany(c => c.Tools)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new ScanConfiguration
        {
            Checks = checks,
            Tools = tools,
            ReportType = ScanCatalog.DefaultReportType
        };
    }

    public void Validate()
    {
        if (Checks.Count == 0)
            throw new DomainException("Select at least one security check.");

        var invalidChecks = Checks.Where(c => !ScanCatalog.ValidCheckIds.Contains(c)).ToList();
        if (invalidChecks.Count > 0)
            throw new DomainException($"Unknown security checks: {string.Join(", ", invalidChecks)}");

        if (Tools.Count == 0)
        {
            Tools = ScanCatalog.Checks
                .Where(c => Checks.Contains(c.Id, StringComparer.OrdinalIgnoreCase))
                .SelectMany(c => c.Tools)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        var invalidTools = Tools.Where(t => !ScanCatalog.ValidToolIds.Contains(t)).ToList();
        if (invalidTools.Count > 0)
            throw new DomainException($"Unknown tools: {string.Join(", ", invalidTools)}");

        if (string.IsNullOrWhiteSpace(ReportType) || !ScanCatalog.ValidReportIds.Contains(ReportType))
            throw new DomainException("Select a valid security report type.");
    }
}
