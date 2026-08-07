using SecurityPortal.Domain.Entities;
using SecurityPortal.Application.Features.Scans.Localization;

namespace SecurityPortal.Application.Features.Scans.DTOs;

public record StartWebsiteScanRequest(
    string TargetUrl,
    IReadOnlyList<string>? Checks = null,
    IReadOnlyList<string>? Tools = null,
    string? ReportType = null,
    StartScanAuthRequest? Auth = null,
    StartScanSourceRequest? Source = null,
    ScanToolOptionsDto? ToolOptions = null);

public record StartScanAuthRequest(
    string? Type = null,
    string? LoginUrl = null,
    string? Username = null,
    string? Password = null,
    string? SuccessUrlContains = null,
    string? UsernameField = null,
    string? PasswordField = null,
    string? ClinicId = null);

public record StartScanSourceRequest(
    string? RepositoryUrl = null,
    string? Branch = null,
    string? Token = null);

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

public record DeleteWebsiteScansRequest(
    IReadOnlyList<Guid> Ids,
    Dictionary<Guid, string>? AccessTokens = null);

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
    IReadOnlyList<string>? ReproductionSteps = null,
    string? Code = null,
    IReadOnlyDictionary<string, string>? Params = null);

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
    ScanReportPayloadDto? Report,
    string? AccessToken = null);

public record ScanConfigurationDto(
    IReadOnlyList<string> Checks,
    IReadOnlyList<string> Tools,
    string ReportType,
    ScanAuthDto? Auth = null,
    ScanSourceDto? Source = null,
    ScanToolOptionsDto? ToolOptions = null);

public record ScanToolOptionsDto(
    NucleiToolOptionsDto? Nuclei = null,
    NaabuToolOptionsDto? Naabu = null,
    FeroxToolOptionsDto? Feroxbuster = null,
    FfufToolOptionsDto? Ffuf = null);

public record NucleiToolOptionsDto(
    string? Profile = null,
    string? Severity = null,
    string? Tags = null,
    string? ExposureTags = null,
    int? Concurrency = null,
    int? RateLimit = null,
    int? TimeoutSeconds = null,
    int? Retries = null,
    int? MaxDurationSeconds = null);

public record NaabuToolOptionsDto(
    string? Ports = null,
    int? Rate = null);

public record FeroxToolOptionsDto(
    int? Depth = null,
    int? Threads = null,
    int? TimeoutSeconds = null,
    int? MaxDurationSeconds = null);

public record FfufToolOptionsDto(
    int? Threads = null,
    int? TimeoutSeconds = null,
    int? MaxDurationSeconds = null,
    string? MatchCodes = null);

/// <summary>Auth metadata returned to clients — never includes password.</summary>
public record ScanAuthDto(
    string Type,
    bool Enabled,
    string? LoginUrl,
    string? UsernameMasked,
    string? SuccessUrlContains,
    string? ClinicIdMasked = null);

/// <summary>Source metadata — never includes token.</summary>
public record ScanSourceDto(
    bool Enabled,
    string? RepositoryUrlMasked,
    string? Branch,
    bool HasToken);

public static class WebsiteScanMappings
{
    public static WebsiteScanDto ToDto(WebsiteScan scan, string? lang = null, string? accessToken = null)
    {
        var config = scan.GetConfiguration();
        ScanReportPayloadDto? report = null;
        if (!string.IsNullOrWhiteSpace(scan.FindingsJson))
        {
            report = System.Text.Json.JsonSerializer.Deserialize<ScanReportPayloadDto>(
                scan.FindingsJson,
                new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase });
            if (report is not null)
                report = ScanI18n.LocalizeReport(report, scan.TargetUrl, lang);
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
            new ScanConfigurationDto(
                config.Checks,
                config.Tools,
                config.ReportType,
                ToAuthDto(config.Auth),
                ToSourceDto(config.Source),
                ToToolOptionsDto(config.ToolOptions)),
            report,
            accessToken);
    }

    public static ScanToolOptionsDto? ToToolOptionsDto(ScanToolOptions? options)
    {
        if (options is null) return null;
        options.Normalize();
        return new ScanToolOptionsDto(
            new NucleiToolOptionsDto(
                options.Nuclei.Profile,
                options.Nuclei.Severity,
                options.Nuclei.Tags,
                options.Nuclei.ExposureTags,
                options.Nuclei.Concurrency,
                options.Nuclei.RateLimit,
                options.Nuclei.TimeoutSeconds,
                options.Nuclei.Retries,
                options.Nuclei.MaxDurationSeconds),
            new NaabuToolOptionsDto(options.Naabu.Ports, options.Naabu.Rate),
            new FeroxToolOptionsDto(
                options.Feroxbuster.Depth,
                options.Feroxbuster.Threads,
                options.Feroxbuster.TimeoutSeconds,
                options.Feroxbuster.MaxDurationSeconds),
            new FfufToolOptionsDto(
                options.Ffuf.Threads,
                options.Ffuf.TimeoutSeconds,
                options.Ffuf.MaxDurationSeconds,
                options.Ffuf.MatchCodes));
    }

    public static ScanToolOptions? FromToolOptionsDto(ScanToolOptionsDto? dto)
    {
        if (dto is null) return ScanToolOptions.CreateDefault();
        var options = new ScanToolOptions
        {
            Nuclei = new NucleiToolOptions
            {
                Profile = dto.Nuclei?.Profile ?? "balanced",
                Severity = dto.Nuclei?.Severity ?? "medium,high,critical",
                Tags = dto.Nuclei?.Tags,
                ExposureTags = dto.Nuclei?.ExposureTags ?? "exposure,config,backup,token,key,file",
                Concurrency = dto.Nuclei?.Concurrency ?? 25,
                RateLimit = dto.Nuclei?.RateLimit ?? 150,
                TimeoutSeconds = dto.Nuclei?.TimeoutSeconds ?? 8,
                Retries = dto.Nuclei?.Retries ?? 1,
                MaxDurationSeconds = dto.Nuclei?.MaxDurationSeconds ?? 120,
            },
            Naabu = new NaabuToolOptions
            {
                Ports = dto.Naabu?.Ports ?? NaabuToolOptions.CreateDefault().Ports,
                Rate = dto.Naabu?.Rate ?? 200,
            },
            Feroxbuster = new FeroxToolOptions
            {
                Depth = dto.Feroxbuster?.Depth ?? 1,
                Threads = dto.Feroxbuster?.Threads ?? 20,
                TimeoutSeconds = dto.Feroxbuster?.TimeoutSeconds ?? 5,
                MaxDurationSeconds = dto.Feroxbuster?.MaxDurationSeconds ?? 90,
            },
            Ffuf = new FfufToolOptions
            {
                Threads = dto.Ffuf?.Threads ?? 20,
                TimeoutSeconds = dto.Ffuf?.TimeoutSeconds ?? 5,
                MaxDurationSeconds = dto.Ffuf?.MaxDurationSeconds ?? 90,
                MatchCodes = dto.Ffuf?.MatchCodes ?? "200,204,301,401,403",
            },
        };
        options.Normalize();
        return options;
    }

    public static ScanSourceDto? ToSourceDto(ScanSourceConfiguration? source)
    {
        if (source is null || !source.IsEnabled)
            return source is null ? null : new ScanSourceDto(false, null, null, false);

        return new ScanSourceDto(
            true,
            MaskRepositoryUrl(source.RepositoryUrl),
            source.Branch,
            !string.IsNullOrWhiteSpace(source.TokenCipher));
    }

    public static string? MaskRepositoryUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return MaskUsername(url);
        var path = uri.AbsolutePath.TrimEnd('/');
        var leaf = path.Length == 0 ? uri.Host : path[(path.LastIndexOf('/') + 1)..];
        return $"{uri.Scheme}://{uri.Host}/***/{leaf}";
    }

    public static ScanAuthDto? ToAuthDto(ScanAuthConfiguration? auth)
    {
        if (auth is null || !auth.IsEnabled)
            return auth is null ? null : new ScanAuthDto(ScanAuthConfiguration.TypeNone, false, null, null, null, null);

        return new ScanAuthDto(
            auth.Type,
            true,
            auth.LoginUrl,
            MaskUsername(auth.Username),
            auth.SuccessUrlContains,
            MaskUsername(auth.ClinicId));
    }

    public static string? MaskUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username)) return null;
        var value = username.Trim();
        if (value.Length <= 2) return new string('*', value.Length);
        if (value.Contains('@', StringComparison.Ordinal))
        {
            var parts = value.Split('@', 2);
            var local = parts[0];
            var maskedLocal = local.Length <= 1 ? "*" : local[0] + new string('*', Math.Min(local.Length - 1, 4));
            return $"{maskedLocal}@{parts[1]}";
        }

        return value[0] + new string('*', Math.Min(value.Length - 1, 6));
    }

    public static ScanCatalogDto ToCatalogDto(string? lang = null) => ScanI18n.LocalizeCatalog(lang);
}
