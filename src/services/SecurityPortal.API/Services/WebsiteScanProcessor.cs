using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.Scans.DTOs;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.API.Services;

public sealed class WebsiteScanProcessor(
    IServiceScopeFactory scopeFactory,
    IHttpClientFactory httpClientFactory,
    ILogger<WebsiteScanProcessor> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessBatchAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Website scan processor failed");
            }

            await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken);
        }
    }

    private async Task ProcessBatchAsync(CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var scans = scope.ServiceProvider.GetRequiredService<IWebsiteScanRepository>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

        var queued = await scans.GetQueuedAsync(5, cancellationToken);
        if (queued.Count == 0) return;

        var client = httpClientFactory.CreateClient("WebsiteScanner");

        foreach (var scan in queued)
        {
            scan.MarkRunning();
            await unitOfWork.SaveChangesAsync(cancellationToken);

            try
            {
                var config = scan.GetConfiguration();
                var result = await AnalyzeAsync(client, scan.TargetUrl, config, cancellationToken);
                var findingsJson = JsonSerializer.Serialize(result.Report, JsonOptions);
                scan.MarkCompleted(
                    result.Summary,
                    result.StatusCode,
                    result.ResponseTimeMs,
                    result.HasHttps,
                    result.ServerHeader,
                    findingsJson);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Scan {ScanId} failed for {Url}", scan.Id, scan.TargetUrl);
                scan.MarkFailed(ex.Message);
            }

            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
    }

    private static async Task<AnalysisResult> AnalyzeAsync(
        HttpClient client,
        string targetUrl,
        ScanConfiguration config,
        CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        using var request = new HttpRequestMessage(HttpMethod.Get, targetUrl);
        request.Headers.TryAddWithoutValidation("User-Agent", "SecurityPortal-Scanner/1.0");
        request.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");

        using var response = await client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        sw.Stop();

        var headers = FlattenHeaders(response);
        var hasHttps = targetUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        headers.TryGetValue("Server", out var server);
        headers.TryGetValue("Set-Cookie", out var setCookie);
        headers.TryGetValue("Access-Control-Allow-Origin", out var corsOrigin);
        headers.TryGetValue("X-Powered-By", out var poweredBy);

        var selectedChecks = config.Checks
            .Select(id => ScanCatalog.Checks.First(c => c.Id.Equals(id, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        var findings = new List<ScanFindingDto>();
        foreach (var check in selectedChecks)
        {
            var tools = check.Tools.Where(t => config.Tools.Contains(t, StringComparer.OrdinalIgnoreCase)).ToList();
            if (tools.Count == 0) tools = check.Tools.ToList();

            findings.AddRange(check.Id switch
            {
                "reachability" => EvaluateReachability(check, tools, response, sw.ElapsedMilliseconds),
                "https-tls" => EvaluateHttps(check, tools, hasHttps, targetUrl),
                "security-headers" => EvaluateSecurityHeaders(check, tools, headers),
                "server-fingerprint" => EvaluateFingerprint(check, tools, server, poweredBy),
                "cookie-security" => EvaluateCookies(check, tools, setCookie, hasHttps),
                "cors-policy" => EvaluateCors(check, tools, corsOrigin),
                "information-disclosure" => EvaluateDisclosure(check, tools, headers, server, poweredBy),
                _ => []
            });
        }

        var riskScore = Score(findings);
        var riskLevel = riskScore >= 70 ? "High" : riskScore >= 40 ? "Medium" : "Low";
        var reportDef = ScanCatalog.Reports.First(r => r.Id.Equals(config.ReportType, StringComparison.OrdinalIgnoreCase));

        var executive = BuildExecutiveSummary(targetUrl, findings, riskLevel, config.ReportType);
        var report = new ScanReportPayloadDto(
            config.ReportType,
            reportDef.Name,
            riskScore,
            riskLevel,
            config.Checks,
            config.Tools,
            findings,
            executive);

        var summary =
            $"{findings.Count} finding(s). Risk: {riskLevel} ({riskScore}/100). " +
            $"HTTP {(int)response.StatusCode} in {sw.ElapsedMilliseconds} ms.";

        return new AnalysisResult(
            summary,
            (int)response.StatusCode,
            sw.ElapsedMilliseconds,
            hasHttps,
            server,
            report);
    }

    private static IEnumerable<ScanFindingDto> EvaluateReachability(
        ScanCheckDefinition check, IReadOnlyList<string> tools, HttpResponseMessage response, long ms)
    {
        var code = (int)response.StatusCode;
        if (code >= 500)
        {
            yield return Finding(check, tools, "High", "Máy chủ trả lỗi 5xx",
                $"Target phản hồi HTTP {code}.", $"status={code}; latency={ms}ms",
                "Kiểm tra availability và error handling phía server.");
        }
        else if (code >= 400)
        {
            yield return Finding(check, tools, "Medium", "Máy chủ trả lỗi 4xx",
                $"Target phản hồi HTTP {code}.", $"status={code}; latency={ms}ms",
                "Xác nhận path/public URL và access control.");
        }
        else
        {
            yield return Finding(check, tools, "Info", "Website reachable",
                $"Host phản hồi HTTP {code} trong {ms} ms.", $"status={code}; latency={ms}ms",
                "Giữ monitoring availability định kỳ.");
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateHttps(
        ScanCheckDefinition check, IReadOnlyList<string> tools, bool hasHttps, string url)
    {
        if (!hasHttps)
        {
            yield return Finding(check, tools, "High", "Không dùng HTTPS",
                "Website đang phục vụ qua HTTP thuần.", url,
                "Bắt buộc HTTPS và chuyển hướng HTTP → HTTPS.");
        }
        else
        {
            yield return Finding(check, tools, "Info", "HTTPS được bật",
                "URL mục tiêu sử dụng HTTPS.", url,
                "Tiếp tục duy trì chứng chỉ hợp lệ và HSTS.");
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateSecurityHeaders(
        ScanCheckDefinition check, IReadOnlyList<string> tools, Dictionary<string, string> headers)
    {
        var required = new (string Header, string Severity, string Recommendation)[]
        {
            ("Strict-Transport-Security", "High", "Bật HSTS với max-age đủ lớn."),
            ("Content-Security-Policy", "High", "Thêm CSP để giảm XSS/injection."),
            ("X-Frame-Options", "Medium", "Thêm X-Frame-Options hoặc frame-ancestors trong CSP."),
            ("X-Content-Type-Options", "Medium", "Thêm X-Content-Type-Options: nosniff."),
            ("Referrer-Policy", "Low", "Thêm Referrer-Policy phù hợp."),
            ("Permissions-Policy", "Low", "Giới hạn browser features bằng Permissions-Policy."),
        };

        foreach (var (header, severity, recommendation) in required)
        {
            if (!headers.ContainsKey(header))
            {
                yield return Finding(check, tools, severity, $"Thiếu header {header}",
                    $"Response không có {header}.", null, recommendation);
            }
        }

        if (required.All(r => headers.ContainsKey(r.Header)))
        {
            yield return Finding(check, tools, "Info", "Security headers cơ bản đã có",
                "Các header bảo mật chính đều hiện diện.", null,
                "Rà soát giá trị header định kỳ theo baseline OWASP.");
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateFingerprint(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string? server, string? poweredBy)
    {
        if (!string.IsNullOrWhiteSpace(server))
        {
            yield return Finding(check, tools, "Low", "Lộ Server header",
                "Response tiết lộ thông tin server.", $"Server: {server}",
                "Ẩn hoặc làm mờ Server header ở reverse proxy.");
        }

        if (!string.IsNullOrWhiteSpace(poweredBy))
        {
            yield return Finding(check, tools, "Medium", "Lộ X-Powered-By",
                "Response tiết lộ framework/runtime.", $"X-Powered-By: {poweredBy}",
                "Gỡ header X-Powered-By trên ứng dụng.");
        }

        if (string.IsNullOrWhiteSpace(server) && string.IsNullOrWhiteSpace(poweredBy))
        {
            yield return Finding(check, tools, "Info", "Fingerprint hạn chế",
                "Không thấy Server/X-Powered-By rõ ràng.", null,
                "Tiếp tục giảm fingerprint bề mặt tấn công.");
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateCookies(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string? setCookie, bool hasHttps)
    {
        if (string.IsNullOrWhiteSpace(setCookie))
        {
            yield return Finding(check, tools, "Info", "Không có Set-Cookie",
                "Response không set cookie ở trang đích.", null,
                "Không có hành động bắt buộc.");
            yield break;
        }

        var lower = setCookie.ToLowerInvariant();
        if (hasHttps && !lower.Contains("secure"))
        {
            yield return Finding(check, tools, "High", "Cookie thiếu Secure",
                "Cookie được set trên HTTPS nhưng thiếu cờ Secure.", Truncate(setCookie),
                "Thêm Secure cho mọi cookie phiên.");
        }

        if (!lower.Contains("httponly"))
        {
            yield return Finding(check, tools, "Medium", "Cookie thiếu HttpOnly",
                "Cookie có thể bị JavaScript đọc.", Truncate(setCookie),
                "Thêm HttpOnly cho cookie phiên.");
        }

        if (!lower.Contains("samesite"))
        {
            yield return Finding(check, tools, "Medium", "Cookie thiếu SameSite",
                "Cookie không khai báo SameSite.", Truncate(setCookie),
                "Thêm SameSite=Lax hoặc Strict tùy use-case.");
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateCors(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string? corsOrigin)
    {
        if (string.IsNullOrWhiteSpace(corsOrigin))
        {
            yield return Finding(check, tools, "Info", "Không thấy ACAO trên response",
                "Không có Access-Control-Allow-Origin trong response GET.", null,
                "Nếu API dùng CORS, kiểm tra preflight riêng.");
            yield break;
        }

        if (corsOrigin.Trim() == "*")
        {
            yield return Finding(check, tools, "High", "CORS mở (*) ",
                "Access-Control-Allow-Origin cho phép mọi origin.", $"ACAO: {corsOrigin}",
                "Thu hẹp origin được phép; tránh * với credentialed requests.");
        }
        else
        {
            yield return Finding(check, tools, "Info", "CORS có giới hạn origin",
                "Access-Control-Allow-Origin không phải wildcard.", $"ACAO: {corsOrigin}",
                "Rà soát danh sách origin theo môi trường.");
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateDisclosure(
        ScanCheckDefinition check, IReadOnlyList<string> tools, Dictionary<string, string> headers, string? server, string? poweredBy)
    {
        var sensitive = new[] { "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via" };
        foreach (var key in sensitive)
        {
            if (headers.TryGetValue(key, out var value))
            {
                yield return Finding(check, tools, "Medium", $"Lộ header {key}",
                    "Header có thể hỗ trợ attacker fingerprint.", $"{key}: {value}",
                    $"Loại bỏ hoặc hạn chế {key}.");
            }
        }

        if (!string.IsNullOrWhiteSpace(server) || !string.IsNullOrWhiteSpace(poweredBy) ||
            sensitive.Any(headers.ContainsKey))
        {
            yield break;
        }

        yield return Finding(check, tools, "Info", "Không phát hiện disclosure rõ",
            "Không thấy các header nhạy cảm phổ biến.", null,
            "Tiếp tục hardening response headers.");
    }

    private static ScanFindingDto Finding(
        ScanCheckDefinition check,
        IReadOnlyList<string> tools,
        string severity,
        string title,
        string detail,
        string? evidence,
        string recommendation) =>
        new(check.Id, check.Name, severity, title, detail, evidence, recommendation, tools);

    private static int Score(IReadOnlyList<ScanFindingDto> findings)
    {
        var score = 0;
        foreach (var f in findings)
        {
            score += f.Severity switch
            {
                "High" => 25,
                "Medium" => 12,
                "Low" => 5,
                _ => 0
            };
        }
        return Math.Clamp(score, 0, 100);
    }

    private static string BuildExecutiveSummary(
        string targetUrl,
        IReadOnlyList<ScanFindingDto> findings,
        string riskLevel,
        string reportType)
    {
        var high = findings.Count(f => f.Severity == "High");
        var medium = findings.Count(f => f.Severity == "Medium");
        var baseText =
            $"Mục tiêu {targetUrl}: mức rủi ro {riskLevel} với {high} high / {medium} medium findings.";

        return reportType switch
        {
            "executive" => baseText + " Ưu tiên khắc phục các mục High trước khi release.",
            "owasp-summary" => baseText + " Các thiếu sót header/cookie/CORS liên quan baseline OWASP ASVS.",
            _ => baseText + " Xem chi tiết technical findings bên dưới."
        };
    }

    private static Dictionary<string, string> FlattenHeaders(HttpResponseMessage response)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in response.Headers)
            map[header.Key] = string.Join(", ", header.Value);
        foreach (var header in response.Content.Headers)
            map[header.Key] = string.Join(", ", header.Value);
        return map;
    }

    private static string Truncate(string value) =>
        value.Length <= 240 ? value : value[..240] + "…";

    private sealed record AnalysisResult(
        string Summary,
        int StatusCode,
        long ResponseTimeMs,
        bool HasHttps,
        string? ServerHeader,
        ScanReportPayloadDto Report);
}
