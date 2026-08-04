using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
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

            IEnumerable<ScanFindingDto> batch = check.Id switch
            {
                "reachability" => EvaluateReachability(check, tools, targetUrl, response, sw.ElapsedMilliseconds),
                "https-tls" => EvaluateHttps(check, tools, hasHttps, targetUrl),
                "security-headers" => EvaluateSecurityHeaders(check, tools, targetUrl, headers),
                "server-fingerprint" => EvaluateFingerprint(check, tools, targetUrl, server, poweredBy),
                "cookie-security" => EvaluateCookies(check, tools, targetUrl, setCookie, hasHttps),
                "cors-policy" => EvaluateCors(check, tools, targetUrl, corsOrigin),
                "information-disclosure" => EvaluateDisclosure(check, tools, targetUrl, headers, server, poweredBy),
                "port-scan" => await EvaluatePortScanAsync(check, tools, targetUrl, cancellationToken),
                "directory-discovery" => await EvaluateDirectoryDiscoveryAsync(client, check, tools, targetUrl, cancellationToken),
                "sensitive-file-scan" => await EvaluateSensitiveFilesAsync(client, check, tools, targetUrl, cancellationToken),
                "vulnerability-scan" => EvaluateVulnerabilityPlaceholder(check, tools, targetUrl),
                "technology-detection" => EvaluateTechnology(check, tools, headers, server, poweredBy),
                "screenshot" => EvaluateScreenshotPlaceholder(check, tools, targetUrl),
                "dns-security" => await EvaluateDnsAsync(check, tools, targetUrl, cancellationToken),
                "waf-detection" => EvaluateWaf(check, tools, headers, server),
                _ => []
            };
            findings.AddRange(batch);
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
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, HttpResponseMessage response, long ms)
    {
        var code = (int)response.StatusCode;
        if (code >= 500)
        {
            yield return Finding(check, tools, "High", "Máy chủ trả lỗi 5xx",
                ObservedImpact(
                    $"GET {targetUrl} → HTTP {code} trong {ms} ms.",
                    "Lỗi 5xx cho thấy ứng dụng/server không ổn định hoặc lỗi nội bộ — ảnh hưởng availability và có thể lộ stack trace."),
                $"method=GET; url={targetUrl}; status={code}; latency_ms={ms}",
                "Kiểm tra log server, health check và error handling; tránh trả stack trace ra client.",
                Steps(
                    $"curl -sI \"{targetUrl}\"",
                    $"Xác nhận status line là HTTP {code} (hoặc 5xx tương đương).",
                    "Thử lại vài lần để phân biệt lỗi tạm thời vs lỗi cố định."));
        }
        else if (code >= 400)
        {
            yield return Finding(check, tools, "Medium", "Máy chủ trả lỗi 4xx",
                ObservedImpact(
                    $"GET {targetUrl} → HTTP {code} trong {ms} ms.",
                    "4xx trên URL công khai có thể do path sai, auth, hoặc WAF chặn — cần xác nhận đây có phải entry point đúng không."),
                $"method=GET; url={targetUrl}; status={code}; latency_ms={ms}",
                "Xác nhận public URL/path và access control; kiểm tra redirect về trang hợp lệ.",
                Steps(
                    $"curl -sI \"{targetUrl}\"",
                    $"Ghi nhận status {code} và các header Location (nếu có).",
                    "So sánh với URL trang chủ/login mà người dùng thực tế truy cập."));
        }
        else
        {
            yield return Finding(check, tools, "Info", "Website reachable",
                $"Host phản hồi HTTP {code} trong {ms} ms.",
                $"status={code}; latency={ms}ms",
                "Giữ monitoring availability định kỳ.");
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateHttps(
        ScanCheckDefinition check, IReadOnlyList<string> tools, bool hasHttps, string url)
    {
        if (!hasHttps)
        {
            var httpsGuess = url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                ? "https://" + url["http://".Length..]
                : url;
            yield return Finding(check, tools, "High", "Không dùng HTTPS",
                ObservedImpact(
                    $"Target đang dùng HTTP thuần: {url}.",
                    "Traffic (cookie, token, form) có thể bị nghe lén/sửa trên đường truyền (MITM)."),
                $"scheme=http; url={url}",
                "Bắt buộc HTTPS, redirect HTTP→HTTPS, và cân nhắc HSTS.",
                Steps(
                    $"curl -sI \"{url}\"",
                    "Xác nhận không có redirect sang HTTPS (hoặc chỉ phục vụ HTTP).",
                    $"Thử \"{httpsGuess}\" — nếu HTTPS hoạt động, cấu hình redirect từ HTTP.",
                    "Mở DevTools → Security để xem connection không được mã hóa."));
        }
        else
        {
            yield return Finding(check, tools, "Info", "HTTPS được bật",
                "URL mục tiêu sử dụng HTTPS.", url,
                "Tiếp tục duy trì chứng chỉ hợp lệ và HSTS.");
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateSecurityHeaders(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, Dictionary<string, string> headers)
    {
        var required = new (string Header, string Severity, string Impact, string Expectation, string Recommendation)[]
        {
            ("Strict-Transport-Security", "High",
                "Không có HSTS → trình duyệt có thể bị downgrade về HTTP ở lần truy cập sau.",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                "Bật HSTS với max-age đủ lớn (và includeSubDomains khi phù hợp)."),
            ("Content-Security-Policy", "High",
                "Thiếu CSP làm tăng bề mặt XSS và injection tài nguyên không kiểm soát.",
                "Content-Security-Policy: default-src 'self'; … (theo policy ứng dụng)",
                "Thêm CSP (bắt đầu report-only nếu cần) để giảm XSS/injection."),
            ("X-Frame-Options", "Medium",
                "Thiếu bảo vệ clickjacking — trang có thể bị nhúng iframe độc hại.",
                "X-Frame-Options: DENY (hoặc SAMEORIGIN) / CSP frame-ancestors",
                "Thêm X-Frame-Options hoặc frame-ancestors trong CSP."),
            ("X-Content-Type-Options", "Medium",
                "Trình duyệt có thể MIME-sniff và thực thi nội dung không đúng kiểu.",
                "X-Content-Type-Options: nosniff",
                "Thêm X-Content-Type-Options: nosniff."),
            ("Referrer-Policy", "Low",
                "Referrer có thể lộ URL/query nhạy cảm sang bên thứ ba.",
                "Referrer-Policy: strict-origin-when-cross-origin (hoặc chặt hơn)",
                "Thêm Referrer-Policy phù hợp."),
            ("Permissions-Policy", "Low",
                "Browser features (camera, mic, …) có thể bị lạm dụng nếu không giới hạn.",
                "Permissions-Policy: geolocation=(), microphone=(), camera=()",
                "Giới hạn browser features bằng Permissions-Policy."),
        };

        foreach (var (header, severity, impact, expectation, recommendation) in required)
        {
            if (!headers.ContainsKey(header))
            {
                var isRisk = severity is "High" or "Medium";
                yield return Finding(check, tools, severity, $"Thiếu header {header}",
                    isRisk
                        ? ObservedImpact($"Response GET {targetUrl} không có header {header}.", impact)
                        : $"Response không có {header}.",
                    $"missing_header={header}; expected≈{expectation}",
                    recommendation,
                    isRisk
                        ? Steps(
                            $"curl -sI \"{targetUrl}\"",
                            $"Trong output, xác nhận không có dòng '{header}: …'.",
                            $"Sau khi fix, lặp lại lệnh và đối chiếu với kỳ vọng: {expectation}.")
                        : null);
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
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, string? server, string? poweredBy)
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
                ObservedImpact(
                    $"Header X-Powered-By = '{poweredBy}' trên {targetUrl}.",
                    "Attacker dùng thông tin framework/runtime để chọn CVE và payload phù hợp."),
                $"X-Powered-By: {poweredBy}",
                "Gỡ header X-Powered-By trên ứng dụng / reverse proxy.",
                Steps(
                    $"curl -sI \"{targetUrl}\"",
                    "Tìm dòng X-Powered-By và ghi nhận giá trị.",
                    "Sau khi tắt header, lặp lại curl và xác nhận đã biến mất."));
        }

        if (string.IsNullOrWhiteSpace(server) && string.IsNullOrWhiteSpace(poweredBy))
        {
            yield return Finding(check, tools, "Info", "Fingerprint hạn chế",
                "Không thấy Server/X-Powered-By rõ ràng.", null,
                "Tiếp tục giảm fingerprint bề mặt tấn công.");
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateCookies(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, string? setCookie, bool hasHttps)
    {
        if (string.IsNullOrWhiteSpace(setCookie))
        {
            yield return Finding(check, tools, "Info", "Không có Set-Cookie",
                "Response không set cookie ở trang đích.", null,
                "Không có hành động bắt buộc.");
            yield break;
        }

        var lower = setCookie.ToLowerInvariant();
        var cookieEvidence = SanitizeSetCookieEvidence(setCookie);

        if (hasHttps && !lower.Contains("secure"))
        {
            yield return Finding(check, tools, "High", "Cookie thiếu Secure",
                ObservedImpact(
                    "Ít nhất một Set-Cookie trên HTTPS không có cờ Secure.",
                    "Cookie phiên có thể bị gửi qua HTTP nếu user/attacker ép downgrade — lộ session."),
                cookieEvidence,
                "Thêm Secure cho mọi cookie phiên/authentication.",
                Steps(
                    $"curl -sI \"{targetUrl}\"",
                    "Tìm header Set-Cookie; xác nhận thiếu thuộc tính Secure.",
                    "DevTools → Application → Cookies: cột Secure phải được tick sau khi fix."));
        }

        if (!lower.Contains("httponly"))
        {
            yield return Finding(check, tools, "Medium", "Cookie thiếu HttpOnly",
                ObservedImpact(
                    "Ít nhất một Set-Cookie không có cờ HttpOnly.",
                    "Script XSS trên trang có thể đọc cookie và đánh cắp phiên."),
                cookieEvidence,
                "Thêm HttpOnly cho cookie phiên (không cần JS đọc).",
                Steps(
                    $"curl -sI \"{targetUrl}\"",
                    "Xác nhận Set-Cookie thiếu HttpOnly.",
                    "DevTools → Application → Cookies: cột HttpOnly phải được bật sau khi fix."));
        }

        if (!lower.Contains("samesite"))
        {
            yield return Finding(check, tools, "Medium", "Cookie thiếu SameSite",
                ObservedImpact(
                    "Ít nhất một Set-Cookie không khai báo SameSite.",
                    "Tăng nguy cơ CSRF khi cookie được gửi kèm cross-site request."),
                cookieEvidence,
                "Thêm SameSite=Lax hoặc Strict tùy use-case (None chỉ khi có Secure + nhu cầu cross-site).",
                Steps(
                    $"curl -sI \"{targetUrl}\"",
                    "Xác nhận Set-Cookie không có SameSite=…",
                    "DevTools → Application → Cookies: kiểm tra cột SameSite sau khi cấu hình."));
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateCors(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, string? corsOrigin)
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
            yield return Finding(check, tools, "High", "CORS mở (*)",
                ObservedImpact(
                    $"Access-Control-Allow-Origin: * trên response của {targetUrl}.",
                    "Mọi website độc hại có thể đọc response từ origin này bằng fetch/XHR (đặc biệt nguy hiểm với API có dữ liệu nhạy cảm)."),
                $"Access-Control-Allow-Origin: {corsOrigin}",
                "Thu hẹp allowlist origin; không dùng * với credentialed requests (cookies/Authorization).",
                Steps(
                    $"curl -sI -H \"Origin: https://evil.example\" \"{targetUrl}\"",
                    "Xác nhận response vẫn có Access-Control-Allow-Origin: * (hoặc echo origin).",
                    "Trong DevTools Console trên trang khác: fetch(target, {mode:'cors'}).then(r=>r.text()) — nếu đọc được body thì tái tạo thành công.",
                    "Sau khi fix, cùng lệnh curl phải không còn * / không reflect origin lạ."));
        }
        else
        {
            yield return Finding(check, tools, "Info", "CORS có giới hạn origin",
                "Access-Control-Allow-Origin không phải wildcard.", $"ACAO: {corsOrigin}",
                "Rà soát danh sách origin theo môi trường.");
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateDisclosure(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, Dictionary<string, string> headers, string? server, string? poweredBy)
    {
        var sensitive = new[] { "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via" };
        foreach (var key in sensitive)
        {
            if (headers.TryGetValue(key, out var value))
            {
                yield return Finding(check, tools, "Medium", $"Lộ header {key}",
                    ObservedImpact(
                        $"Response có {key}: {value}.",
                        "Thông tin phiên bản/stack hỗ trợ attacker chọn CVE và kỹ thuật tấn công chính xác hơn."),
                    $"{key}: {value}",
                    $"Loại bỏ hoặc hạn chế {key} ở web server / app middleware.",
                    Steps(
                        $"curl -sI \"{targetUrl}\"",
                        $"Tìm dòng '{key}: {value}'.",
                        "Sau khi gỡ header, lặp lại curl và xác nhận đã biến mất."));
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

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluatePortScanAsync(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, CancellationToken cancellationToken)
    {
        var host = new Uri(targetUrl).Host;
        var ports = new[] { 21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443 };
        var open = new List<int>();

        foreach (var port in ports)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromMilliseconds(700));
                using var client = new System.Net.Sockets.TcpClient();
                await client.ConnectAsync(host, port, cts.Token);
                open.Add(port);
            }
            catch
            {
                // closed / filtered
            }
        }

        if (open.Count > 0)
        {
            var risky = open.Where(p => p is 21 or 23 or 445 or 3306 or 3389 or 5432 or 6379).ToList();
            return
            [
                Finding(check, tools, "Medium",
                    $"Phát hiện {open.Count} cổng mở (probe nhanh)",
                    ObservedImpact(
                        $"TCP connect thành công tới {host} trên: {string.Join(", ", open)}.",
                        risky.Count > 0
                            ? $"Một số cổng nhạy cảm có thể lộ dịch vụ quản trị/DB ({string.Join(", ", risky)}) — tăng bề mặt tấn công."
                            : "Cổng mở làm tăng bề mặt quét/tấn công; cần xác nhận chỉ dịch vụ cần thiết được expose."),
                    $"host={host}; open={string.Join(',', open)}; ports_tested={ports.Length}",
                    "Chỉ mở cổng cần thiết trên firewall/NSG; gắn Naabu trên worker cho full port scan.",
                    Steps(
                        $"Test-NetConnection {host} -Port {open[0]}   # PowerShell",
                        $"hoặc: nc -vz {host} {string.Join(' ', open.Take(5))}",
                        "Đối chiếu danh sách open với inventory dịch vụ được phép public.",
                        "Sau khi đóng port, lặp lại probe và xác nhận timeout/refused."))
            ];
        }

        return
        [
            Finding(check, tools, "Info",
                "Không thấy cổng phổ biến mở (probe nhanh)",
                "Kết quả từ TCP probe nội bộ. Để quét toàn diện hãy chạy Naabu trên worker.",
                $"host={host}; ports_tested={ports.Length}",
                "Chỉ mở cổng cần thiết; gắn runner Naabu cho full port scan.")
        ];
    }

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateDirectoryDiscoveryAsync(
        HttpClient client, ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, CancellationToken cancellationToken)
    {
        var baseUri = new Uri(targetUrl.TrimEnd('/') + "/");
        var paths = new[]
        {
            "admin", "login", "dashboard", "api", "swagger", "graphql",
            "backup", "uploads", "static", "assets", "wp-admin", "robots.txt", "sitemap.xml"
        };

        var baseline = await ProbeUrlAsync(
            client,
            new Uri(baseUri, $".__sp_missing_{Guid.NewGuid():N}__/").ToString(),
            cancellationToken);

        var found = new List<(string Path, int Code, string Url, string Note)>();

        foreach (var path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var url = new Uri(baseUri, path).ToString();
                var probe = await ProbeUrlAsync(client, url, cancellationToken);
                if (probe is null) continue;

                var code = probe.StatusCode;
                if (code is 401 or 403)
                {
                    found.Add((path, code, url, "auth/forbidden"));
                    continue;
                }

                if (code is < 200 or >= 400) continue;
                if (IsSoft404OrSpaFallback(probe, baseline, path, allowHtml: true)) continue;

                // Directory/path hits: accept distinct content from baseline (HTML login/admin hợp lệ)
                found.Add((path, code, url, probe.ContentType ?? "unknown"));
            }
            catch
            {
                // ignore
            }
        }

        if (found.Count > 0)
        {
            var sample = found[0];
            return
            [
                Finding(check, tools, "Medium",
                    $"Directory probe: {found.Count} path phản hồi",
                    ObservedImpact(
                        $"Wordlist ngắn phát hiện {found.Count} path (đã lọc soft-404/SPA): {string.Join(", ", found.Select(f => $"{f.Path}({f.Code})"))}.",
                        "Path admin/backup/API lộ diện giúp attacker tập trung brute-force hoặc khai thác panel."),
                    string.Join("; ", found.Select(f => $"{f.Url} → {f.Code} [{f.Note}]")),
                    "Ẩn/ bảo vệ panel admin (IP allowlist, SSO); tắt directory listing; gắn Feroxbuster/FFUF cho discovery sâu.",
                    Steps(
                        $"curl -sI \"{sample.Url}\"",
                        $"Xác nhận status {sample.Code} và nội dung không phải trang HTML fallback.",
                        "Mở URL trên browser (nếu 200) hoặc ghi nhận trang login/403.",
                        "Sau khi hạn chế truy cập, lặp lại curl — kỳ vọng 404 hoặc chặn bởi WAF."))
            ];
        }

        return
        [
            Finding(check, tools, "Info",
                "Directory probe: không thấy path phổ biến",
                "Wordlist ngắn built-in (đã loại soft-404). Full discovery cần Feroxbuster/FFUF trên worker.",
                null,
                "Ẩn/ bảo vệ panel admin; gắn Feroxbuster hoặc FFUF cho discovery sâu.")
        ];
    }

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateSensitiveFilesAsync(
        HttpClient client, ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, CancellationToken cancellationToken)
    {
        var baseUri = new Uri(targetUrl.TrimEnd('/') + "/");
        var paths = new[]
        {
            ".env", ".git/config", ".git/HEAD", "web.config", "appsettings.json",
            "backup.sql", "dump.sql", "config.php", "phpinfo.php", ".DS_Store",
            "id_rsa", "server-status", "actuator/env", "api/swagger.json"
        };

        // Baseline: path chắc chắn không tồn tại — dùng để phát hiện soft-404 / SPA fallback (HTTP 200 + HTML).
        var baseline = await ProbeUrlAsync(
            client,
            new Uri(baseUri, $".__sp_missing_{Guid.NewGuid():N}__.txt").ToString(),
            cancellationToken);

        var hits = new List<(string Path, int Code, string Url, string EvidenceNote)>();

        foreach (var path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var url = new Uri(baseUri, path).ToString();
                var probe = await ProbeUrlAsync(client, url, cancellationToken);
                if (probe is null) continue;
                if (probe.StatusCode is < 200 or >= 300) continue;
                if (IsSoft404OrSpaFallback(probe, baseline, path, allowHtml: false)) continue;
                if (!LooksLikeSensitiveContent(path, probe)) continue;

                hits.Add((
                    path,
                    probe.StatusCode,
                    url,
                    $"ctype={probe.ContentType ?? "—"}; bytes={probe.BodyLength}; marker=validated"));
            }
            catch
            {
                // ignore
            }
        }

        if (hits.Count > 0)
        {
            var sample = hits[0];
            return
            [
                Finding(check, tools, "High", "Phát hiện file/path nhạy cảm có thể truy cập",
                    ObservedImpact(
                        $"Các path trả HTTP 2xx và đã xác thực nội dung (không phải soft-404/SPA): {string.Join(", ", hits.Select(h => $"{h.Path}({h.Code})"))}.",
                        "File cấu hình/backup/source có thể chứa secret, credential hoặc lộ cấu trúc hệ thống."),
                    string.Join("; ", hits.Select(h => $"{h.Url} → {h.Code}; {h.EvidenceNote}")),
                    "Gỡ file nhạy cảm khỏi web root ngay; chặn bằng server/WAF rules; rotate secret nếu đã lộ; chạy Nuclei định kỳ.",
                    Steps(
                        $"curl -sI \"{sample.Url}\"",
                        $"Xác nhận HTTP {sample.Code} và Content-Type phù hợp file thật (không phải text/html trang chủ).",
                        $"curl -s \"{sample.Url}\" | head  # đối chiếu nội dung có marker đặc trưng (cẩn thận secret)",
                        "Sau khi gỡ/chặn: cùng URL phải trả 404/403 (không còn soft-404 HTML)."))
            ];
        }

        return
        [
            Finding(check, tools, "Info", "Không thấy sensitive path phổ biến (probe ngắn)",
                "Đã lọc soft-404/SPA fallback (HTTP 200 giả). Chưa phát hiện file trong wordlist cơ bản sau khi xác thực nội dung.",
                baseline is null
                    ? null
                    : $"baseline_status={baseline.StatusCode}; baseline_ctype={baseline.ContentType ?? "—"}",
                "Giữ Nuclei trong pipeline CI/CD cho scan sâu.")
        ];
    }

    private sealed record UrlProbe(
        int StatusCode,
        string? ContentType,
        string BodySample,
        string FinalUrl,
        int BodyLength,
        string BodyFingerprint);

    private static async Task<UrlProbe?> ProbeUrlAsync(HttpClient client, string url, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var status = (int)response.StatusCode;
        var contentType = response.Content.Headers.ContentType?.MediaType;
        var finalUrl = response.RequestMessage?.RequestUri?.ToString() ?? url;

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[4096];
        var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
        var sample = Encoding.UTF8.GetString(buffer, 0, read);
        var fingerprint = Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, read)));

        return new UrlProbe(status, contentType, sample, finalUrl, read, fingerprint);
    }

    private static bool IsSoft404OrSpaFallback(
        UrlProbe probe,
        UrlProbe? baseline,
        string requestedPath,
        bool allowHtml)
    {
        // Redirected away from the requested path → thường là catch-all / login / home.
        if (!FinalUrlMatchesPath(probe.FinalUrl, requestedPath))
            return true;

        if (baseline is not null
            && probe.StatusCode == baseline.StatusCode
            && string.Equals(probe.ContentType, baseline.ContentType, StringComparison.OrdinalIgnoreCase)
            && (probe.BodyFingerprint == baseline.BodyFingerprint
                || BodiesNearlyIdentical(probe.BodySample, baseline.BodySample)))
        {
            return true;
        }

        // Sensitive files: SPA / soft-404 thường trả HTML shell thay vì file thật.
        if (!allowHtml && !PathExpectsHtml(requestedPath))
        {
            if (LooksLikeHtmlDocument(probe.BodySample))
                return true;
            if (IsHtmlContentType(probe.ContentType))
                return true;
        }

        return false;
    }

    private static bool FinalUrlMatchesPath(string finalUrl, string requestedPath)
    {
        if (!Uri.TryCreate(finalUrl, UriKind.Absolute, out var uri))
            return false;

        var path = uri.AbsolutePath.TrimEnd('/');
        var expected = "/" + requestedPath.TrimStart('/');
        return path.EndsWith(expected, StringComparison.OrdinalIgnoreCase)
               || path.Equals(expected, StringComparison.OrdinalIgnoreCase);
    }

    private static bool BodiesNearlyIdentical(string a, string b)
    {
        var na = NormalizeBody(a);
        var nb = NormalizeBody(b);
        if (na.Length == 0 || nb.Length == 0) return na.Length == nb.Length;
        var take = Math.Min(512, Math.Min(na.Length, nb.Length));
        return string.Equals(na[..take], nb[..take], StringComparison.Ordinal);
    }

    private static string NormalizeBody(string value) =>
        Regex.Replace(value ?? string.Empty, @"\s+", " ").Trim();

    private static bool LooksLikeHtmlDocument(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var sample = body.AsSpan(0, Math.Min(body.Length, 2048));
        return sample.Contains("<html", StringComparison.OrdinalIgnoreCase)
               || sample.Contains("<!doctype html", StringComparison.OrdinalIgnoreCase)
               || sample.Contains("<head", StringComparison.OrdinalIgnoreCase)
               || sample.Contains("<body", StringComparison.OrdinalIgnoreCase)
               || sample.Contains("<div id=\"root\"", StringComparison.OrdinalIgnoreCase)
               || sample.Contains("<div id=\"app\"", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsHtmlContentType(string? contentType) =>
        !string.IsNullOrWhiteSpace(contentType)
        && (contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase)
            || contentType.Contains("application/xhtml", StringComparison.OrdinalIgnoreCase));

    private static bool PathExpectsHtml(string path) =>
        path.Equals("phpinfo.php", StringComparison.OrdinalIgnoreCase)
        || path.Equals("server-status", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeSensitiveContent(string path, UrlProbe probe)
    {
        var body = probe.BodySample ?? string.Empty;
        var lower = body.ToLowerInvariant();

        return path.ToLowerInvariant() switch
        {
            ".env" => Regex.IsMatch(body, @"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=", RegexOptions.Multiline)
                      || lower.Contains("app_key=")
                      || lower.Contains("db_password=")
                      || lower.Contains("aws_secret"),
            ".git/config" => lower.Contains("[core]") || lower.Contains("[remote") || lower.Contains("repositoryformatversion"),
            ".git/head" => lower.Contains("ref:") || Regex.IsMatch(body, @"^[0-9a-f]{40}\s*$", RegexOptions.IgnoreCase | RegexOptions.Multiline),
            "web.config" => lower.Contains("<configuration") || lower.Contains("<?xml"),
            "appsettings.json" => body.TrimStart().StartsWith('{')
                                  && (lower.Contains("\"connectionstrings\"")
                                      || lower.Contains("\"logging\"")
                                      || lower.Contains("\"allowedhosts\"")
                                      || lower.Contains("\"appsettings\"")),
            "backup.sql" or "dump.sql" => lower.Contains("create table")
                                          || lower.Contains("insert into")
                                          || lower.Contains("drop table")
                                          || lower.Contains("-- mysql")
                                          || lower.Contains("postgresql"),
            "config.php" => lower.Contains("<?php") || lower.Contains("<?="),
            "phpinfo.php" => lower.Contains("php version") || lower.Contains("phpinfo()") || lower.Contains("<title>phpinfo"),
            ".ds_store" => probe.BodyLength >= 4 && !LooksLikeHtmlDocument(body),
            "id_rsa" => lower.Contains("begin") && lower.Contains("private key"),
            "server-status" => lower.Contains("apache") || lower.Contains("server status") || lower.Contains("current time"),
            "actuator/env" => lower.Contains("propertysources")
                              || lower.Contains("activeprofiles")
                              || (body.TrimStart().StartsWith('{') && lower.Contains("\"property\"")),
            "api/swagger.json" => lower.Contains("\"swagger\"")
                                  || lower.Contains("\"openapi\"")
                                  || lower.Contains("\"paths\""),
            _ => !LooksLikeHtmlDocument(body) && probe.BodyLength > 0
        };
    }

    private static IEnumerable<ScanFindingDto> EvaluateVulnerabilityPlaceholder(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl)
    {
        yield return Finding(check, tools, "Info", "Vulnerability Scan đã chọn (Nuclei)",
            "Module này yêu cầu runner Nuclei với template pack. Hiện portal ghi nhận cấu hình để worker thực thi.",
            $"target={targetUrl}; tool=nuclei",
            "Triển khai SecurityPortal.Worker gắn Nuclei (CVE + misconfig templates).");
    }

    private static IEnumerable<ScanFindingDto> EvaluateTechnology(
        ScanCheckDefinition check,
        IReadOnlyList<string> tools,
        Dictionary<string, string> headers,
        string? server,
        string? poweredBy)
    {
        var tech = new List<string>();
        if (!string.IsNullOrWhiteSpace(server)) tech.Add($"Server:{server}");
        if (!string.IsNullOrWhiteSpace(poweredBy)) tech.Add($"X-Powered-By:{poweredBy}");
        if (headers.ContainsKey("X-AspNet-Version") || headers.ContainsKey("X-AspNetMvc-Version")) tech.Add("ASP.NET");
        string? gen = null;
        if (headers.TryGetValue("X-Generator", out gen)) tech.Add($"Generator:{gen}");
        if (headers.ContainsKey("CF-Ray") || (server?.Contains("cloudflare", StringComparison.OrdinalIgnoreCase) ?? false))
            tech.Add("Cloudflare");
        if (headers.ContainsKey("X-Drupal-Cache") || (gen?.Contains("Drupal", StringComparison.OrdinalIgnoreCase) == true))
            tech.Add("Drupal");

        yield return Finding(check, tools, tech.Count > 0 ? "Low" : "Info",
            tech.Count > 0 ? "Technology signals phát hiện" : "Ít tín hiệu technology từ header",
            "Suy luận từ header (built-in). WhatWeb/Wappalyzer cho kết quả đầy đủ hơn.",
            tech.Count > 0 ? string.Join("; ", tech) : null,
            "Giảm fingerprint; gắn WhatWeb/Wappalyzer trên worker để detect sâu.");
    }

    private static IEnumerable<ScanFindingDto> EvaluateScreenshotPlaceholder(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl)
    {
        yield return Finding(check, tools, "Info", "Screenshot module đã chọn (Gowitness)",
            "Cần runner Gowitness + lưu ảnh lên MinIO. Portal đã ghi nhận yêu cầu trong cấu hình scan.",
            $"target={targetUrl}; tool=gowitness",
            "Triển khai worker Screenshot (Gowitness) và gắn MinIO bucket evidence.");
    }

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateDnsAsync(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, CancellationToken cancellationToken)
    {
        var host = new Uri(targetUrl).Host;
        try
        {
            var addresses = await System.Net.Dns.GetHostAddressesAsync(host, cancellationToken);
            var evidence = string.Join(", ", addresses.Select(a => a.ToString()));
            return
            [
                Finding(check, tools, "Info", "DNS resolve thành công",
                    "Resolve A/AAAA qua DNS hệ thống. dnsx bổ sung CNAME/NS/MX/TXT và wildcard detection.",
                    $"host={host}; addrs={evidence}",
                    "Giám sát thay đổi DNS; gắn dnsx cho kiểm tra DNS security đầy đủ.")
            ];
        }
        catch (Exception ex)
        {
            return
            [
                Finding(check, tools, "High", "DNS resolve thất bại",
                    ObservedImpact(
                        $"Không resolve được host '{host}' cho {targetUrl}.",
                        "Target không tới được qua DNS — scan/khách hàng đều thất bại; có thể lỗi cấu hình hoặc nameserver."),
                    $"host={host}; error={ex.Message}",
                    "Kiểm tra DNS record và nameserver; chạy dnsx để chẩn đoán.",
                    Steps(
                        $"nslookup {host}",
                        $"Resolve-DnsName {host}   # PowerShell",
                        "Đối chiếu lỗi với registrar/DNS zone (A/AAAA thiếu hoặc nameserver sai).",
                        "Sau khi sửa DNS, lặp lại resolve và mở lại target URL."))
            ];
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateWaf(
        ScanCheckDefinition check, IReadOnlyList<string> tools, Dictionary<string, string> headers, string? server)
    {
        var signals = new List<string>();
        if (headers.ContainsKey("CF-Ray") || headers.ContainsKey("CF-Cache-Status")) signals.Add("Cloudflare");
        if (headers.ContainsKey("X-Sucuri-ID") || headers.ContainsKey("X-Sucuri-Cache")) signals.Add("Sucuri");
        if (headers.ContainsKey("X-Akamai-Transformed") || headers.ContainsKey("Akamai-Origin-Hop")) signals.Add("Akamai");
        if (headers.ContainsKey("X-CDN") || headers.ContainsKey("X-Iinfo")) signals.Add("Imperva/Incapsula?");
        if (server?.Contains("cloudflare", StringComparison.OrdinalIgnoreCase) == true && !signals.Contains("Cloudflare"))
            signals.Add("Cloudflare");

        if (signals.Count > 0)
        {
            yield return Finding(check, tools, "Info", $"WAF/CDN fingerprint: {string.Join(", ", signals)}",
                "Nhận diện qua header. wafw00f xác nhận chính xác hơn bằng probe chủ động.",
                string.Join("; ", signals),
                "Giữ WAF rules cập nhật; dùng wafw00f trong pipeline để verify vendor.");
        }
        else
        {
            yield return Finding(check, tools, "Low", "Không thấy WAF fingerprint rõ từ header",
                "Có thể không có WAF hoặc WAF ẩn fingerprint. Xác minh bằng wafw00f.",
                null,
                "Cân nhắc triển khai WAF; chạy wafw00f để xác nhận.");
        }
    }

    private static string ObservedImpact(string observed, string impact) =>
        $"Observed: {observed}\nImpact: {impact}";

    private static IReadOnlyList<string> Steps(params string[] steps) => steps;

    private static string SanitizeSetCookieEvidence(string setCookie)
    {
        var names = new List<string>();
        foreach (var segment in setCookie.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var first = segment.Split(';', 2)[0].Trim();
            var eq = first.IndexOf('=');
            var name = eq > 0 ? first[..eq] : first;
            if (!string.IsNullOrWhiteSpace(name) && !names.Contains(name, StringComparer.OrdinalIgnoreCase))
                names.Add(name);
        }

        var lower = setCookie.ToLowerInvariant();
        var flags = new List<string>();
        if (lower.Contains("secure")) flags.Add("Secure");
        if (lower.Contains("httponly")) flags.Add("HttpOnly");
        if (lower.Contains("samesite")) flags.Add("SameSite");

        var namePart = names.Count > 0 ? string.Join(", ", names) : "(unknown)";
        var flagPart = flags.Count > 0 ? string.Join(", ", flags) : "(none of Secure/HttpOnly/SameSite detected)";
        return $"cookies=[{namePart}]; flags_present=[{flagPart}]; raw_length={setCookie.Length}";
    }

    private static ScanFindingDto Finding(
        ScanCheckDefinition check,
        IReadOnlyList<string> tools,
        string severity,
        string title,
        string detail,
        string? evidence,
        string recommendation,
        IReadOnlyList<string>? reproductionSteps = null) =>
        new(check.Id, check.Name, severity, title, detail, evidence, recommendation, tools, reproductionSteps);

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
