using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.Scans.DTOs;
using SecurityPortal.Application.Features.Scans.Localization;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.API.Services;

public sealed class WebsiteScanProcessor(
    IServiceScopeFactory scopeFactory,
    IHttpClientFactory httpClientFactory,
    ScanCancellationRegistry cancelRegistry,
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

    private async Task ProcessBatchAsync(CancellationToken stoppingToken)
    {
        using var scope = scopeFactory.CreateScope();
        var scans = scope.ServiceProvider.GetRequiredService<IWebsiteScanRepository>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var db = scope.ServiceProvider.GetRequiredService<SecurityPortal.Infrastructure.Persistence.ApplicationDbContext>();

        var queued = await scans.GetQueuedAsync(5, stoppingToken);
        if (queued.Count == 0) return;

        var client = httpClientFactory.CreateClient("WebsiteScanner");

        foreach (var scan in queued)
        {
            if (await IsCancelledAsync(scan.Id, stoppingToken))
            {
                db.Entry(scan).State = Microsoft.EntityFrameworkCore.EntityState.Detached;
                continue;
            }

            var scanAbort = cancelRegistry.Register(scan.Id);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, scanAbort);
            var scanToken = linked.Token;

            scan.MarkRunning();
            await unitOfWork.SaveChangesAsync(stoppingToken);

            try
            {
                var config = scan.GetConfiguration();
                var result = await AnalyzeAsync(client, scan.Id, scan.TargetUrl, config, scanToken);

                // Drop tracked entity so we cannot overwrite a concurrent Cancelled row.
                db.Entry(scan).State = Microsoft.EntityFrameworkCore.EntityState.Detached;
                var fresh = await scans.GetByIdAsync(scan.Id, stoppingToken);
                if (fresh is null || fresh.Status == ScanStatus.Cancelled)
                    continue;

                if (fresh.Status != ScanStatus.Running)
                    continue;

                var findingsJson = JsonSerializer.Serialize(result.Report, JsonOptions);
                fresh.MarkCompleted(
                    result.Summary,
                    result.StatusCode,
                    result.ResponseTimeMs,
                    result.HasHttps,
                    result.ServerHeader,
                    findingsJson);

                // Final cancel race: if stop landed after analyze, drop local complete.
                if (await IsCancelledAsync(scan.Id, stoppingToken))
                {
                    db.Entry(fresh).State = Microsoft.EntityFrameworkCore.EntityState.Detached;
                    continue;
                }

                await unitOfWork.SaveChangesAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (scanAbort.IsCancellationRequested && !stoppingToken.IsCancellationRequested)
            {
                logger.LogInformation("Scan {ScanId} cancelled for {Url}", scan.Id, scan.TargetUrl);
                db.Entry(scan).State = Microsoft.EntityFrameworkCore.EntityState.Detached;
                // Ensure DB row is Cancelled even if abort raced ahead of ExecuteUpdate.
                await scans.TryCancelAsync(scan.Id, "Scan cancelled by user.", CancellationToken.None);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Scan {ScanId} failed for {Url}", scan.Id, scan.TargetUrl);
                db.Entry(scan).State = Microsoft.EntityFrameworkCore.EntityState.Detached;
                var fresh = await scans.GetByIdAsync(scan.Id, stoppingToken);
                if (fresh is not null && fresh.Status == ScanStatus.Running)
                {
                    fresh.MarkFailed(ex.Message);
                    await unitOfWork.SaveChangesAsync(stoppingToken);
                }
            }
            finally
            {
                cancelRegistry.Unregister(scan.Id);
            }
        }
    }

    private async Task<bool> IsCancelledAsync(Guid scanId, CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var scans = scope.ServiceProvider.GetRequiredService<IWebsiteScanRepository>();
        var current = await scans.GetByIdAsync(scanId, cancellationToken);
        return current?.Status == ScanStatus.Cancelled;
    }

    private async Task EnsureNotCancelledAsync(Guid scanId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (await IsCancelledAsync(scanId, cancellationToken))
            throw new OperationCanceledException("Scan cancelled by user.");
    }

    private async Task<AnalysisResult> AnalyzeAsync(
        HttpClient client,
        Guid scanId,
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
            await EnsureNotCancelledAsync(scanId, cancellationToken);

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

        await EnsureNotCancelledAsync(scanId, cancellationToken);

        var riskScore = Score(findings);
        var riskLevel = riskScore >= 70 ? "High" : riskScore >= 40 ? "Medium" : "Low";
        var reportDef = ScanCatalog.Reports.First(r => r.Id.Equals(config.ReportType, StringComparison.OrdinalIgnoreCase));

        var executive = ScanI18n.BuildExecutiveSummary(
            targetUrl, riskLevel, findings.Count(f => f.Severity == "High"),
            findings.Count(f => f.Severity == "Medium"), config.ReportType, "en");
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
        var status = (int)response.StatusCode;
        var code = status >= 500 ? "reachability.5xx" : status >= 400 ? "reachability.4xx" : "reachability.ok";
        var severity = status >= 500 ? "High" : status >= 400 ? "Medium" : "Info";
        yield return Finding(check, tools, severity, code, P(
            ("targetUrl", targetUrl), ("status", status.ToString()), ("observed", $"GET {targetUrl} returned HTTP {status} in {ms} ms."),
            ("impact", status >= 500 ? "The service may be unavailable or expose internal errors." : status >= 400 ? "The public entry point may be incorrect or blocked." : "")),
            $"method=GET; url={targetUrl}; status={status}; latency_ms={ms}");
    }

    private static IEnumerable<ScanFindingDto> EvaluateHttps(
        ScanCheckDefinition check, IReadOnlyList<string> tools, bool hasHttps, string url)
    {
        if (!hasHttps)
        {
            var httpsGuess = url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                ? "https://" + url["http://".Length..]
                : url;
            yield return Finding(check, tools, "High", "https.missing", P(
                ("targetUrl", url), ("httpsUrl", httpsGuess), ("observed", $"The target uses unencrypted HTTP: {url}."),
                ("impact", "Cookies, tokens, and forms can be intercepted or modified in transit.")), $"scheme=http; url={url}");
        }
        else
        {
            yield return Finding(check, tools, "Info", "https.ok", P(("targetUrl", url)), url);
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
                yield return Finding(check, tools, severity, "header.missing", P(
                    ("header", header), ("targetUrl", targetUrl), ("expectation", expectation), ("recommendation", recommendation),
                    ("observed", $"GET response does not include {header}."), ("impact", impact)),
                    $"missing_header={header}; expected={expectation}");
            }
        }

        if (required.All(r => headers.ContainsKey(r.Header)))
        {
            yield return Finding(check, tools, "Info", "header.ok", P(("targetUrl", targetUrl)), null);
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateFingerprint(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, string? server, string? poweredBy)
    {
        if (!string.IsNullOrWhiteSpace(server))
        {
            yield return Finding(check, tools, "Low", "fingerprint.server", P(
                ("server", server), ("impact", "Server information helps attackers fingerprint the stack.")), $"Server: {server}");
        }

        if (!string.IsNullOrWhiteSpace(poweredBy))
        {
            yield return Finding(check, tools, "Medium", "fingerprint.powered_by", P(
                ("targetUrl", targetUrl), ("observed", $"X-Powered-By: {poweredBy}"), ("impact", "Framework information can help target CVEs.")), $"X-Powered-By: {poweredBy}");
        }

        if (string.IsNullOrWhiteSpace(server) && string.IsNullOrWhiteSpace(poweredBy))
        {
            yield return Finding(check, tools, "Info", "fingerprint.ok", P(), null);
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateCookies(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, string? setCookie, bool hasHttps)
    {
        if (string.IsNullOrWhiteSpace(setCookie))
        {
            yield return Finding(check, tools, "Info", "cookie.none", P(("targetUrl", targetUrl)), null);
            yield break;
        }

        var lower = setCookie.ToLowerInvariant();
        var cookieEvidence = SanitizeSetCookieEvidence(setCookie);

        if (hasHttps && !lower.Contains("secure"))
        {
            yield return Finding(check, tools, "High", "cookie.secure", P(
                ("targetUrl", targetUrl), ("observed", "At least one HTTPS Set-Cookie lacks Secure."), ("impact", "A session cookie could be exposed after an HTTP downgrade.")), cookieEvidence);
        }

        if (!lower.Contains("httponly"))
        {
            yield return Finding(check, tools, "Medium", "cookie.httponly", P(
                ("targetUrl", targetUrl), ("observed", "At least one Set-Cookie lacks HttpOnly."), ("impact", "XSS could read and steal the session cookie.")), cookieEvidence);
        }

        if (!lower.Contains("samesite"))
        {
            yield return Finding(check, tools, "Medium", "cookie.samesite", P(
                ("targetUrl", targetUrl), ("observed", "At least one Set-Cookie lacks SameSite."), ("impact", "Cross-site requests may increase CSRF risk.")), cookieEvidence);
        }
    }

    private static IEnumerable<ScanFindingDto> EvaluateCors(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, string? corsOrigin)
    {
        if (string.IsNullOrWhiteSpace(corsOrigin))
        {
            yield return Finding(check, tools, "Info", "cors.none", P(("targetUrl", targetUrl)), null);
            yield break;
        }

        if (corsOrigin.Trim() == "*")
        {
            yield return Finding(check, tools, "High", "cors.wildcard", P(
                ("targetUrl", targetUrl), ("observed", $"Access-Control-Allow-Origin: {corsOrigin}"),
                ("impact", "Any website may be able to read responses from this origin.")), $"Access-Control-Allow-Origin: {corsOrigin}");
        }
        else
        {
            yield return Finding(check, tools, "Info", "cors.ok", P(("origin", corsOrigin)), $"Access-Control-Allow-Origin: {corsOrigin}");
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
                yield return Finding(check, tools, "Medium", "disclosure.header", P(
                    ("key", key), ("value", value), ("targetUrl", targetUrl),
                    ("impact", "Version and stack information can help attackers select targeted exploits.")), $"{key}: {value}");
            }
        }

        if (!string.IsNullOrWhiteSpace(server) || !string.IsNullOrWhiteSpace(poweredBy) ||
            sensitive.Any(headers.ContainsKey))
        {
            yield break;
        }

        yield return Finding(check, tools, "Info", "disclosure.ok", P(), null);
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
                Finding(check, tools, "Medium", "port.open", P(
                    ("host", host), ("port", open[0].ToString()), ("observed", $"TCP connections succeeded to {host} on {string.Join(", ", open)}."),
                    ("impact", risky.Count > 0 ? $"Sensitive management or database ports are exposed: {string.Join(", ", risky)}." : "Open ports increase the attack surface.")),
                    $"host={host}; open={string.Join(',', open)}; ports_tested={ports.Length}")
            ];
        }

        return
        [
            Finding(check, tools, "Info", "port.none", P(("host", host)), $"host={host}; ports_tested={ports.Length}")
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
                Finding(check, tools, "Medium", "directory.found", P(
                    ("url", sample.Url), ("status", sample.Code.ToString()),
                    ("observed", $"The built-in wordlist found {found.Count} paths: {string.Join(", ", found.Select(f => $"{f.Path}({f.Code})"))}."),
                    ("impact", "Exposed administration, backup, or API paths can focus attacker activity.")),
                    string.Join("; ", found.Select(f => $"{f.Url} -> {f.Code} [{f.Note}]")))
            ];
        }

        return
        [
            Finding(check, tools, "Info", "directory.none", P(("targetUrl", targetUrl)), null)
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
                Finding(check, tools, "High", "sensitive.found", P(
                    ("url", sample.Url), ("status", sample.Code.ToString()),
                    ("observed", $"Validated sensitive paths returned HTTP 2xx: {string.Join(", ", hits.Select(h => $"{h.Path}({h.Code})"))}."),
                    ("impact", "Configuration, backup, or source files may expose secrets and system details.")),
                    string.Join("; ", hits.Select(h => $"{h.Url} -> {h.Code}; {h.EvidenceNote}")))
            ];
        }

        return
        [
            Finding(check, tools, "Info", "sensitive.none", P(("targetUrl", targetUrl)),
                baseline is null ? null : $"baseline_status={baseline.StatusCode}; baseline_ctype={baseline.ContentType ?? "unknown"}")
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
        yield return Finding(check, tools, "Info", "vuln.placeholder", P(("targetUrl", targetUrl)), $"target={targetUrl}; tool=nuclei");
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
            tech.Count > 0 ? "tech.found" : "tech.none",
            P(("tech", string.Join("; ", tech))), tech.Count > 0 ? string.Join("; ", tech) : null);
    }

    private static IEnumerable<ScanFindingDto> EvaluateScreenshotPlaceholder(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl)
    {
        yield return Finding(check, tools, "Info", "screenshot.placeholder", P(("targetUrl", targetUrl)), $"target={targetUrl}; tool=gowitness");
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
                Finding(check, tools, "Info", "dns.ok", P(("host", host), ("addresses", evidence)), $"host={host}; addrs={evidence}")
            ];
        }
        catch (Exception ex)
        {
            return
            [
                Finding(check, tools, "High", "dns.fail", P(
                    ("host", host), ("targetUrl", targetUrl), ("observed", $"DNS could not resolve {host}: {ex.Message}"),
                    ("impact", "The target is unavailable through DNS to scanners and users.")), $"host={host}; error={ex.Message}")
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
            yield return Finding(check, tools, "Info", "waf.found", P(("signals", string.Join(", ", signals))), string.Join("; ", signals));
        }
        else
        {
            yield return Finding(check, tools, "Low", "waf.none", P(), null);
        }
    }

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
        string code,
        IReadOnlyDictionary<string, string> parameters,
        string? evidence)
    {
        var resolved = ScanI18n.ResolveFinding(code, parameters, "en");
        return new ScanFindingDto(
            check.Id, ScanI18n.CheckName(check.Id, "en"), severity, resolved.Title,
            resolved.Detail, evidence, resolved.Recommendation, tools, resolved.Steps, code, parameters);
    }

    private static IReadOnlyDictionary<string, string> P(params (string Key, string? Value)[] values) =>
        values.ToDictionary(value => value.Key, value => value.Value ?? string.Empty, StringComparer.OrdinalIgnoreCase);

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
