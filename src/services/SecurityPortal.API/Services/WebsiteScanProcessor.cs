using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.Scans.DTOs;
using SecurityPortal.Application.Features.Scans.Localization;
using SecurityPortal.Domain.Entities;
using SecurityPortal.Domain.Scanning;
using SecurityPortal.Domain.Security;

namespace SecurityPortal.API.Services;

public sealed class WebsiteScanProcessor(
    IServiceScopeFactory scopeFactory,
    ScanCancellationRegistry cancelRegistry,
    IScanSecretProtector secretProtector,
    ILogger<WebsiteScanProcessor> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static readonly ScanCheckDefinition AuthCheckDef = new(
        "authenticated-scan",
        "Authenticated Scan",
        "Login then scan post-auth areas.",
        ["http-probe"],
        false,
        "owasp",
        4);

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
                using var handler = CreateScanHandler();
                using var client = CreateScanClient(handler);
                IFileStorage? fileStorage = null;
                try { fileStorage = scope.ServiceProvider.GetService<IFileStorage>(); }
                catch { /* optional */ }
                var result = await AnalyzeAsync(handler, client, scan.Id, scan.TargetUrl, config, fileStorage, scanToken);

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
                logger.LogWarning("Scan {ScanId} failed for {Url}: {Error}",
                    scan.Id, scan.TargetUrl, ScanSecretSanitizer.Sanitize(ex.Message));
                db.Entry(scan).State = Microsoft.EntityFrameworkCore.EntityState.Detached;
                var fresh = await scans.GetByIdAsync(scan.Id, stoppingToken);
                if (fresh is not null && fresh.Status == ScanStatus.Running)
                {
                    // Persist actionable diagnostics (DB column ~2000 chars).
                    var detail = ex is ArgumentOutOfRangeException aro
                        ? $"ArgumentOutOfRangeException param={aro.ParamName} actual={aro.ActualValue}. {aro}"
                        : ex.ToString();
                    if (detail.Length > 1900) detail = detail[..1900] + "…";
                    fresh.MarkFailed(ScanSecretSanitizer.Sanitize(detail));
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

    private static HttpClientHandler CreateScanHandler() =>
        // AllowAutoRedirect=false: hops go through SendWithSafeRedirectsAsync (SSRF checks).
        // Never set MaxAutomaticRedirections=0 — that assignment throws ArgumentOutOfRangeException.
        ScanHttpClientFactory.CreateHandler(allowAutoRedirect: false);

    private static HttpClient CreateScanClient(HttpClientHandler handler) =>
        ScanHttpClientFactory.CreateClient(handler, disposeHandler: false);

    private async Task<AnalysisResult> AnalyzeAsync(
        HttpClientHandler handler,
        HttpClient client,
        Guid scanId,
        string targetUrl,
        ScanConfiguration config,
        IFileStorage? fileStorage,
        CancellationToken cancellationToken)
    {
        // Re-check at runtime (DNS may have changed since queue).
        ScanHostSafety.EnsureSafeHttpTarget(targetUrl, "Website URL");

        var authFindings = new List<ScanFindingDto>();
        var sourceFindings = new List<ScanFindingDto>();
        var sourceProbePaths = new List<string>();
        var sourceProbeRoutes = new List<SourceRouteInventoryAnalyzer.ProbeRoute>();
        var authenticated = false;
        string? authNote = null;

        if (config.Source?.IsEnabled == true
            && !config.Checks.Contains(SourceRouteInventoryAnalyzer.CheckId, StringComparer.OrdinalIgnoreCase))
        {
            config.Checks.Add(SourceRouteInventoryAnalyzer.CheckId);
            if (!config.Tools.Contains("source-analyzer", StringComparer.OrdinalIgnoreCase))
                config.Tools.Add("source-analyzer");
        }

        if (config.Source?.IsEnabled == true)
        {
            await EnsureNotCancelledAsync(scanId, cancellationToken);
            var inventory = await SourceRouteInventoryAnalyzer.AnalyzeAsync(
                scanId, config.Source, secretProtector, fileStorage, logger, cancellationToken);
            sourceFindings.AddRange(inventory.Findings);
            sourceProbePaths.AddRange(inventory.ProbePaths);
            sourceProbeRoutes.AddRange(inventory.ProbeRoutes);
        }

        // Anonymous runtime probes against source-discovered API paths (does not require login).
        if (sourceProbeRoutes.Count > 0 || sourceProbePaths.Count > 0)
        {
            await EnsureNotCancelledAsync(scanId, cancellationToken);
            sourceFindings.AddRange(await EvaluateSourceRouteProbesAsync(
                client, targetUrl, sourceProbeRoutes, sourceProbePaths, cancellationToken));
        }

        if (config.Auth?.IsEnabled == true)
        {
            await EnsureNotCancelledAsync(scanId, cancellationToken);
            var login = await TryAuthenticateAsync(client, targetUrl, config.Auth, cancellationToken);
            authenticated = login.Success;
            authNote = login.Message;
            authFindings.Add(login.Success
                ? Finding(AuthCheckDef, AuthCheckDef.Tools, "Info", "auth.ok",
                    P(("observed", login.Message), ("authType", config.Auth.Type), ("loginUrl", login.LoginUrl)),
                    $"authType={config.Auth.Type}; loginUrl={login.LoginUrl}")
                : Finding(AuthCheckDef, AuthCheckDef.Tools, "High", "auth.failed",
                    P(("observed", RedactSecrets(login.Message, config.Auth)),
                        ("impact", "Post-login checks may be incomplete or skipped."),
                        ("loginUrl", login.LoginUrl),
                        ("authType", config.Auth.Type)),
                    $"authType={config.Auth.Type}; loginUrl={login.LoginUrl}"));

            if (login.Success)
            {
                await EnsureNotCancelledAsync(scanId, cancellationToken);
                authFindings.AddRange(await EvaluateAuthenticatedSurfaceAsync(
                    handler, client, targetUrl, sourceProbePaths, cancellationToken));
            }
            else
            {
                authFindings.Add(Finding(AuthCheckDef, AuthCheckDef.Tools, "Info", "auth.coverage.skipped",
                    P(("observed", "Authenticated surface probes were skipped because login failed."),
                        ("impact", "Post-login API, session-cookie, and authz-diff checks were not run.")),
                    "coverage=skipped"));
            }
        }

        var sw = Stopwatch.StartNew();
        using var request = new HttpRequestMessage(HttpMethod.Get, targetUrl);
        using var response = await SendWithSafeRedirectsAsync(
            client,
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
            .Where(c => !c.Id.Equals("authenticated-scan", StringComparison.OrdinalIgnoreCase)
                        && !c.Id.Equals(SourceRouteInventoryAnalyzer.CheckId, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var deepClient = client;

        var findings = new List<ScanFindingDto>();
        findings.AddRange(sourceFindings);
        findings.AddRange(authFindings);

        // Secondary API/GraphQL hosts (Clever-style backends, cookie domains) for Nuclei/Ferox/FFUF.
        var secondaryTargets = BuildSecondaryScanTargets(handler, targetUrl);
        // Promote source-discovered API URLs onto the same fan-out list (capped).
        foreach (var sourceUrl in BuildSourceAbsoluteUrls(targetUrl, sourceProbePaths).Take(8))
        {
            if (!secondaryTargets.Any(t => string.Equals(t, sourceUrl, StringComparison.OrdinalIgnoreCase))
                && !string.Equals(sourceUrl.TrimEnd('/'), targetUrl.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
            {
                secondaryTargets.Add(sourceUrl);
            }
        }

        // Prefer CVE/misconfig Nuclei before exposure scan so the larger budget is not spent first.
        var checkList = selectedChecks.ToList();
        var orderedChecks = checkList
            .Select((c, index) => (Check: c, Index: index))
            .OrderBy(x => x.Check.Id switch
            {
                "vulnerability-scan" => 0,
                "sensitive-file-scan" => 1,
                _ => 2
            })
            .ThenBy(x => x.Index)
            .Select(x => x.Check)
            .ToList();

        foreach (var check in orderedChecks)
        {
            await EnsureNotCancelledAsync(scanId, cancellationToken);

            var tools = check.Tools.Where(t => config.Tools.Contains(t, StringComparer.OrdinalIgnoreCase)).ToList();
            if (tools.Count == 0) tools = check.Tools.ToList();

            var needsAuthSession = check.Id is "directory-discovery" or "sensitive-file-scan";
            if (needsAuthSession && config.Auth?.IsEnabled == true && !authenticated)
                continue;

            var toolOpts = config.ToolOptions ?? ScanToolOptions.CreateDefault();
            toolOpts.Normalize();

            IEnumerable<ScanFindingDto> batch = check.Id switch
            {
                "reachability" => EvaluateReachability(check, tools, targetUrl, response, sw.ElapsedMilliseconds),
                "https-tls" => EvaluateHttps(check, tools, hasHttps, targetUrl),
                "security-headers" => EvaluateSecurityHeaders(check, tools, targetUrl, headers),
                "server-fingerprint" => EvaluateFingerprint(check, tools, targetUrl, server, poweredBy),
                "cookie-security" => EvaluateCookies(check, tools, targetUrl, setCookie, hasHttps),
                "cors-policy" => EvaluateCors(check, tools, targetUrl, corsOrigin),
                "information-disclosure" => EvaluateDisclosure(check, tools, targetUrl, headers, server, poweredBy),
                "port-scan" => await EvaluatePortScanAsync(check, tools, targetUrl, toolOpts.Naabu, cancellationToken),
                "directory-discovery" => await EvaluateDirectoryDiscoveryAsync(deepClient, check, tools, targetUrl, secondaryTargets, sourceProbePaths, toolOpts, cancellationToken),
                "sensitive-file-scan" => await EvaluateSensitiveFilesAsync(deepClient, check, tools, targetUrl, secondaryTargets, toolOpts.Nuclei, cancellationToken),
                "vulnerability-scan" => await EvaluateVulnerabilityAsync(check, tools, targetUrl, secondaryTargets, toolOpts.Nuclei, cancellationToken),
                "technology-detection" => await EvaluateTechnologyAsync(check, tools, headers, server, poweredBy, targetUrl, cancellationToken),
                "screenshot" => await EvaluateScreenshotAsync(check, tools, targetUrl, cancellationToken),
                "dns-security" => await EvaluateDnsAsync(check, tools, targetUrl, cancellationToken),
                "waf-detection" => await EvaluateWafAsync(check, tools, targetUrl, headers, server, cancellationToken),
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
        if (config.Auth?.IsEnabled == true)
        {
            var authSurfaceCount = findings.Count(f =>
                f.Code.StartsWith("auth.surface.", StringComparison.OrdinalIgnoreCase)
                || f.Code.StartsWith("auth.session.", StringComparison.OrdinalIgnoreCase));
            executive += authenticated
                ? $" Authenticated session established; {authSurfaceCount} post-login surface finding(s)."
                : " Authentication failed; post-login coverage limited.";
        }

        var report = new ScanReportPayloadDto(
            config.ReportType,
            reportDef.Name,
            riskScore,
            riskLevel,
            config.Checks,
            config.Tools,
            findings,
            executive);

        var summary = authenticated
            ? $"Authenticated scan completed ({authNote})."
            : config.Auth?.IsEnabled == true
                ? $"Scan completed with auth failure ({authNote})."
                : $"Scan completed with {findings.Count} findings.";

        return new AnalysisResult(
            summary,
            (int)response.StatusCode,
            sw.ElapsedMilliseconds,
            hasHttps,
            server,
            report);
    }

    private async Task<IReadOnlyList<ScanFindingDto>> EvaluateAuthenticatedSurfaceAsync(
        HttpClientHandler authHandler,
        HttpClient authClient,
        string targetUrl,
        IReadOnlyList<string> extraProbePaths,
        CancellationToken cancellationToken)
    {
        var findings = new List<ScanFindingDto>();
        var tools = AuthCheckDef.Tools;

        findings.AddRange(EvaluateSessionCookies(authHandler, targetUrl));

        var apiBases = DiscoverAuthenticatedApiBases(authHandler, targetUrl);
        if (apiBases.Count > 0)
        {
            findings.Add(Finding(AuthCheckDef, tools, "Info", "auth.surface.api_discovered",
                P(("observed", $"Discovered {apiBases.Count} post-login API/base URL(s): {string.Join(", ", apiBases)}."),
                    ("impact", "Authenticated scanning should include these hosts, not only the public landing page.")),
                string.Join("; ", apiBases)));
        }
        else
        {
            findings.Add(Finding(AuthCheckDef, tools, "Low", "auth.surface.api_none",
                P(("observed", "No GraphQL/API base URL was discovered from the authenticated session."),
                    ("impact", "Post-login API coverage may be incomplete for SPA apps.")),
                $"target={targetUrl}"));
        }

        using var anonHandler = CreateScanHandler();
        using var anonClient = CreateScanClient(anonHandler);

        findings.AddRange(await DiffAuthzPathsAsync(anonClient, authClient, targetUrl, extraProbePaths, cancellationToken));

        foreach (var api in apiBases.Where(u => u.Contains("graphql", StringComparison.OrdinalIgnoreCase)).Take(3))
        {
            cancellationToken.ThrowIfCancellationRequested();
            findings.AddRange(await DiffGraphqlAccessAsync(anonClient, authClient, api, cancellationToken));
        }

        if (!findings.Any(f => f.Code.StartsWith("auth.surface.authz_diff", StringComparison.OrdinalIgnoreCase)
                               || f.Code.StartsWith("auth.surface.graphql", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(Finding(AuthCheckDef, tools, "Info", "auth.coverage.limited",
                P(("observed", "Login succeeded but no clear anonymous-vs-auth response differences were found on the probed paths."),
                    ("impact", "The app may be a SPA that serves the same shell publicly; API-level authz tests are still required.")),
                $"target={targetUrl}; apis={apiBases.Count}"));
        }

        return findings;
    }

    private static IEnumerable<ScanFindingDto> EvaluateSessionCookies(HttpClientHandler handler, string targetUrl)
    {
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var targetUri))
            yield break;

        var hosts = new HashSet<Uri>(new UriHostComparer()) { targetUri };
        foreach (Cookie cookie in handler.CookieContainer.GetAllCookies())
        {
            try
            {
                var scheme = targetUri.Scheme;
                var host = cookie.Domain.TrimStart('.');
                hosts.Add(new Uri($"{scheme}://{host}/"));
            }
            catch
            {
                // ignore malformed cookie domains
            }
        }

        var sessionCookies = new List<Cookie>();
        foreach (var host in hosts)
        {
            try
            {
                sessionCookies.AddRange(handler.CookieContainer.GetCookies(host).Cast<Cookie>());
            }
            catch
            {
                // ignore
            }
        }

        sessionCookies = sessionCookies
            .GroupBy(c => $"{c.Domain}|{c.Name}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        if (sessionCookies.Count == 0)
        {
            // SPA / GraphQL bearer flows often have no cookies — informational, not a Medium defect.
            yield return Finding(AuthCheckDef, AuthCheckDef.Tools, "Info", "auth.session.cookie_missing",
                P(("observed", "Authenticated session established but no cookies were present in the scanner jar."),
                    ("impact", "Session may rely only on bearer tokens in memory/localStorage — cookie-based authz probes may be incomplete."),
                    ("targetUrl", targetUrl)),
                "cookies=0");
            yield break;
        }

        var insecure = sessionCookies.Where(c => !c.Secure).Select(c => c.Name).Distinct().ToList();
        var noHttpOnly = sessionCookies.Where(c => !c.HttpOnly).Select(c => c.Name).Distinct().ToList();

        if (insecure.Count > 0)
        {
            yield return Finding(AuthCheckDef, AuthCheckDef.Tools, "High", "auth.session.cookie_insecure",
                P(("observed", $"Session cookie(s) without Secure: {string.Join(", ", insecure)}."),
                    ("impact", "Session cookies can be sent over HTTP if a downgrade occurs."),
                    ("targetUrl", targetUrl)),
                $"missing_secure={string.Join(",", insecure)}");
        }

        if (noHttpOnly.Count > 0)
        {
            yield return Finding(AuthCheckDef, AuthCheckDef.Tools, "Medium", "auth.session.cookie_no_httponly",
                P(("observed", $"Session cookie(s) without HttpOnly: {string.Join(", ", noHttpOnly)}."),
                    ("impact", "XSS could steal session cookies readable by JavaScript."),
                    ("targetUrl", targetUrl)),
                $"missing_httponly={string.Join(",", noHttpOnly)}");
        }

        if (insecure.Count == 0 && noHttpOnly.Count == 0)
        {
            yield return Finding(AuthCheckDef, AuthCheckDef.Tools, "Info", "auth.session.cookie_ok",
                P(("observed", $"Authenticated cookie jar has {sessionCookies.Count} cookie(s) with Secure+HttpOnly."),
                    ("targetUrl", targetUrl)),
                $"cookies={sessionCookies.Count}");
        }
    }

    private static List<string> DiscoverAuthenticatedApiBases(HttpClientHandler handler, string targetUrl)
    {
        var bases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var url in DiscoverHeuristicApiBases(targetUrl))
            bases.Add(url);

        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var target))
            return bases.Take(8).ToList();

        foreach (Cookie cookie in handler.CookieContainer.GetAllCookies())
        {
            var host = cookie.Domain.TrimStart('.');
            if (host.Contains("graph", StringComparison.OrdinalIgnoreCase)
                || host.Contains("api", StringComparison.OrdinalIgnoreCase)
                || host.Contains("backend", StringComparison.OrdinalIgnoreCase))
            {
                bases.Add($"{target.Scheme}://{host}/graphql");
                bases.Add($"{target.Scheme}://{host}/api");
            }
        }

        return bases.Take(8).ToList();
    }

    private static IEnumerable<string> DiscoverHeuristicApiBases(string targetUrl)
    {
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var target))
            yield break;

        // Sibling Clever-style hosts commonly used after OIDC login.
        if (target.Host.Contains("intro.", StringComparison.OrdinalIgnoreCase))
        {
            var graphHost = target.Host.Replace("intro.", "cvgraph2.", StringComparison.OrdinalIgnoreCase);
            yield return $"{target.Scheme}://{graphHost}/graphql";
        }

        if (target.Host.Contains("cvmanager.", StringComparison.OrdinalIgnoreCase))
        {
            var backend = target.Host.Replace("cvmanager.", "cvmanager-backend.", StringComparison.OrdinalIgnoreCase);
            yield return $"{target.Scheme}://{backend}/graphql";
        }
    }

    /// <summary>
    /// Extra HTTP(S) targets for Nuclei/Ferox/FFUF — discovered API/GraphQL backends, same-site safe only.
    /// </summary>
    private static List<string> BuildSecondaryScanTargets(HttpClientHandler handler, string targetUrl)
    {
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var primary))
            return [];

        var candidates = new List<string>();
        candidates.AddRange(DiscoverAuthenticatedApiBases(handler, targetUrl));
        candidates.AddRange(DiscoverHeuristicApiBases(targetUrl));

        var results = new List<string>();
        foreach (var raw in candidates)
        {
            if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
                continue;
            if (string.Equals(uri.Host, primary.Host, StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                ScanHostSafety.EnsureSafeHttpTarget(uri.ToString());
            }
            catch
            {
                continue;
            }

            // Prefer full GraphQL/API URL for Nuclei; directory discovery will normalize to origin.
            var normalized = uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
            if (results.Any(r => string.Equals(r, normalized, StringComparison.OrdinalIgnoreCase)))
                continue;
            results.Add(normalized);
            if (results.Count >= 3)
                break;
        }

        return results;
    }

    private static string ToOriginUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.TrimEnd('/') + "/";
        return $"{uri.Scheme}://{uri.Authority}/";
    }

    private static NucleiToolOptions CloneNucleiOptions(NucleiToolOptions source, int maxDurationSeconds)
    {
        var clone = new NucleiToolOptions
        {
            Profile = source.Profile,
            Severity = source.Severity,
            Tags = source.Tags,
            ExposureTags = source.ExposureTags,
            Concurrency = source.Concurrency,
            RateLimit = source.RateLimit,
            TimeoutSeconds = source.TimeoutSeconds,
            Retries = source.Retries,
            MaxDurationSeconds = maxDurationSeconds,
        };
        clone.Normalize();
        // Preserve caller duration after Normalize (deep profile may bump 240→300).
        clone.MaxDurationSeconds = Math.Clamp(maxDurationSeconds, 30, 900);
        return clone;
    }

    private async Task<IReadOnlyList<ScanFindingDto>> DiffAuthzPathsAsync(
        HttpClient anonClient,
        HttpClient authClient,
        string targetUrl,
        IReadOnlyList<string> extraProbePaths,
        CancellationToken cancellationToken)
    {
        var findings = new List<ScanFindingDto>();
        var baseUri = new Uri(targetUrl.TrimEnd('/') + "/");
        var paths = new List<string>
        {
            "dashboard", "general/dashboard", "app", "home", "profile", "settings",
            "account", "admin", "api", "me", "user", "patients", "chart",
            "event", "event/export", "event/next", "event/previous",
            "event/print/calendar", "event/print/planning"
        };
        foreach (var extra in extraProbePaths)
        {
            if (string.IsNullOrWhiteSpace(extra)) continue;
            paths.Add(extra.Trim().TrimStart('/'));
        }

        paths = paths
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(80)
            .ToList();

        var diffs = new List<string>();
        foreach (var path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var url = new Uri(baseUri, path).ToString();
            var anon = await ProbeUrlAsync(anonClient, url, cancellationToken);
            var auth = await ProbeUrlAsync(authClient, url, cancellationToken);
            if (anon is null || auth is null) continue;

            var anonBlocked = anon.StatusCode is 401 or 403
                              || (anon.StatusCode is >= 300 and < 400)
                              || LooksLikeLoginPage(anon.BodySample);
            var authOk = auth.StatusCode is >= 200 and < 300;

            // Meaningful unlock: anonymous blocked / login-like, authenticated gets 2xx with different body.
            if (anonBlocked && authOk
                && anon.BodyFingerprint != auth.BodyFingerprint
                && !IsSoft404OrSpaFallback(auth, anon, path, allowHtml: true))
            {
                diffs.Add($"{path}: anon={anon.StatusCode} -> auth={auth.StatusCode}");
            }
            else if (anon.StatusCode is >= 400 && auth.StatusCode is >= 200 and < 300
                     && anon.BodyFingerprint != auth.BodyFingerprint
                     && !IsSoft404OrSpaFallback(auth, anon, path, allowHtml: true))
            {
                diffs.Add($"{path}: anon={anon.StatusCode} -> auth={auth.StatusCode}");
            }
        }

        if (diffs.Count > 0)
        {
            // Expected login gates are Info; only escalate when many API-like unlocks.
            var severity = diffs.Count >= 3 ? "Medium" : "Info";
            findings.Add(Finding(AuthCheckDef, AuthCheckDef.Tools, severity, "auth.surface.authz_diff",
                P(("observed", $"Paths behave differently with an authenticated session: {string.Join("; ", diffs)}."),
                    ("impact", "These routes are gated by login; verify authorization (role/tenant) still restricts sensitive data."),
                    ("targetUrl", targetUrl)),
                string.Join("; ", diffs)));
        }

        return findings;
    }

    private static async Task<IReadOnlyList<ScanFindingDto>> DiffGraphqlAccessAsync(
        HttpClient anonClient,
        HttpClient authClient,
        string graphqlUrl,
        CancellationToken cancellationToken)
    {
        var findings = new List<ScanFindingDto>();
        const string probeQuery = """{"query":"{ __typename }"}""";

        async Task<(int Status, string Body)> PostAsync(HttpClient client)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, graphqlUrl)
            {
                Content = new StringContent(probeQuery, Encoding.UTF8, "application/json")
            };
            using var resp = await SendWithSafeRedirectsAsync(client, req, cancellationToken);
            var body = await resp.Content.ReadAsStringAsync(cancellationToken);
            return ((int)resp.StatusCode, body.Length > 400 ? body[..400] : body);
        }

        try
        {
            var anon = await PostAsync(anonClient);
            var auth = await PostAsync(authClient);

            var anonDenied = anon.Status is 401 or 403
                             || anon.Body.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase)
                             || anon.Body.Contains("AUTH", StringComparison.OrdinalIgnoreCase);
            var authAccepted = auth.Status is >= 200 and < 300
                               && (auth.Body.Contains("__typename", StringComparison.OrdinalIgnoreCase)
                                   || auth.Body.Contains("\"data\"", StringComparison.OrdinalIgnoreCase));

            if (anonDenied && authAccepted)
            {
                findings.Add(Finding(AuthCheckDef, AuthCheckDef.Tools, "Medium", "auth.surface.graphql_authz",
                    P(("observed", $"GraphQL {graphqlUrl}: anonymous HTTP {anon.Status}, authenticated HTTP {auth.Status} with data."),
                        ("impact", "API accepts the session; continue with authenticated GraphQL security tests (introspection, IDOR, mutations)."),
                        ("url", graphqlUrl)),
                    $"anon={anon.Status}; auth={auth.Status}"));
            }
            else if (authAccepted && anon.Status is >= 200 and < 300
                     && anon.Body.Contains("\"data\"", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(Finding(AuthCheckDef, AuthCheckDef.Tools, "High", "auth.surface.graphql_public",
                    P(("observed", $"GraphQL {graphqlUrl} answered both anonymously and with a session (HTTP {anon.Status}/{auth.Status})."),
                        ("impact", "GraphQL may be reachable without authentication — verify resolvers enforce authz."),
                        ("url", graphqlUrl)),
                    $"anon={anon.Status}; auth={auth.Status}"));
            }
            else if (authAccepted)
            {
                findings.Add(Finding(AuthCheckDef, AuthCheckDef.Tools, "Info", "auth.surface.graphql_ok",
                    P(("observed", $"Authenticated GraphQL probe succeeded at {graphqlUrl} (HTTP {auth.Status})."),
                        ("url", graphqlUrl)),
                    $"auth={auth.Status}"));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            findings.Add(Finding(AuthCheckDef, AuthCheckDef.Tools, "Info", "auth.surface.graphql_error",
                P(("observed", $"GraphQL probe error for {graphqlUrl} (details redacted)."),
                    ("url", graphqlUrl)),
                "probe=error"));
        }

        return findings;
    }

    private sealed class UriHostComparer : IEqualityComparer<Uri>
    {
        public bool Equals(Uri? x, Uri? y) =>
            string.Equals(x?.Authority, y?.Authority, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode(Uri obj) =>
            StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Authority);
    }

    private async Task<AuthAttemptResult> TryAuthenticateAsync(
        HttpClient client,
        string targetUrl,
        ScanAuthConfiguration auth,
        CancellationToken cancellationToken)
    {
        try
        {
            var password = secretProtector.Unprotect(auth.PasswordCipher!);
            var loginUrl = ResolveLoginUrl(targetUrl, auth.LoginUrl);

            if (auth.Type.Equals(ScanAuthConfiguration.TypeBasic, StringComparison.OrdinalIgnoreCase))
            {
                // Probe without credentials first to see if Basic is actually required.
                using var unauthProbe = new HttpRequestMessage(HttpMethod.Get, targetUrl);
                using var unauthResponse = await SendWithSafeRedirectsAsync(client, 
                    unauthProbe, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                var unauthCode = (int)unauthResponse.StatusCode;
                var challengesBasic = unauthResponse.Headers.WwwAuthenticate
                    .Any(h => h.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase));

                if (unauthCode is >= 200 and < 400 && !challengesBasic)
                {
                    return new AuthAttemptResult(
                        false,
                        loginUrl,
                        $"Target did not challenge for HTTP Basic (HTTP {unauthCode}); credentials were not validated.");
                }

                var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{auth.Username}:{password}"));
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", token);
                using var probe = new HttpRequestMessage(HttpMethod.Get, targetUrl);
                using var response = await SendWithSafeRedirectsAsync(client, probe, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                var code = (int)response.StatusCode;
                if (code is 401 or 403)
                    return new AuthAttemptResult(false, loginUrl, $"Basic auth rejected with HTTP {code}.");
                if (code is >= 200 and < 400)
                    return new AuthAttemptResult(true, loginUrl, $"Basic auth accepted (HTTP {code}).");
                return new AuthAttemptResult(false, loginUrl, $"Basic auth probe failed with HTTP {code}.");
            }

            if (auth.Type.Equals(ScanAuthConfiguration.TypeGraphql, StringComparison.OrdinalIgnoreCase))
            {
                // LoginUrl may be the SPA /login page — resolve real GraphQL endpoints first.
                var gqlTargets = await ResolveGraphqlLoginTargetsAsync(
                    client, targetUrl, loginUrl, html: null, cancellationToken);
                AuthAttemptResult? last = null;
                foreach (var endpoint in gqlTargets)
                {
                    last = await TryGraphqlAuthenticateAsync(client, auth, password, endpoint, cancellationToken);
                    if (last.Success)
                        return last;
                }

                return last ?? new AuthAttemptResult(
                    false,
                    loginUrl,
                    "GraphQL login failed: no usable /graphql endpoint discovered for this host.");
            }

            // Form login
            using var getLogin = new HttpRequestMessage(HttpMethod.Get, loginUrl);
            using var loginPage = await SendWithSafeRedirectsAsync(client, getLogin, cancellationToken);
            var html = await loginPage.Content.ReadAsStringAsync(cancellationToken);

            // SPA / Next.js pages often have no HTML form — try OIDC /auth/login then GraphQL.
            if (!Regex.IsMatch(html, "<form\\b", RegexOptions.IgnoreCase)
                && (html.Contains("__NEXT_DATA__", StringComparison.Ordinal)
                    || html.Contains("/_next/", StringComparison.OrdinalIgnoreCase)))
            {
                AuthAttemptResult? oidcFailure = null;
                foreach (var oidcLogin in DiscoverOidcLoginUrls(targetUrl, html))
                {
                    var oidc = await TryFormLoginAtAsync(client, auth, password, oidcLogin, cancellationToken);
                    if (oidc.Success)
                        return oidc;
                    oidcFailure = oidc;
                }

                if (oidcFailure is not null
                    && oidcFailure.Message.Contains("flash=", StringComparison.OrdinalIgnoreCase))
                {
                    return oidcFailure;
                }

                var discovered = await ResolveGraphqlLoginTargetsAsync(
                    client, targetUrl, loginUrl, html, cancellationToken);
                foreach (var endpoint in discovered)
                {
                    var gql = await TryGraphqlAuthenticateAsync(client, auth, password, endpoint, cancellationToken);
                    if (gql.Success)
                    {
                        return new AuthAttemptResult(
                            true,
                            endpoint,
                            $"SPA had no HTML form; GraphQL login succeeded via discovered endpoint ({endpoint}).");
                    }
                }

                if (oidcFailure is not null)
                    return oidcFailure;

                var hint = discovered.Count > 0
                    ? $"Tried GraphQL: {string.Join(", ", discovered)}."
                    : "No GraphQL URL found in page assets.";
                return new AuthAttemptResult(
                    false,
                    loginUrl,
                    $"Login page is a JavaScript SPA (no HTML form). {hint} For Clever Manager, use GraphQL auth with …-backend…/graphql or Form auth (auto-discovers backend).");
            }

            return await TryFormLoginAtAsync(client, auth, password, loginUrl, cancellationToken, html);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Authentication attempt failed");
            return new AuthAttemptResult(false, auth.LoginUrl ?? targetUrl, "Authentication attempt error (details redacted).");
        }
    }

    private async Task<AuthAttemptResult> TryFormLoginAtAsync(
        HttpClient client,
        ScanAuthConfiguration auth,
        string password,
        string loginUrl,
        CancellationToken cancellationToken,
        string? prefetchedHtml = null)
    {
        string html;
        string pageUrl = loginUrl;
        if (prefetchedHtml is null)
        {
            using var getLogin = new HttpRequestMessage(HttpMethod.Get, loginUrl);
            using var loginPage = await SendWithSafeRedirectsAsync(client, getLogin, cancellationToken);
            html = await loginPage.Content.ReadAsStringAsync(cancellationToken);
            pageUrl = loginPage.RequestMessage?.RequestUri?.AbsoluteUri ?? loginUrl;
        }
        else
        {
            html = prefetchedHtml;
            pageUrl = loginUrl;
        }

        // If still no form (e.g. OIDC bounced to session-error), fail clearly.
        if (!Regex.IsMatch(html, "<form\\b", RegexOptions.IgnoreCase))
        {
            return new AuthAttemptResult(
                false,
                pageUrl,
                $"No HTML login form at {pageUrl}.");
        }

        // Re-fetch using the response URI if the first GET was a redirect chain landing page.
        // HttpClient follows redirects; parse action relative to loginUrl host carefully.
        var form = ExtractLoginForm(html, pageUrl, auth);
        form.Fields[form.PasswordField] = password;
        form.Fields[form.UsernameField] = auth.Username ?? "";

        if (!string.IsNullOrWhiteSpace(auth.ClinicId))
        {
            var clinicField = form.Fields.Keys.FirstOrDefault(k =>
                                  k.Contains("hospital", StringComparison.OrdinalIgnoreCase)
                                  || k.Contains("clinic", StringComparison.OrdinalIgnoreCase)
                                  || k.Equals("org", StringComparison.OrdinalIgnoreCase)
                                  || k.Equals("tenant", StringComparison.OrdinalIgnoreCase))
                              ?? "hospital";
            form.Fields[clinicField] = auth.ClinicId;
        }

        using var post = new HttpRequestMessage(HttpMethod.Post, form.ActionUrl);
        post.Content = new FormUrlEncodedContent(form.Fields);
        post.Headers.TryAddWithoutValidation("Referer", pageUrl);
        using var posted = await SendWithSafeRedirectsAsync(client, post, cancellationToken);
        var finalUrl = posted.RequestMessage?.RequestUri?.AbsoluteUri ?? form.ActionUrl;
        var body = await posted.Content.ReadAsStringAsync(cancellationToken);
        var codePost = (int)posted.StatusCode;

        var flash = Regex.Match(body, "flashLocale\\s*=\\s*\"([^\"]*)\"", RegexOptions.IgnoreCase);
        if (flash.Success && !string.IsNullOrWhiteSpace(flash.Groups[1].Value))
        {
            var code = flash.Groups[1].Value;
            var hint = code switch
            {
                "wrongPassMsg" => "Wrong password (clinic/user recognized).",
                "employeeFoundErrMsg" => "User ID not found.",
                "invalidClinicMsg" or "clinicErrMsg" => "Clinic ID invalid.",
                "invalidHospitalMsg" => "Hospital/clinic unavailable.",
                "fiveTimeFailErrMsg" or "fiveTimeFailErrMsgAdmin" => "Account locked after failed attempts.",
                _ => $"Login rejected (flash={code})."
            };
            return new AuthAttemptResult(false, pageUrl, $"Form login failed: {hint} flash={code}");
        }

        // Clever/OIDC: credentials OK then auto-submit "Continue" confirm form.
        var confirm = await TrySubmitOidcConfirmAsync(client, body, finalUrl, cancellationToken);
        if (confirm is not null)
        {
            body = confirm.Body;
            finalUrl = confirm.Url;
            codePost = confirm.StatusCode;
        }

        if (!string.IsNullOrWhiteSpace(auth.SuccessUrlContains)
            && (finalUrl.Contains(auth.SuccessUrlContains, StringComparison.OrdinalIgnoreCase)
                || body.Contains(auth.SuccessUrlContains, StringComparison.OrdinalIgnoreCase)))
        {
            return new AuthAttemptResult(true, pageUrl, $"Form login success marker matched ({auth.SuccessUrlContains}).");
        }

        var hasCredentialForm = Regex.IsMatch(body, "name=[\"']hospital[\"']|name=[\"']password[\"']", RegexOptions.IgnoreCase)
                                && Regex.IsMatch(body, "<form\\b", RegexOptions.IgnoreCase);
        var stillOnLogin = hasCredentialForm
                           || LooksLikeLoginPage(body)
                           || body.Contains("wrongPassMsg", StringComparison.OrdinalIgnoreCase);

        if (codePost is >= 200 and < 400 && !stillOnLogin)
            return new AuthAttemptResult(true, pageUrl, $"Form/OIDC login appears successful (HTTP {codePost}, url={finalUrl}).");

        if (codePost is >= 200 and < 400
            && (finalUrl.Contains("/auth/callback", StringComparison.OrdinalIgnoreCase)
                || finalUrl.Contains("intro.", StringComparison.OrdinalIgnoreCase)
                || finalUrl.Contains("cvgraph", StringComparison.OrdinalIgnoreCase)
                || body.Contains("access_token", StringComparison.OrdinalIgnoreCase)))
        {
            return new AuthAttemptResult(true, pageUrl, $"Form/OIDC login completed (HTTP {codePost}, url={finalUrl}).");
        }

        if (stillOnLogin || codePost is 401 or 403)
            return new AuthAttemptResult(false, pageUrl, $"Form login failed (HTTP {codePost}, url={finalUrl}).");

        if (posted.Headers.TryGetValues("Set-Cookie", out _) || client.DefaultRequestHeaders.Authorization is not null)
            return new AuthAttemptResult(true, pageUrl, $"Form login returned session artifacts (HTTP {codePost}).");

        return new AuthAttemptResult(false, pageUrl, $"Form login inconclusive (HTTP {codePost}, url={finalUrl}).");
    }

    private static async Task<OidcHopResult?> TrySubmitOidcConfirmAsync(
        HttpClient client,
        string html,
        string currentUrl,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(html)) return null;
        if (Regex.IsMatch(html, "name=[\"']password[\"']", RegexOptions.IgnoreCase))
            return null;

        var actionMatch = Regex.Match(html, "action\\s*=\\s*[\"']([^\"']*/confirm)[\"']", RegexOptions.IgnoreCase);
        if (!actionMatch.Success) return null;

        var action = System.Net.WebUtility.HtmlDecode(actionMatch.Groups[1].Value.Trim());
        if (!Uri.TryCreate(currentUrl, UriKind.Absolute, out var baseUri))
            baseUri = new Uri("https://cvauth.vnm2.vnclever.com/");
        var actionUrl = Uri.TryCreate(baseUri, action, out var abs) ? abs.ToString() : action;

        using var confirmPost = new HttpRequestMessage(HttpMethod.Post, actionUrl)
        {
            Content = new FormUrlEncodedContent(Array.Empty<KeyValuePair<string, string>>())
        };
        confirmPost.Headers.TryAddWithoutValidation("Referer", currentUrl);
        using var resp = await SendWithSafeRedirectsAsync(client, confirmPost, cancellationToken);
        var body = await resp.Content.ReadAsStringAsync(cancellationToken);
        var url = resp.RequestMessage?.RequestUri?.AbsoluteUri ?? actionUrl;
        return new OidcHopResult(body, url, (int)resp.StatusCode);
    }

    private sealed record OidcHopResult(string Body, string Url, int StatusCode);

    private static IReadOnlyList<string> DiscoverOidcLoginUrls(string targetUrl, string html)
    {
        var urls = new List<string>();
        foreach (Match m in Regex.Matches(
                     html,
                     "https?://[a-zA-Z0-9._\\-:]+",
                     RegexOptions.IgnoreCase))
        {
            // filled from scripts via CollectGraphql later; keep empty here
        }

        // Clever Dent pattern: graphql host without /graphql + /auth/login?returnTo=
        var gqlHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CollectGraphqlUrls(html, targetUrl, gqlHosts);
        AddHeuristicGraphqlEndpoints(targetUrl, gqlHosts);
        foreach (var gql in gqlHosts)
        {
            if (!Uri.TryCreate(gql, UriKind.Absolute, out var uri)) continue;
            var root = $"{uri.Scheme}://{uri.Authority}";
            urls.Add($"{root}/auth/login?returnTo={Uri.EscapeDataString(targetUrl)}");
        }

        // Also try sibling host cvgraph2 if target is intro.*
        if (Uri.TryCreate(targetUrl, UriKind.Absolute, out var target)
            && target.Host.Contains("intro.", StringComparison.OrdinalIgnoreCase))
        {
            var authHost = target.Host.Replace("intro.", "cvgraph2.", StringComparison.OrdinalIgnoreCase);
            urls.Add($"{target.Scheme}://{authHost}/auth/login?returnTo={Uri.EscapeDataString(targetUrl)}");
        }

        return urls.Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToList();
    }

    private async Task<AuthAttemptResult> TryGraphqlAuthenticateAsync(
        HttpClient client,
        ScanAuthConfiguration auth,
        string password,
        string loginUrl,
        CancellationToken cancellationToken)
    {
        var userField = string.IsNullOrWhiteSpace(auth.UsernameField) ? "loginId" : auth.UsernameField.Trim();
        var passField = string.IsNullOrWhiteSpace(auth.PasswordField) ? "password" : auth.PasswordField.Trim();

        // Default mutation used by many Clever/manager GraphQL portals; override via UsernameField/PasswordField names.
        const string query = """
            mutation LoginManager($loginManagerDto: LoginManagerInput!) {
              loginManager(loginManagerDto: $loginManagerDto) {
                token
              }
            }
            """;

        var payload = new Dictionary<string, object?>
        {
            ["query"] = query,
            ["variables"] = new Dictionary<string, object?>
            {
                ["loginManagerDto"] = new Dictionary<string, object?>
                {
                    [userField] = auth.Username,
                    [passField] = password
                }
            }
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, loginUrl)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        using var response = await SendWithSafeRedirectsAsync(client, request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var code = (int)response.StatusCode;

        if (code is < 200 or >= 300)
            return new AuthAttemptResult(false, loginUrl, $"GraphQL login HTTP {code}.");

        using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
        if (doc.RootElement.TryGetProperty("errors", out var errors)
            && errors.ValueKind == JsonValueKind.Array
            && errors.GetArrayLength() > 0)
        {
            return new AuthAttemptResult(false, loginUrl, "GraphQL login returned errors (credentials or schema rejected).");
        }

        var token = FindJsonStringProperty(doc.RootElement, "token");
        if (string.IsNullOrWhiteSpace(token))
            return new AuthAttemptResult(false, loginUrl, "GraphQL login succeeded HTTP-wise but no token was returned.");

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return new AuthAttemptResult(true, loginUrl, "GraphQL login succeeded; Bearer token attached for subsequent probes.");
    }

    private static string? FindJsonStringProperty(JsonElement element, string name)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in element.EnumerateObject())
            {
                if (prop.NameEquals(name) && prop.Value.ValueKind == JsonValueKind.String)
                    return prop.Value.GetString();
                var nested = FindJsonStringProperty(prop.Value, name);
                if (!string.IsNullOrWhiteSpace(nested))
                    return nested;
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var nested = FindJsonStringProperty(item, name);
                if (!string.IsNullOrWhiteSpace(nested))
                    return nested;
            }
        }

        return null;
    }

    private async Task<IReadOnlyList<string>> ResolveGraphqlLoginTargetsAsync(
        HttpClient client,
        string targetUrl,
        string pageOrLoginUrl,
        string? html,
        CancellationToken cancellationToken)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(pageOrLoginUrl)
            && pageOrLoginUrl.Contains("/graphql", StringComparison.OrdinalIgnoreCase)
            && Uri.TryCreate(pageOrLoginUrl, UriKind.Absolute, out _))
        {
            found.Add(pageOrLoginUrl.Trim());
        }

        AddHeuristicGraphqlEndpoints(targetUrl, found);
        AddHeuristicGraphqlEndpoints(pageOrLoginUrl, found);

        if (!string.IsNullOrWhiteSpace(html))
        {
            CollectGraphqlUrls(html, pageOrLoginUrl, found);
            var fromPage = await DiscoverGraphqlEndpointsAsync(client, pageOrLoginUrl, html, cancellationToken);
            foreach (var u in fromPage)
                found.Add(u);
        }
        else
        {
            // Fetch SPA login page once so relative uri:'/graphql' and heuristics can resolve.
            try
            {
                var pageUrl = string.IsNullOrWhiteSpace(pageOrLoginUrl) ? targetUrl : pageOrLoginUrl;
                using var req = new HttpRequestMessage(HttpMethod.Get, pageUrl);
                using var res = await client.SendAsync(req, cancellationToken);
                if (res.IsSuccessStatusCode)
                {
                    var pageHtml = await res.Content.ReadAsStringAsync(cancellationToken);
                    CollectGraphqlUrls(pageHtml, pageUrl, found);
                    foreach (var u in await DiscoverGraphqlEndpointsAsync(client, pageUrl, pageHtml, cancellationToken))
                        found.Add(u);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // heuristics still apply
            }
        }

        return found
            .Where(u => u.Contains("/graphql", StringComparison.OrdinalIgnoreCase))
            .Where(u => !u.Contains("chrome.google.com", StringComparison.OrdinalIgnoreCase)
                        && !u.Contains("github.com", StringComparison.OrdinalIgnoreCase)
                        && !u.Contains("mswjs.io", StringComparison.OrdinalIgnoreCase)
                        && !u.Contains("npmjs.com", StringComparison.OrdinalIgnoreCase)
                        && !u.Contains("apollo.dev", StringComparison.OrdinalIgnoreCase)
                        && !u.Contains("apollostack.com", StringComparison.OrdinalIgnoreCase))
            .OrderBy(u => u.Contains("backend", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(u => u.Contains("manager", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(u => u.Length)
            .Take(8)
            .ToList();
    }

    private async Task<IReadOnlyList<string>> DiscoverGraphqlEndpointsAsync(
        HttpClient client,
        string pageUrl,
        string html,
        CancellationToken cancellationToken)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CollectGraphqlUrls(html, pageUrl, found);
        AddHeuristicGraphqlEndpoints(pageUrl, found);

        var scriptSrcs = Regex.Matches(html, "src=[\"']([^\"']+)[\"']", RegexOptions.IgnoreCase)
            .Select(m => m.Groups[1].Value)
            .Where(src => src.Contains("/_next/", StringComparison.OrdinalIgnoreCase)
                          || src.Contains("app", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();

        foreach (var src in scriptSrcs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var abs = Uri.TryCreate(new Uri(pageUrl), src, out var uri) ? uri.ToString() : null;
                if (abs is null) continue;
                using var req = new HttpRequestMessage(HttpMethod.Get, abs);
                using var res = await SendWithSafeRedirectsAsync(client, req, cancellationToken);
                if (!res.IsSuccessStatusCode) continue;
                var js = await res.Content.ReadAsStringAsync(cancellationToken);
                CollectGraphqlUrls(js, pageUrl, found);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Best-effort discovery only.
            }
        }

        // Prefer backend/manager graphql hosts over chrome/apollo docs false positives.
        return found
            .Where(u => u.Contains("/graphql", StringComparison.OrdinalIgnoreCase))
            .Where(u => !u.Contains("chrome.google.com", StringComparison.OrdinalIgnoreCase)
                        && !u.Contains("github.com", StringComparison.OrdinalIgnoreCase)
                        && !u.Contains("mswjs.io", StringComparison.OrdinalIgnoreCase)
                        && !u.Contains("npmjs.com", StringComparison.OrdinalIgnoreCase)
                        && !u.Contains("apollo.dev", StringComparison.OrdinalIgnoreCase)
                        && !u.Contains("apollostack.com", StringComparison.OrdinalIgnoreCase))
            .OrderBy(u => u.Contains("backend", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(u => u.Contains("manager", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(u => u.Length)
            .Take(8)
            .ToList();
    }

    private static void AddHeuristicGraphqlEndpoints(string? anyUrl, HashSet<string> sink)
    {
        if (string.IsNullOrWhiteSpace(anyUrl) || !Uri.TryCreate(anyUrl, UriKind.Absolute, out var uri))
            return;

        sink.Add($"{uri.Scheme}://{uri.Authority}/graphql");

        if (uri.Host.Contains("cvmanager.", StringComparison.OrdinalIgnoreCase)
            && !uri.Host.Contains("cvmanager-backend.", StringComparison.OrdinalIgnoreCase))
        {
            var backend = uri.Host.Replace("cvmanager.", "cvmanager-backend.", StringComparison.OrdinalIgnoreCase);
            sink.Add($"{uri.Scheme}://{backend}/graphql");
        }

        if (uri.Host.Contains("intro.", StringComparison.OrdinalIgnoreCase))
        {
            var graphHost = uri.Host.Replace("intro.", "cvgraph2.", StringComparison.OrdinalIgnoreCase);
            sink.Add($"{uri.Scheme}://{graphHost}/graphql");
        }
    }

    private static void CollectGraphqlUrls(string text, string baseUrl, HashSet<string> sink)
    {
        if (string.IsNullOrWhiteSpace(text)) return;

        foreach (Match m in Regex.Matches(
                     text,
                     @"https?://[a-zA-Z0-9][a-zA-Z0-9._\-]*(?:\.[a-zA-Z0-9._\-]+)+(?:\:\d+)?/(?:[a-zA-Z0-9._\-~/%]+/)*graphql[a-zA-Z0-9._\-~/%]*",
                     RegexOptions.IgnoreCase))
        {
            if (TryNormalizeGraphqlUrl(m.Value, out var url))
                sink.Add(url);
        }

        // SPA Apollo-style relative: uri: '/graphql'
        foreach (Match m in Regex.Matches(
                     text,
                     @"['""](/graphql[a-zA-Z0-9._\-/]*)['""]",
                     RegexOptions.IgnoreCase))
        {
            var path = m.Groups[1].Value;
            if (Uri.TryCreate(baseUrl, UriKind.Absolute, out var page)
                && Uri.TryCreate(page, path, out var abs)
                && TryNormalizeGraphqlUrl(abs.ToString(), out var url))
            {
                sink.Add(url);
            }

            AddHeuristicGraphqlEndpoints(baseUrl, sink);
        }
    }

    private static bool TryNormalizeGraphqlUrl(string raw, out string url)
    {
        url = "";
        if (string.IsNullOrWhiteSpace(raw)) return false;
        var cleaned = raw.Trim().TrimEnd('.', ',', ';', ')', ']', '\'', '"', '`');
        // Drop fragment/query junk often glued by minified JS regex hits.
        var hash = cleaned.IndexOf('#');
        if (hash >= 0) cleaned = cleaned[..hash];
        var q = cleaned.IndexOf('?');
        if (q >= 0) cleaned = cleaned[..q];

        if (!Uri.TryCreate(cleaned, UriKind.Absolute, out var uri))
            return false;
        if (uri.Scheme is not ("http" or "https"))
            return false;
        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Host.Contains(' ', StringComparison.Ordinal))
            return false;
        if (!uri.AbsolutePath.Contains("graphql", StringComparison.OrdinalIgnoreCase))
            return false;

        url = uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        if (!url.EndsWith("graphql", StringComparison.OrdinalIgnoreCase)
            && !url.Contains("/graphql/", StringComparison.OrdinalIgnoreCase))
        {
            // keep only paths that still clearly target graphql
            if (!uri.AbsolutePath.EndsWith("/graphql", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(uri.AbsolutePath, "/graphql", StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }

    private static void CollectGraphqlUrls(string text, HashSet<string> sink) =>
        CollectGraphqlUrls(text, "https://localhost/", sink);

    private static string ResolveLoginUrl(string targetUrl, string? loginUrl)
    {
        if (!string.IsNullOrWhiteSpace(loginUrl))
            return loginUrl.Trim();

        // Prefer the target itself; many SPAs host login entry on `/` and redirect out-of-band.
        return targetUrl.Trim();
    }

    private static LoginFormExtract ExtractLoginForm(
        string html,
        string loginUrl,
        ScanAuthConfiguration auth)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var actionUrl = loginUrl;

        var formMatch = Regex.Match(
            html,
            "<form\\b[^>]*>.*?</form>",
            RegexOptions.IgnoreCase | RegexOptions.Singleline);
        var formHtml = formMatch.Success ? formMatch.Value : html;

        var actionMatch = Regex.Match(formHtml, "action\\s*=\\s*[\"']([^\"']+)[\"']", RegexOptions.IgnoreCase);
        if (actionMatch.Success)
        {
            var action = System.Net.WebUtility.HtmlDecode(actionMatch.Groups[1].Value.Trim());
            if (!string.IsNullOrWhiteSpace(action) && !action.StartsWith('#'))
                actionUrl = Uri.TryCreate(new Uri(loginUrl), action, out var abs) ? abs.ToString() : loginUrl;
        }

        foreach (Match input in Regex.Matches(formHtml, "<input\\b[^>]*>", RegexOptions.IgnoreCase))
        {
            var tag = input.Value;
            var name = Attr(tag, "name");
            if (string.IsNullOrWhiteSpace(name)) continue;
            var type = (Attr(tag, "type") ?? "text").ToLowerInvariant();
            var value = Attr(tag, "value") ?? "";
            if (type is "submit" or "button" or "image") continue;
            fields[name] = System.Net.WebUtility.HtmlDecode(value);
        }

        var userField = auth.UsernameField;
        if (string.IsNullOrWhiteSpace(userField))
        {
            userField = fields.Keys.FirstOrDefault(k =>
                k.Contains("user", StringComparison.OrdinalIgnoreCase)
                || k.Contains("email", StringComparison.OrdinalIgnoreCase)
                || k.Contains("employee", StringComparison.OrdinalIgnoreCase)
                || k.Equals("login", StringComparison.OrdinalIgnoreCase)
                || k.Equals("loginid", StringComparison.OrdinalIgnoreCase)
                || k.Equals("account", StringComparison.OrdinalIgnoreCase)) ?? "username";
        }

        var passField = auth.PasswordField;
        if (string.IsNullOrWhiteSpace(passField))
        {
            passField = fields.Keys.FirstOrDefault(k =>
                k.Contains("pass", StringComparison.OrdinalIgnoreCase)
                || k.Equals("pwd", StringComparison.OrdinalIgnoreCase)) ?? "password";
        }

        return new LoginFormExtract(actionUrl, fields, userField, passField);
    }

    private static string? Attr(string tag, string name)
    {
        var match = Regex.Match(tag, name + "\\s*=\\s*[\"']([^\"']*)[\"']", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static bool LooksLikeLoginPage(string html)
    {
        if (string.IsNullOrWhiteSpace(html)) return false;
        var lower = html.ToLowerInvariant();
        return lower.Contains("type=\"password\"")
               || lower.Contains("type='password'")
               || (lower.Contains("login") && lower.Contains("password"));
    }

    private static string RedactSecrets(string message, ScanAuthConfiguration auth)
    {
        var text = message;
        if (!string.IsNullOrWhiteSpace(auth.Username))
            text = text.Replace(auth.Username, MaskUsername(auth.Username), StringComparison.Ordinal);
        return text;
    }

    private static string MaskUsername(string username) =>
        WebsiteScanMappings.MaskUsername(username) ?? "***";

    private async Task EnsureNotCancelledAsync(Guid scanId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (await IsCancelledAsync(scanId, cancellationToken))
            throw new OperationCanceledException("Scan cancelled by user.");
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
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, NaabuToolOptions naabuOpts, CancellationToken cancellationToken)
    {
        var host = new Uri(targetUrl).Host;
        ScanHostSafety.EnsureSafeHost(host, "Port-scan host");
        naabuOpts.Normalize();
        var ports = naabuOpts.ParsePorts().ToArray();
        var open = new List<int>();
        var toolUsed = "tcp-probe";

        if (tools.Contains("naabu", StringComparer.OrdinalIgnoreCase))
        {
            var naabu = await ExternalToolRunner.TryNaabuAsync(host, ports, cancellationToken, naabuOpts);
            if (naabu is { Ran: true })
            {
                toolUsed = "naabu";
                foreach (var p in ExternalToolRunner.ParseNaabuOpenPorts(naabu.StdOut))
                    if (int.TryParse(p, out var port)) open.Add(port);
            }
        }

        if (open.Count == 0 && toolUsed == "tcp-probe")
        {
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
        }

        open = open.Distinct().OrderBy(p => p).ToList();
        var banners = new Dictionary<int, string?>();
        foreach (var port in open.Take(24))
        {
            cancellationToken.ThrowIfCancellationRequested();
            banners[port] = await ProbePortBannerAsync(host, port, cancellationToken);
        }

        var assessment = PortScanAssessor.Assess(host, open, ports, toolUsed, banners);
        return
        [
            Finding(check, tools, assessment.Severity, assessment.Code, P(
                    ("host", host),
                    ("port", open.Count > 0 ? open[0].ToString() : ""),
                    ("observed", assessment.Observed),
                    ("impact", assessment.Impact)),
                assessment.Evidence)
        ];
    }

    private static async Task<string?> ProbePortBannerAsync(string host, int port, CancellationToken cancellationToken)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromMilliseconds(900));
            using var client = new System.Net.Sockets.TcpClient();
            await client.ConnectAsync(host, port, cts.Token);
            await using var stream = client.GetStream();
            stream.ReadTimeout = 700;
            stream.WriteTimeout = 700;

            // Nudge common cleartext services; TLS ports usually won't return a clear banner.
            if (port is 80 or 8080)
            {
                var probe = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n");
                await stream.WriteAsync(probe, cts.Token);
            }
            else if (port is 21 or 22 or 25 or 110 or 143 or 3306 or 5432 or 6379)
            {
                // Many of these send an unsolicited banner.
            }

            var buffer = new byte[256];
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cts.Token);
            if (read <= 0) return null;
            var text = Encoding.UTF8.GetString(buffer, 0, read);
            text = Regex.Replace(text, @"[^\x20-\x7E]+", " ").Trim();
            if (text.Length < 3) return null;
            return text.Length > 80 ? text[..80] : text;
        }
        catch
        {
            return null;
        }
    }

    private static List<string> BuildSourceAbsoluteUrls(string targetUrl, IReadOnlyList<string> sourceProbePaths)
    {
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var baseUri))
            return [];

        var results = new List<string>();
        foreach (var path in sourceProbePaths)
        {
            if (string.IsNullOrWhiteSpace(path)) continue;
            try
            {
                var relative = path.TrimStart('/');
                var url = new Uri(baseUri, relative).ToString();
                ScanHostSafety.EnsureSafeHttpTarget(url);
                if (!results.Contains(url, StringComparer.OrdinalIgnoreCase))
                    results.Add(url);
            }
            catch
            {
                // skip unsafe / malformed
            }
        }

        return results;
    }

    private static HttpMethod ResolveHttpMethod(string method) =>
        method.ToUpperInvariant() switch
        {
            "POST" => HttpMethod.Post,
            "PUT" => HttpMethod.Put,
            "DELETE" => HttpMethod.Delete,
            "PATCH" => HttpMethod.Patch,
            "HEAD" => HttpMethod.Head,
            _ => HttpMethod.Get,
        };

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateSourceRouteProbesAsync(
        HttpClient client,
        string targetUrl,
        IReadOnlyList<SourceRouteInventoryAnalyzer.ProbeRoute> sourceProbeRoutes,
        IReadOnlyList<string> sourceProbePaths,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var baseUri))
            return [];

        var routes = sourceProbeRoutes.Count > 0
            ? sourceProbeRoutes.Take(40).ToList()
            : sourceProbePaths.Take(40)
                .Select(p => new SourceRouteInventoryAnalyzer.ProbeRoute("GET", p, false, false))
                .ToList();
        if (routes.Count == 0)
            return [];

        var intentionalPublic = new List<(string Method, string Url, int Status)>();
        var unexpectedExposed = new List<(string Method, string Url, int Status, string Note)>();
        var authRequired = new List<(string Method, string Url, int Status)>();
        var other = new List<(string Method, string Url, int Status)>();
        var probed = 0;

        foreach (var route in routes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string url;
            try
            {
                url = new Uri(baseUri, route.Path.TrimStart('/')).ToString();
                ScanHostSafety.EnsureSafeHttpTarget(url);
            }
            catch
            {
                continue;
            }

            probed++;
            try
            {
                var httpMethod = ResolveHttpMethod(route.Method);
                using var req = new HttpRequestMessage(httpMethod, url);
                if (httpMethod == HttpMethod.Post || httpMethod == HttpMethod.Put || httpMethod == HttpMethod.Patch)
                {
                    req.Content = new StringContent("{}", Encoding.UTF8, "application/json");
                }

                using var resp = await SendWithSafeRedirectsAsync(
                    client, req, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                var status = (int)resp.StatusCode;
                var path = new Uri(url).AbsolutePath;

                if (status is 401 or 403)
                {
                    authRequired.Add((route.Method, url, status));
                    continue;
                }

                // Wrong method → endpoint exists but this is not anonymous data exposure.
                if (status == 405)
                {
                    other.Add((route.Method, url, status));
                    continue;
                }

                if (status is >= 200 and < 300)
                {
                    if (route.AllowAnonymous)
                    {
                        intentionalPublic.Add((route.Method, url, status));
                        continue;
                    }

                    var sensitive = !path.Contains("/auth/login", StringComparison.OrdinalIgnoreCase)
                                    && !path.Contains("/auth/register", StringComparison.OrdinalIgnoreCase)
                                    && !path.Contains("/auth/refresh", StringComparison.OrdinalIgnoreCase)
                                    && (path.Contains("password", StringComparison.OrdinalIgnoreCase)
                                        || path.Contains("/admin", StringComparison.OrdinalIgnoreCase)
                                        || path.Contains("secret", StringComparison.OrdinalIgnoreCase)
                                        || (path.Contains("/auth/", StringComparison.OrdinalIgnoreCase)
                                            && (httpMethod == HttpMethod.Get)));
                    unexpectedExposed.Add((route.Method, url, status, sensitive ? "sensitive-api" : "unexpected-anon"));
                    continue;
                }

                if (status is not 404)
                    other.Add((route.Method, url, status));
            }
            catch
            {
                // ignore probe errors
            }
        }

        var findings = new List<ScanFindingDto>();
        var check = new ScanCheckDefinition(
            SourceRouteInventoryAnalyzer.CheckId,
            "Source Route Inventory",
            "Clone Git and extract route/API inventory.",
            ["source-analyzer", "http-probe"],
            false,
            "recon",
            5);

        if (unexpectedExposed.Count > 0)
        {
            var high = unexpectedExposed.Where(e => e.Note == "sensitive-api").ToList();
            var sample = (high.Count > 0 ? high : unexpectedExposed).Take(12)
                .Select(e => $"{e.Method} {e.Url}({e.Status})");
            findings.Add(Finding(check, check.Tools,
                high.Count > 0 ? "High" : "Medium",
                high.Count > 0 ? "source.route.sensitive_exposed" : "source.route.exposed",
                P(("observed", $"Source routes without [AllowAnonymous] returned anonymous HTTP 2xx ({unexpectedExposed.Count}/{probed}): {string.Join(", ", sample)}"),
                    ("impact", high.Count > 0
                        ? "Anonymous access to sensitive API routes increases account takeover and data exposure risk."
                        : "Unexpected anonymous API surface — confirm authorization is intentional."),
                    ("targetUrl", targetUrl),
                    ("probed", probed.ToString())),
                string.Join("; ", unexpectedExposed.Take(40).Select(e => $"{e.Method} {e.Url} -> {e.Status} [{e.Note}]"))));
        }

        if (intentionalPublic.Count > 0)
        {
            findings.Add(Finding(check, check.Tools, "Info", "source.route.public_ok",
                P(("observed", $"{intentionalPublic.Count} [AllowAnonymous] route(s) correctly reachable without auth. Sample: {string.Join(", ", intentionalPublic.Take(8).Select(a => $"{a.Method} {a.Url}({a.Status})"))}"),
                    ("impact", "Intentional public surface — keep reviewed; do not treat as missing authz."),
                    ("targetUrl", targetUrl)),
                string.Join("; ", intentionalPublic.Take(30).Select(a => $"{a.Method} {a.Url} -> {a.Status}"))));
        }

        if (authRequired.Count > 0)
        {
            findings.Add(Finding(check, check.Tools, "Info", "source.route.auth_required",
                P(("observed", $"{authRequired.Count} source-derived route(s) require auth (401/403). Sample: {string.Join(", ", authRequired.Take(8).Select(a => $"{a.Method} {a.Url}({a.Status})"))}"),
                    ("impact", "These endpoints exist at runtime; follow up with authenticated testing."),
                    ("targetUrl", targetUrl)),
                string.Join("; ", authRequired.Take(30).Select(a => $"{a.Method} {a.Url} -> {a.Status}"))));
        }

        if (unexpectedExposed.Count == 0 && intentionalPublic.Count == 0 && authRequired.Count == 0)
        {
            findings.Add(Finding(check, check.Tools, "Info", "source.route.probe_none",
                P(("observed", $"Probed {probed} source-derived route(s) on {targetUrl}; no anonymous 2xx or 401/403 signals."),
                    ("targetUrl", targetUrl)),
                other.Count == 0
                    ? $"probed={probed}"
                    : $"other={string.Join(',', other.Take(12).Select(o => $"{o.Method}:{o.Status}"))}"));
        }

        return findings;
    }

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateDirectoryDiscoveryAsync(
        HttpClient client,
        ScanCheckDefinition check,
        IReadOnlyList<string> tools,
        string targetUrl,
        IReadOnlyList<string> secondaryTargets,
        IReadOnlyList<string> sourceProbePaths,
        ScanToolOptions toolOpts,
        CancellationToken cancellationToken)
    {
        var origins = new List<string> { ToOriginUrl(targetUrl) };
        foreach (var secondary in secondaryTargets)
        {
            var origin = ToOriginUrl(secondary);
            if (!origins.Any(o => string.Equals(o, origin, StringComparison.OrdinalIgnoreCase)))
                origins.Add(origin);
        }

        var allHits = new List<ExternalToolRunner.DiscoveryHit>();
        string? toolName = null;
        var toolNotes = new List<string>();
        var sourceWordlist = ExternalToolRunner.WriteMergedWordlist(sourceProbePaths);
        try
        {
        foreach (var (origin, index) in origins.Select((o, i) => (o, i)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var feroxOpts = toolOpts.Feroxbuster;
            var ffufOpts = toolOpts.Ffuf;
            if (index > 0)
            {
                feroxOpts = new FeroxToolOptions
                {
                    Depth = Math.Min(feroxOpts.Depth, 1),
                    Threads = Math.Min(feroxOpts.Threads, 20),
                    TimeoutSeconds = Math.Min(feroxOpts.TimeoutSeconds, 5),
                    MaxDurationSeconds = Math.Clamp(feroxOpts.MaxDurationSeconds / 2, 30, 60),
                };
                feroxOpts.Normalize();
                ffufOpts = new FfufToolOptions
                {
                    Threads = Math.Min(ffufOpts.Threads, 20),
                    TimeoutSeconds = Math.Min(ffufOpts.TimeoutSeconds, 5),
                    MaxDurationSeconds = Math.Clamp(ffufOpts.MaxDurationSeconds / 2, 30, 60),
                    MatchCodes = ffufOpts.MatchCodes,
                };
                ffufOpts.Normalize();
            }

            if (tools.Contains("feroxbuster", StringComparer.OrdinalIgnoreCase))
            {
                var ferox = await ExternalToolRunner.TryFeroxAsync(origin, cancellationToken, feroxOpts, sourceWordlist);
                if (ferox is { Ran: true })
                {
                    toolName ??= "feroxbuster";
                    var hits = ExternalToolRunner.ParseFeroxHits(ferox.StdOut);
                    allHits.AddRange(hits);
                    toolNotes.Add($"{origin} ferox exit={ferox.ExitCode} hits={hits.Count} wl={(sourceWordlist is null ? "default" : "source+default")}");
                    if (hits.Count > 0) continue;
                    if (ferox.ExitCode is not (0 or 1) && index == 0)
                        toolNotes.Add($"ferox_warn_exit={ferox.ExitCode}");
                    // Fall through to ffuf / built-in when ferox finds nothing.
                }
            }

            if (tools.Contains("ffuf", StringComparer.OrdinalIgnoreCase))
            {
                var ffuf = await ExternalToolRunner.TryFfufAsync(origin, cancellationToken, ffufOpts, sourceWordlist);
                if (ffuf is { Ran: true })
                {
                    toolName ??= "ffuf";
                    var hits = ExternalToolRunner.ParseFfufHits(ffuf.StdOut);
                    allHits.AddRange(hits);
                    toolNotes.Add($"{origin} ffuf exit={ffuf.ExitCode} hits={hits.Count}");
                }
            }
        }

        allHits = allHits
            .GroupBy(h => h.Url, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Take(80)
            .ToList();

        if (allHits.Count > 0)
        {
            var sample = allHits[0];
            var sourceSet = new HashSet<string>(
                sourceProbePaths.Select(p => p.Trim().TrimStart('/')),
                StringComparer.OrdinalIgnoreCase);
            static string HitPath(string url)
            {
                try { return new Uri(url).AbsolutePath.Trim('/'); }
                catch { return url.Trim().TrimStart('/'); }
            }
            var novelHits = allHits.Where(h => !sourceSet.Contains(HitPath(h.Url))).ToList();
            var severity = novelHits.Count > 0 ? "Medium" : "Info";
            var code = novelHits.Count > 0 ? "directory.found" : "directory.source_confirmed";
            return
            [
                Finding(check, tools, severity, code, P(
                        ("url", sample.Url), ("status", sample.Status.ToString()),
                        ("observed", $"{toolName ?? "discovery"} found {allHits.Count} path(s) across {origins.Count} origin(s)" +
                                     (novelHits.Count > 0 ? $" ({novelHits.Count} novel)." : " (all already in source inventory).") +
                                     $" Sample: {string.Join(", ", allHits.Take(12).Select(h => $"{h.Url}({h.Status})"))}."),
                        ("impact", novelHits.Count > 0
                            ? "Exposed administration, backup, or API paths can focus attacker activity."
                            : "These paths were already inventoried from source — treat as coverage confirmation.")),
                    $"tool={toolName}; targets={origins.Count}; {string.Join("; ", allHits.Take(40).Select(h => $"{h.Url} -> {h.Status}"))}")
            ];
        }
        // Continue to built-in/source HTTP probes even when ferox/ffuf ran with zero hits.
        }
        finally
        {
            if (sourceWordlist is not null)
            {
                try { File.Delete(sourceWordlist); } catch { /* ignore */ }
            }
        }

        // Built-in wordlist + source-derived paths on primary (+ secondary origins, capped).
        var found = new List<(string Path, int Code, string Url, string Note)>();
        foreach (var origin in origins.Take(2))
        {
            var baseUri = new Uri(origin);
            var paths = new[]
                {
                    "admin", "login", "dashboard", "api", "swagger", "graphql",
                    "backup", "uploads", "static", "assets", "wp-admin", "robots.txt", "sitemap.xml"
                }
                .Concat(sourceProbePaths.Take(40))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var baseline = await ProbeUrlAsync(
                client,
                new Uri(baseUri, $".__sp_missing_{Guid.NewGuid():N}__/").ToString(),
                cancellationToken);

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

                    found.Add((path, code, url, probe.ContentType ?? "unknown"));
                }
                catch
                {
                    // ignore
                }
            }
        }

        if (found.Count > 0)
        {
            var sample = found[0];
            // Paths already known from source AllowAnonymous inventory are confirmation, not new exposure.
            var sourceSet = new HashSet<string>(
                sourceProbePaths.Select(p => p.Trim().TrimStart('/')),
                StringComparer.OrdinalIgnoreCase);
            var novel = found.Where(f => !sourceSet.Contains(f.Path.Trim().TrimStart('/'))).ToList();
            var severity = novel.Count > 0 ? "Medium" : "Info";
            var code = novel.Count > 0 ? "directory.found" : "directory.source_confirmed";
            var list = novel.Count > 0 ? novel : found;
            return
            [
                Finding(check, tools, severity, code, P(
                        ("url", sample.Url), ("status", sample.Code.ToString()),
                        ("observed", novel.Count > 0
                            ? $"The built-in wordlist found {found.Count} paths ({novel.Count} not in source inventory): {string.Join(", ", found.Select(f => $"{f.Path}({f.Code})"))}."
                            : $"Built-in discovery confirmed {found.Count} source-derived path(s): {string.Join(", ", found.Select(f => $"{f.Path}({f.Code})"))}."),
                        ("impact", novel.Count > 0
                            ? "Exposed administration, backup, or API paths can focus attacker activity."
                            : "These paths were already inventoried from source — treat as coverage confirmation.")),
                    string.Join("; ", list.Select(f => $"{f.Url} -> {f.Code} [{f.Note}]")))
            ];
        }

        return
        [
            Finding(check, tools, "Info", "directory.none", P(("targetUrl", targetUrl)),
                $"targets={string.Join(",", origins)}")
        ];
    }

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateSensitiveFilesAsync(
        HttpClient client,
        ScanCheckDefinition check,
        IReadOnlyList<string> tools,
        string targetUrl,
        IReadOnlyList<string> secondaryTargets,
        NucleiToolOptions nucleiOpts,
        CancellationToken cancellationToken)
    {
        var findings = new List<ScanFindingDto>();
        var nucleiTargets = new List<string> { targetUrl };
        foreach (var secondary in secondaryTargets.Take(2))
        {
            if (!nucleiTargets.Any(t => string.Equals(t, secondary, StringComparison.OrdinalIgnoreCase)))
                nucleiTargets.Add(secondary);
        }

        if (tools.Contains("nuclei", StringComparer.OrdinalIgnoreCase))
        {
            var totalHits = 0;
            var notes = new List<string>();
            var completed = 0;
            foreach (var (url, index) in nucleiTargets.Select((u, i) => (u, i)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var opts = index == 0
                    ? nucleiOpts
                    : CloneNucleiOptions(nucleiOpts, Math.Clamp(nucleiOpts.MaxDurationSeconds / 3, 45, 75));
                var nuclei = await ExternalToolRunner.TryNucleiExposuresAsync(url, cancellationToken, opts);
                if (nuclei is not { Ran: true }) continue;
                completed++;
                var count = ExternalToolRunner.CountNucleiFindings(nuclei.StdOut);
                totalHits += count;
                notes.Add($"{url}: hits={count}; exit={nuclei.ExitCode}");
            }

            if (totalHits > 0)
            {
                findings.Add(Finding(check, tools, "High", "sensitive.nuclei.hits",
                    P(("observed", $"Nuclei exposure/config templates reported {totalHits} finding(s) across {completed} target(s). {string.Join(" ", notes.Take(4))}"),
                        ("impact", "Exposed configs, backups, or secrets may be downloadable."),
                        ("targetUrl", targetUrl)),
                    $"tool=nuclei; count={totalHits}; targets={completed}; {string.Join(" | ", notes.Take(6))}"));
            }
            else if (completed > 0)
            {
                findings.Add(Finding(check, tools, "Info", "sensitive.nuclei.none",
                    P(("observed", $"Nuclei exposure templates returned no hits on {completed} target(s)."),
                        ("targetUrl", targetUrl)),
                    $"tool=nuclei; targets={string.Join(",", nucleiTargets)}; {string.Join(" | ", notes.Take(6))}"));
            }
        }

        var origins = new List<string> { ToOriginUrl(targetUrl) };
        foreach (var secondary in secondaryTargets.Take(2))
        {
            var origin = ToOriginUrl(secondary);
            if (!origins.Any(o => string.Equals(o, origin, StringComparison.OrdinalIgnoreCase)))
                origins.Add(origin);
        }

        var paths = new[]
        {
            ".env", ".git/config", ".git/HEAD", "web.config", "appsettings.json",
            "backup.sql", "dump.sql", "config.php", "phpinfo.php", ".DS_Store",
            "id_rsa", "server-status", "actuator/env", "api/swagger.json"
        };

        var hits = new List<(string Path, int Code, string Url, string EvidenceNote)>();
        UrlProbe? lastBaseline = null;

        foreach (var origin in origins)
        {
            var baseUri = new Uri(origin);
            var baseline = await ProbeUrlAsync(
                client,
                new Uri(baseUri, $".__sp_missing_{Guid.NewGuid():N}__.txt").ToString(),
                cancellationToken);
            lastBaseline = baseline;

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
        }

        if (hits.Count > 0)
        {
            var sample = hits[0];
            findings.Add(Finding(check, tools, "High", "sensitive.found", P(
                    ("url", sample.Url), ("status", sample.Code.ToString()),
                    ("observed", $"Validated sensitive paths returned HTTP 2xx: {string.Join(", ", hits.Select(h => $"{h.Path}({h.Code})"))}."),
                    ("impact", "Configuration, backup, or source files may expose secrets and system details.")),
                string.Join("; ", hits.Select(h => $"{h.Url} -> {h.Code}; {h.EvidenceNote}"))));
        }
        else if (findings.Count == 0)
        {
            findings.Add(Finding(check, tools, "Info", "sensitive.none", P(("targetUrl", targetUrl)),
                lastBaseline is null
                    ? $"targets={origins.Count}"
                    : $"baseline_status={lastBaseline.StatusCode}; baseline_ctype={lastBaseline.ContentType ?? "unknown"}; targets={origins.Count}"));
        }

        return findings;
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
        try
        {
            ScanHostSafety.EnsureSafeHttpTarget(url);
        }
        catch
        {
            return null;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        using var response = await SendWithSafeRedirectsAsync(
            client, request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
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

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateVulnerabilityAsync(
        ScanCheckDefinition check,
        IReadOnlyList<string> tools,
        string targetUrl,
        IReadOnlyList<string> secondaryTargets,
        NucleiToolOptions nucleiOpts,
        CancellationToken cancellationToken)
    {
        if (!tools.Contains("nuclei", StringComparer.OrdinalIgnoreCase)
            || !ExternalToolRunner.IsAvailable("nuclei"))
        {
            return
            [
                Finding(check, tools, "Info", "vuln.placeholder",
                    P(("observed", "Nuclei binary not available on scanner host; vulnerability templates were skipped."),
                        ("impact", "Install Nuclei on the API/worker image or keep sensitive-file-scan enabled."),
                        ("targetUrl", targetUrl)),
                    $"target={targetUrl}; tool=nuclei; available=false")
            ];
        }

        var targets = new List<string> { targetUrl };
        foreach (var secondary in secondaryTargets.Take(2))
        {
            if (!targets.Any(t => string.Equals(t, secondary, StringComparison.OrdinalIgnoreCase)))
                targets.Add(secondary);
        }

        var totalHits = 0;
        var notes = new List<string>();
        var anyPartial = false;
        var anyCompleteSuccess = false;
        var anyHardFailure = false;
        string? lastSummary = null;

        foreach (var (url, index) in targets.Select((u, i) => (u, i)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Secondary backends get a shorter budget so Deep max-detection still finishes.
            var opts = index == 0
                ? nucleiOpts
                : CloneNucleiOptions(nucleiOpts, Math.Clamp(nucleiOpts.MaxDurationSeconds / 2, 60, 120));

            var nuclei = await ExternalToolRunner.TryNucleiAsync(url, cancellationToken, options: opts);
            if (nuclei is null)
            {
                anyHardFailure = true;
                notes.Add($"{url}: unavailable");
                continue;
            }

            lastSummary = nuclei.Summary;
            var count = ExternalToolRunner.CountNucleiFindings(nuclei.StdOut);
            var partial = nuclei.Summary.Contains("partial", StringComparison.OrdinalIgnoreCase)
                          || nuclei.ExitCode == -1;
            if (partial) anyPartial = true;

            if (nuclei.Ran)
            {
                if (!partial || count > 0)
                    anyCompleteSuccess = true;
                totalHits += count;
                notes.Add($"{url}: hits={count}; exit={nuclei.ExitCode}; partial={partial}");
            }
            else
            {
                anyHardFailure = true;
                notes.Add($"{url}: error={Truncate(nuclei.Summary)}");
            }
        }

        if (totalHits > 0)
        {
            return
            [
                Finding(check, tools, "High", "vuln.nuclei.hits",
                    P(("observed", $"Nuclei ({nucleiOpts.Profile}) reported {totalHits} finding(s) across {targets.Count} target(s){(anyPartial ? " (includes partial run)" : "")}. {string.Join(" ", notes.Take(4))}"),
                        ("impact", "Template-based scanner detected exposures or CVEs."),
                        ("targetUrl", targetUrl)),
                    $"tool=nuclei; profile={nucleiOpts.Profile}; severity={nucleiOpts.Severity}; count={totalHits}; targets={targets.Count}; partial={anyPartial}; {string.Join(" | ", notes.Take(6))}")
            ];
        }

        if (anyCompleteSuccess && !anyHardFailure)
        {
            return
            [
                Finding(check, tools, "Info", "vuln.nuclei.none",
                    P(("observed", $"Nuclei ({nucleiOpts.Profile}) completed with no hits for severity={nucleiOpts.Severity} on {targets.Count} target(s){(anyPartial ? " (partial on some)" : "")}."),
                        ("targetUrl", targetUrl)),
                    $"tool=nuclei; profile={nucleiOpts.Profile}; severity={nucleiOpts.Severity}; targets={string.Join(",", targets)}; partial={anyPartial}; {string.Join(" | ", notes.Take(6))}")
            ];
        }

        if (anyCompleteSuccess)
        {
            // Primary or a secondary finished clean; mention incomplete siblings without failing the check.
            return
            [
                Finding(check, tools, "Info", "vuln.nuclei.none",
                    P(("observed", $"Nuclei ({nucleiOpts.Profile}) found no hits; some targets incomplete. {string.Join(" ", notes.Take(4))}"),
                        ("targetUrl", targetUrl)),
                    $"tool=nuclei; profile={nucleiOpts.Profile}; severity={nucleiOpts.Severity}; partial={anyPartial}; {string.Join(" | ", notes.Take(6))}")
            ];
        }

        return
        [
            Finding(check, tools, "Info", "vuln.nuclei.error",
                P(("observed", $"Nuclei was present but did not complete on scanned targets: {Truncate(lastSummary ?? string.Join("; ", notes))}"),
                    ("impact", "Vulnerability coverage may be incomplete until Nuclei runs successfully."),
                    ("targetUrl", targetUrl)),
                $"tool=nuclei; ran=false; targets={targets.Count}; {string.Join(" | ", notes.Take(6))}")
        ];
    }

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateTechnologyAsync(
        ScanCheckDefinition check,
        IReadOnlyList<string> tools,
        Dictionary<string, string> headers,
        string? server,
        string? poweredBy,
        string targetUrl,
        CancellationToken cancellationToken)
    {
        var findings = new List<ScanFindingDto>();
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

        if (tools.Contains("whatweb", StringComparer.OrdinalIgnoreCase))
        {
            var whatweb = await ExternalToolRunner.TryWhatWebAsync(targetUrl, cancellationToken);
            if (whatweb is { Ran: true } && !string.IsNullOrWhiteSpace(whatweb.StdOut))
            {
                findings.Add(Finding(check, tools, "Info", "tech.whatweb",
                    P(("observed", $"WhatWeb fingerprint: {Truncate(whatweb.Summary)}"),
                        ("targetUrl", targetUrl)),
                    $"tool=whatweb; exit={whatweb.ExitCode}"));
            }
        }

        findings.Add(Finding(check, tools, tech.Count > 0 ? "Low" : "Info",
            tech.Count > 0 ? "tech.found" : "tech.none",
            P(("tech", string.Join("; ", tech)), ("targetUrl", targetUrl)),
            tech.Count > 0 ? string.Join("; ", tech) : null));

        return findings;
    }

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateScreenshotAsync(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, CancellationToken cancellationToken)
    {
        if (tools.Contains("gowitness", StringComparer.OrdinalIgnoreCase)
            && ExternalToolRunner.IsAvailable("gowitness"))
        {
            var dir = Path.Combine(Path.GetTempPath(), "sp-gowitness", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var run = await ExternalToolRunner.RunAsync(
                    "gowitness",
                    $"single {QuoteArg(targetUrl)} --screenshot-path {QuoteArg(dir)}",
                    TimeSpan.FromSeconds(45),
                    cancellationToken);
                if (run.Ran && run.ExitCode == 0)
                {
                    return
                    [
                        Finding(check, tools, "Info", "screenshot.ok",
                            P(("observed", $"Gowitness captured screenshot for {targetUrl}."),
                                ("targetUrl", targetUrl)),
                            $"tool=gowitness; path={dir}")
                    ];
                }
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { /* ignore */ }
            }
        }

        return
        [
            Finding(check, tools, "Info", "screenshot.placeholder",
                P(("observed", "Gowitness not available on scanner host."),
                    ("targetUrl", targetUrl)),
                $"target={targetUrl}; tool=gowitness; available=false")
        ];
    }

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateDnsAsync(
        ScanCheckDefinition check, IReadOnlyList<string> tools, string targetUrl, CancellationToken cancellationToken)
    {
        var host = new Uri(targetUrl).Host;
        if (tools.Contains("dnsx", StringComparer.OrdinalIgnoreCase))
        {
            var dnsx = await ExternalToolRunner.TryDnsxAsync(host, cancellationToken);
            if (dnsx is { Ran: true } && !string.IsNullOrWhiteSpace(dnsx.StdOut))
            {
                return
                [
                    Finding(check, tools, "Info", "dns.ok",
                        P(("host", host), ("addresses", Truncate(dnsx.StdOut))),
                        $"host={host}; tool=dnsx; out={Truncate(dnsx.StdOut)}")
                ];
            }
        }

        try
        {
            var addresses = await System.Net.Dns.GetHostAddressesAsync(host, cancellationToken);
            // Do not echo private IPs into findings if somehow resolved (should be blocked earlier).
            var publicAddrs = addresses.Where(a => !ScanHostSafety.IsBlockedIp(a)).Select(a => a.ToString()).ToList();
            var evidence = string.Join(", ", publicAddrs);
            return
            [
                Finding(check, tools, "Info", "dns.ok", P(("host", host), ("addresses", evidence)),
                    $"host={host}; tool=system-dns; addrs={evidence}")
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

    private static async Task<IReadOnlyList<ScanFindingDto>> EvaluateWafAsync(
        ScanCheckDefinition check,
        IReadOnlyList<string> tools,
        string targetUrl,
        Dictionary<string, string> headers,
        string? server,
        CancellationToken cancellationToken)
    {
        if (tools.Contains("wafw00f", StringComparer.OrdinalIgnoreCase))
        {
            var waf = await ExternalToolRunner.TryWafw00fAsync(targetUrl, cancellationToken);
            if (waf is { Ran: true } && !string.IsNullOrWhiteSpace(waf.StdOut + waf.StdErr))
            {
                var text = ExternalToolRunner.StripAnsi(waf.StdOut + "\n" + waf.StdErr);
                var none = text.Contains("No WAF", StringComparison.OrdinalIgnoreCase)
                           || text.Contains("is not behind a WAF", StringComparison.OrdinalIgnoreCase)
                           || text.Contains("no WAF has been detected", StringComparison.OrdinalIgnoreCase);
                var found = !none && (
                    text.Contains("is behind a WAF", StringComparison.OrdinalIgnoreCase)
                    || text.Contains("is behind", StringComparison.OrdinalIgnoreCase)
                    || Regex.IsMatch(text, @"WAF\s*:\s*\S+", RegexOptions.IgnoreCase));
                return
                [
                    Finding(check, tools, "Info",
                        found ? "waf.found" : "waf.none",
                        P(("signals", Truncate(text))),
                        $"tool=wafw00f; {Truncate(text)}")
                ];
            }
        }

        var signals = new List<string>();
        if (headers.ContainsKey("CF-Ray") || headers.ContainsKey("CF-Cache-Status")) signals.Add("Cloudflare");
        if (headers.ContainsKey("X-Sucuri-ID")) signals.Add("Sucuri");
        if (headers.ContainsKey("X-Akamai-Transformed") || (server?.Contains("AkamaiGHost", StringComparison.OrdinalIgnoreCase) ?? false))
            signals.Add("Akamai");
        if (headers.ContainsKey("X-Iinfo") || headers.ContainsKey("X-CDN")) signals.Add("Imperva/Incapsula-like");

        if (signals.Count > 0)
        {
            return
            [
                Finding(check, tools, "Info", "waf.found", P(("signals", string.Join(", ", signals))),
                    $"tool=header-fingerprint; {string.Join(',', signals)}")
            ];
        }

        return
        [
            Finding(check, tools, "Info", "waf.none", P(), "tool=header-fingerprint")
        ];
    }

    private static string QuoteArg(string value) =>
        "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    private static Task<HttpResponseMessage> SendWithSafeRedirectsAsync(
        HttpClient client,
        HttpRequestMessage initial,
        CancellationToken cancellationToken) =>
        SendWithSafeRedirectsAsync(client, initial, HttpCompletionOption.ResponseContentRead, cancellationToken);

    private static async Task<HttpResponseMessage> SendWithSafeRedirectsAsync(
        HttpClient client,
        HttpRequestMessage initial,
        HttpCompletionOption completion,
        CancellationToken cancellationToken,
        int maxRedirects = 8)
    {
        var method = initial.Method;
        var currentUrl = initial.RequestUri?.ToString()
            ?? throw new InvalidOperationException("Request URI required.");
        ScanHostSafety.EnsureSafeHttpTarget(currentUrl);

        HttpContent? content = initial.Content;
        var headerCopy = initial.Headers.ToList();
        HttpRequestMessage request = initial;
        for (var hop = 0; hop <= maxRedirects; hop++)
        {
            var response = await client.SendAsync(request, completion, cancellationToken);
            if (response.StatusCode is not (HttpStatusCode.MovedPermanently or HttpStatusCode.Found
                or HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect))
            {
                return response;
            }

            var location = response.Headers.Location;
            response.Dispose();
            if (location is null)
                throw new InvalidOperationException("Redirect without Location header.");

            var next = location.IsAbsoluteUri
                ? location
                : new Uri(new Uri(currentUrl), location);
            if (!ScanHostSafety.IsSafeRedirectTarget(next))
                throw new InvalidOperationException($"Blocked redirect to unsafe host: {next.Host}");

            currentUrl = next.ToString();
            // After POST redirect, browsers typically switch to GET (303/302).
            method = HttpMethod.Get;
            content = null;
            request = new HttpRequestMessage(method, currentUrl);
            foreach (var h in headerCopy)
                request.Headers.TryAddWithoutValidation(h.Key, h.Value);
        }

        throw new InvalidOperationException("Too many redirects.");
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
        // Category-weighted score: API/auth/source findings outweigh baseline header gaps.
        static double Weight(ScanFindingDto f)
        {
            var code = f.Code ?? "";
            if (code.StartsWith("header.", StringComparison.OrdinalIgnoreCase)
                || code.StartsWith("cookie.", StringComparison.OrdinalIgnoreCase)
                || code.StartsWith("fingerprint.", StringComparison.OrdinalIgnoreCase)
                || code.Equals("reachability.4xx", StringComparison.OrdinalIgnoreCase))
                return 0.4;
            if (code.StartsWith("source.route.public_ok", StringComparison.OrdinalIgnoreCase)
                || code.EndsWith(".none", StringComparison.OrdinalIgnoreCase)
                || code.EndsWith(".ok", StringComparison.OrdinalIgnoreCase)
                || code.EndsWith(".placeholder", StringComparison.OrdinalIgnoreCase))
                return 0;
            if (code.StartsWith("source.", StringComparison.OrdinalIgnoreCase)
                || code.StartsWith("auth.surface.", StringComparison.OrdinalIgnoreCase)
                || code.StartsWith("vuln.", StringComparison.OrdinalIgnoreCase)
                || code.StartsWith("sensitive.", StringComparison.OrdinalIgnoreCase)
                || code.StartsWith("port.sensitive", StringComparison.OrdinalIgnoreCase))
                return 1.15;
            return 1.0;
        }

        double score = 0;
        var highIdx = 0;
        var mediumIdx = 0;
        var lowIdx = 0;
        var actionableHigh = 0;
        var actionableMedium = 0;

        foreach (var f in findings.OrderByDescending(f => f.Severity switch
                 {
                     "High" or "Critical" => 3,
                     "Medium" => 2,
                     "Low" => 1,
                     _ => 0
                 }))
        {
            var w = Weight(f);
            if (w <= 0) continue;
            switch (f.Severity)
            {
                case "High" or "Critical":
                    score += 25 * Math.Pow(0.85, highIdx++) * w;
                    if (w >= 1) actionableHigh++;
                    break;
                case "Medium":
                    score += 12 * Math.Pow(0.8, mediumIdx++) * w;
                    if (w >= 1) actionableMedium++;
                    break;
                case "Low":
                    score += 5 * Math.Pow(0.75, lowIdx++) * w;
                    break;
            }
        }

        var rounded = (int)Math.Round(score);
        // Floors use weighted/actionable severities so header-only Highs do not force 55+.
        if (actionableHigh > 0) rounded = Math.Max(rounded, 55);
        else if (actionableMedium > 0) rounded = Math.Max(rounded, 25);
        else if (highIdx > 0) rounded = Math.Max(rounded, 35); // baseline-only Highs

        return Math.Clamp(rounded, 0, 100);
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

    private sealed record AuthAttemptResult(bool Success, string LoginUrl, string Message);
    private sealed record LoginFormExtract(
        string ActionUrl,
        Dictionary<string, string> Fields,
        string UsernameField,
        string PasswordField);

    private sealed record AnalysisResult(
        string Summary,
        int StatusCode,
        long ResponseTimeMs,
        bool HasHttps,
        string? ServerHeader,
        ScanReportPayloadDto Report);
}
