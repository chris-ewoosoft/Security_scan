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
                logger.LogWarning(ex, "Scan {ScanId} failed for {Url}", scan.Id, scan.TargetUrl);
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

    private static HttpClientHandler CreateScanHandler() => ScanHttpClientFactory.CreateHandler();

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
        var authFindings = new List<ScanFindingDto>();
        var sourceFindings = new List<ScanFindingDto>();
        var sourceProbePaths = new List<string>();
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
            .Where(c => !c.Id.Equals("authenticated-scan", StringComparison.OrdinalIgnoreCase)
                        && !c.Id.Equals(SourceRouteInventoryAnalyzer.CheckId, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var deepClient = client;

        var findings = new List<ScanFindingDto>();
        findings.AddRange(sourceFindings);
        findings.AddRange(authFindings);

        foreach (var check in selectedChecks)
        {
            await EnsureNotCancelledAsync(scanId, cancellationToken);

            var tools = check.Tools.Where(t => config.Tools.Contains(t, StringComparer.OrdinalIgnoreCase)).ToList();
            if (tools.Count == 0) tools = check.Tools.ToList();

            var needsAuthSession = check.Id is "directory-discovery" or "sensitive-file-scan";
            if (needsAuthSession && config.Auth?.IsEnabled == true && !authenticated)
                continue;

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
                "directory-discovery" => await EvaluateDirectoryDiscoveryAsync(deepClient, check, tools, targetUrl, cancellationToken),
                "sensitive-file-scan" => await EvaluateSensitiveFilesAsync(deepClient, check, tools, targetUrl, cancellationToken),
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
            yield return Finding(AuthCheckDef, AuthCheckDef.Tools, "Medium", "auth.session.cookie_missing",
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
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var target))
            return [];

        // Sibling Clever-style hosts commonly used after OIDC login.
        if (target.Host.Contains("intro.", StringComparison.OrdinalIgnoreCase))
        {
            var graphHost = target.Host.Replace("intro.", "cvgraph2.", StringComparison.OrdinalIgnoreCase);
            bases.Add($"{target.Scheme}://{graphHost}/graphql");
        }

        if (target.Host.Contains("cvmanager.", StringComparison.OrdinalIgnoreCase))
        {
            var backend = target.Host.Replace("cvmanager.", "cvmanager-backend.", StringComparison.OrdinalIgnoreCase);
            bases.Add($"{target.Scheme}://{backend}/graphql");
        }

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
                     && anon.BodyFingerprint != auth.BodyFingerprint)
            {
                diffs.Add($"{path}: anon={anon.StatusCode} -> auth={auth.StatusCode}");
            }
        }

        if (diffs.Count > 0)
        {
            findings.Add(Finding(AuthCheckDef, AuthCheckDef.Tools, "Medium", "auth.surface.authz_diff",
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
            using var resp = await client.SendAsync(req, cancellationToken);
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
                using var unauthResponse = await client.SendAsync(
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
                using var response = await client.SendAsync(probe, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
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
            using var loginPage = await client.SendAsync(getLogin, cancellationToken);
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
            using var loginPage = await client.SendAsync(getLogin, cancellationToken);
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
        using var posted = await client.SendAsync(post, cancellationToken);
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
        using var resp = await client.SendAsync(confirmPost, cancellationToken);
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
        using var response = await client.SendAsync(request, cancellationToken);
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
                using var res = await client.SendAsync(req, cancellationToken);
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
