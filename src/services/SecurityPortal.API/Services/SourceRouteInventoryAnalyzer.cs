using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using LibGit2Sharp;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.Scans.DTOs;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.API.Services;

/// <summary>
/// Phase-1 source-assisted scan: shallow Git clone + heuristic route inventory.
/// Hard limits keep work safe inside the API poller until a sandbox worker exists.
/// </summary>
public static partial class SourceRouteInventoryAnalyzer
{
    public const string CheckId = "route-inventory";
    private static readonly ScanCheckDefinition CheckDef = new(
        CheckId,
        "Source Route Inventory",
        "Clone Git and extract route/API inventory.",
        ["source-analyzer"],
        false,
        "recon",
        5);

    private const int CloneTimeoutSeconds = 90;
    /// <summary>Size of analyzable tree (excludes .git / node_modules / build outputs).</summary>
    private const long MaxWorktreeBytes = 512L * 1024 * 1024;
    private const int MaxFilesToScan = 4_000;
    private const int MaxRoutesInFinding = 80;
    private const int MaxAuthzCandidates = 25;

    private static readonly string[] SkipDirNames =
    [
        ".git", "node_modules", "bin", "obj", "dist", "build", ".next", "coverage",
        "vendor", "packages", ".turbo", ".cache", "TestResults", "__pycache__"
    ];

    private static readonly string[] CodeExtensions =
    [
        ".cs", ".ts", ".tsx", ".js", ".jsx", ".json", ".yaml", ".yml", ".graphql", ".gql"
    ];

    /// <summary>Structured probe target retained from source (method + auth hints).</summary>
    public sealed record ProbeRoute(
        string Method,
        string Path,
        bool AllowAnonymous,
        bool OwnerTokenGuarded);

    public sealed record InventoryResult(
        IReadOnlyList<ScanFindingDto> Findings,
        IReadOnlyList<string> ProbePaths,
        string? ArtifactJson,
        IReadOnlyList<ProbeRoute> ProbeRoutes);

    public static async Task<InventoryResult> AnalyzeAsync(
        Guid scanId,
        ScanSourceConfiguration source,
        IScanSecretProtector secretProtector,
        IFileStorage? fileStorage,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var tools = CheckDef.Tools;
        var workRoot = Path.Combine(Path.GetTempPath(), "sp-source", scanId.ToString("N"));
        Directory.CreateDirectory(workRoot);
        var cloneDir = Path.Combine(workRoot, "repo");
        string? token = null;

        var usedLocalWorkspace = false;
        try
        {
            token = string.IsNullOrWhiteSpace(source.TokenCipher)
                ? null
                : secretProtector.Unprotect(source.TokenCipher);

            CloneOutcome clone;
            if (TryResolveLocalSource(source.RepositoryUrl, out var localRoot))
            {
                usedLocalWorkspace = true;
                cloneDir = localRoot!;
                clone = new CloneOutcome(true, "local-workspace", "workspace");
                logger.LogInformation(
                    "Using local source root {Root} for scan {ScanId} (SECURITYPORTAL_LOCAL_SOURCE_ROOT)",
                    localRoot, scanId);
            }
            else
            {
                clone = await CloneAsync(source.RepositoryUrl!, source.Branch, token, cloneDir, cancellationToken);
            }

            if (!clone.Ok)
            {
                return new InventoryResult(
                [
                    Finding("High", "source.clone.failed",
                        P(("observed", clone.Message),
                            ("impact", "Source-assisted route inventory and authz hints were skipped."),
                            ("repository", MaskRepo(source.RepositoryUrl))),
                        clone.Message)
                ], [], null, []);
            }

            var size = DirSize(cloneDir, excludeSkipDirs: true);
            if (size > MaxWorktreeBytes)
            {
                return new InventoryResult(
                [
                    Finding("Medium", "source.clone.too_large",
                        P(("observed", $"Analyzable source ~{size / (1024 * 1024)} MB exceeds limit {MaxWorktreeBytes / (1024 * 1024)} MB (`.git`/build folders excluded)."),
                            ("impact", "Inventory skipped to protect scanner resources."),
                            ("repository", MaskRepo(source.RepositoryUrl))),
                        $"bytes={size}")
                ], [], null, []);
            }

            var inventory = ExtractRoutes(cloneDir, cancellationToken);
            var probeRoutes = inventory.Routes
                .Where(r => !r.Method.Equals("GQL", StringComparison.OrdinalIgnoreCase))
                .Select(r => new ProbeRoute(
                    r.Method,
                    NormalizeProbePath(r),
                    r.AllowAnonymous,
                    r.OwnerTokenGuarded))
                .Where(r => !string.IsNullOrWhiteSpace(r.Path))
                .GroupBy(r => $"{r.Method}|{r.Path}", StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .Take(120)
                .ToList();
            var probePaths = probeRoutes
                .Select(r => r.Path)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var findings = new List<ScanFindingDto>();
            if (inventory.Routes.Count == 0)
            {
                findings.Add(Finding("Low", "source.routes.none",
                    P(("observed", $"Cloned {MaskRepo(source.RepositoryUrl)} but no routes matched built-in heuristics."),
                        ("impact", "HTTP scan was not enriched from source; add OpenAPI or supported frameworks."),
                        ("repository", MaskRepo(source.RepositoryUrl)),
                        ("commit", clone.Commit ?? "unknown")),
                    $"filesScanned={inventory.FilesScanned}"));
            }
            else
            {
                var sample = string.Join("; ", inventory.Routes.Take(MaxRoutesInFinding).Select(r => $"{r.Method} {r.Path}"));
                findings.Add(Finding("Info", "source.routes.found",
                    P(("observed", $"Found {inventory.Routes.Count} route(s) from source ({inventory.FilesScanned} files). Sample: {sample}"),
                        ("impact", "Discovered paths enrich anonymous API probes, directory discovery, and Nuclei URL targets."),
                        ("repository", MaskRepo(source.RepositoryUrl)),
                        ("commit", clone.Commit ?? "unknown"),
                        ("routeCount", inventory.Routes.Count.ToString())),
                    sample));
            }

            foreach (var candidate in inventory.AuthzCandidates.Take(MaxAuthzCandidates))
            {
                // Owner-token / scan-token gates are not classic tenant BOLA — keep as Low hint.
                var severity = candidate.OwnerTokenGuarded ? "Low" : "Medium";
                var code = candidate.OwnerTokenGuarded ? "source.authz.owner_token" : "source.authz.candidate";
                findings.Add(Finding(severity, code,
                    P(("observed", candidate.OwnerTokenGuarded
                            ? $"Object-id route uses owner/scan-token style guard (not org tenant): {candidate.Method} {candidate.Path} ({candidate.File}:{candidate.Line})."
                            : $"Possible object-id route without nearby tenant/org guard: {candidate.Method} {candidate.Path} ({candidate.File}:{candidate.Line})."),
                        ("impact", candidate.OwnerTokenGuarded
                            ? "Verify token binding is mandatory and cannot be bypassed with another owner's id."
                            : "May allow BOLA/IDOR or cross-organization access — confirm with dual-account runtime tests."),
                        ("path", candidate.Path),
                        ("file", candidate.File),
                        ("line", candidate.Line.ToString())),
                    $"{candidate.File}:{candidate.Line} {candidate.Method} {candidate.Path}"));
            }

            string? artifactJson = null;
            try
            {
                artifactJson = JsonSerializer.Serialize(new
                {
                    repository = MaskRepo(source.RepositoryUrl),
                    branch = source.Branch,
                    commit = clone.Commit,
                    routeCount = inventory.Routes.Count,
                    routes = inventory.Routes.Take(500),
                    authzCandidates = inventory.AuthzCandidates.Take(100),
                }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

                if (fileStorage is not null)
                {
                    await using var ms = new MemoryStream(Encoding.UTF8.GetBytes(artifactJson));
                    await fileStorage.UploadAsync(
                        "scan-artifacts",
                        $"scans/{scanId:N}/routes.json",
                        ms,
                        "application/json",
                        cancellationToken);
                    findings.Add(Finding("Info", "source.artifact.stored",
                        P(("observed", $"Route inventory stored at scan-artifacts/scans/{scanId:N}/routes.json"),
                            ("impact", "Artifact available for follow-up BOLA pack synthesis.")),
                        $"scans/{scanId:N}/routes.json"));
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to store source inventory artifact for scan {ScanId}", scanId);
            }

            return new InventoryResult(findings, probePaths, artifactJson, probeRoutes);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning("Source inventory failed for scan {ScanId}: {Safe}",
                scanId, ScanSecretSanitizer.Sanitize(ex.Message, token));
            var safe = ScanSecretSanitizer.Sanitize(ex.Message, token);
            return new InventoryResult(
            [
                Finding("Medium", "source.inventory.error",
                    P(("observed", safe),
                        ("impact", "Source-assisted enrichment skipped."),
                        ("repository", MaskRepo(source.RepositoryUrl))),
                    null)
            ], [], null, []);
        }
        finally
        {
            // Never delete the developer workspace when LOCAL_SOURCE_ROOT was used.
            if (!usedLocalWorkspace)
                TryDelete(workRoot);
        }
    }

    /// <summary>
    /// Lab helper: SECURITYPORTAL_ALLOW_LOCAL_SOURCE=1 + SECURITYPORTAL_LOCAL_SOURCE_ROOT=/path
    /// when the configured repository URL refers to the same project (e.g. Security_scan).
    /// </summary>
    private static bool TryResolveLocalSource(string? repositoryUrl, out string? localRoot)
    {
        localRoot = null;
        if (!string.Equals(Environment.GetEnvironmentVariable("SECURITYPORTAL_ALLOW_LOCAL_SOURCE"), "1",
                StringComparison.Ordinal))
            return false;

        var root = Environment.GetEnvironmentVariable("SECURITYPORTAL_LOCAL_SOURCE_ROOT");
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            return false;

        if (string.IsNullOrWhiteSpace(repositoryUrl))
            return false;

        var marker = Path.GetFileName(root.TrimEnd(Path.DirectorySeparatorChar, '/'));
        if (string.IsNullOrWhiteSpace(marker))
            marker = "Security_scan";

        if (!repositoryUrl.Contains(marker, StringComparison.OrdinalIgnoreCase)
            && !repositoryUrl.Contains("local://", StringComparison.OrdinalIgnoreCase))
            return false;

        localRoot = Path.GetFullPath(root);
        return true;
    }

    private sealed record CloneOutcome(bool Ok, string Message, string? Commit);

    private static async Task<CloneOutcome> CloneAsync(
        string repositoryUrl,
        string? branch,
        string? token,
        string cloneDir,
        CancellationToken cancellationToken)
    {
        if (Directory.Exists(cloneDir))
            Directory.Delete(cloneDir, true);

        var cleanUrl = StripUserInfo(repositoryUrl);

        try
        {
            return await Task.Run(() =>
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(CloneTimeoutSeconds));

                var options = new CloneOptions { Checkout = true };
                options.FetchOptions.Depth = 1;

                if (!string.IsNullOrWhiteSpace(branch))
                    options.BranchName = branch.Trim();

                if (!string.IsNullOrWhiteSpace(token))
                {
                    var user = BuildCredentialUsername(cleanUrl);
                    options.FetchOptions.CredentialsProvider = (_, _, _) =>
                        new UsernamePasswordCredentials { Username = user, Password = token };
                }

                timeoutCts.Token.ThrowIfCancellationRequested();
                Repository.Clone(cleanUrl, cloneDir, options);

                using var repo = new Repository(cloneDir);
                var sha = repo.Head.Tip?.Sha;
                var shortSha = sha is { Length: >= 7 } ? sha[..7] : sha;
                return new CloneOutcome(true, "ok", shortSha);
            }, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryDelete(cloneDir);
            return new CloneOutcome(false, $"Clone timed out after {CloneTimeoutSeconds}s.", null);
        }
        catch (Exception ex)
        {
            TryDelete(cloneDir);
            return new CloneOutcome(false, ScanSecretSanitizer.Sanitize(ex.Message, token), null);
        }
    }

    private static string BuildCredentialUsername(string repositoryUrl)
    {
        var host = Uri.TryCreate(repositoryUrl, UriKind.Absolute, out var uri)
            ? uri.Host
            : "";
        if (host.Contains("gitlab", StringComparison.OrdinalIgnoreCase))
            return "oauth2";
        if (host.Contains("dev.azure.com", StringComparison.OrdinalIgnoreCase)
            || host.Contains("visualstudio.com", StringComparison.OrdinalIgnoreCase))
            return "pat";
        return "x-access-token";
    }

    private static string StripUserInfo(string repositoryUrl)
    {
        if (!Uri.TryCreate(repositoryUrl, UriKind.Absolute, out var uri))
            return repositoryUrl;
        var builder = new UriBuilder(uri) { UserName = "", Password = "" };
        // UriBuilder may leave empty userinfo as "@" on some versions — normalize.
        var cleaned = builder.Uri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped);
        return cleaned.Replace("://@", "://", StringComparison.Ordinal);
    }

    private static IEnumerable<string> EnumerateCodeFiles(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            IEnumerable<string> subdirs;
            try { subdirs = Directory.EnumerateDirectories(dir); }
            catch { continue; }

            foreach (var sub in subdirs)
            {
                var name = Path.GetFileName(sub);
                if (SkipDirNames.Contains(name, StringComparer.OrdinalIgnoreCase))
                    continue;
                stack.Push(sub);
            }

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir); }
            catch { continue; }

            foreach (var file in files)
            {
                var ext = Path.GetExtension(file);
                if (CodeExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
                    yield return file;
            }
        }
    }

    private sealed record RouteHit(
        string Method,
        string Path,
        string File,
        int Line,
        bool HasObjectId,
        bool AllowAnonymous = false,
        bool OwnerTokenGuarded = false);
    private sealed record AuthzCandidate(
        string Method,
        string Path,
        string File,
        int Line,
        bool OwnerTokenGuarded = false);
    private sealed record Extracted(IReadOnlyList<RouteHit> Routes, IReadOnlyList<AuthzCandidate> AuthzCandidates, int FilesScanned);

    private static Extracted ExtractRoutes(string root, CancellationToken cancellationToken)
    {
        var routes = new List<RouteHit>();
        var authz = new List<AuthzCandidate>();
        var filesScanned = 0;
        var classRoutes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var classBases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var csharpFiles = new List<(string Relative, string Text)>();

        foreach (var file in EnumerateCodeFiles(root))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (filesScanned >= MaxFilesToScan) break;
            filesScanned++;

            string text;
            try
            {
                text = File.ReadAllText(file);
            }
            catch
            {
                continue;
            }

            if (text.Length > 1_500_000) continue;
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            var ext = Path.GetExtension(file);

            if (ext is ".cs")
            {
                csharpFiles.Add((relative, text));
                CollectCsharpTypeRoutes(text, classRoutes, classBases);
            }
            else if (ext is ".ts" or ".tsx" or ".js" or ".jsx")
                ScanJsTs(text, relative, routes, authz);
            else if (ext is ".json" or ".yaml" or ".yml")
                ScanOpenApi(text, relative, routes);
            else if (ext is ".graphql" or ".gql")
            {
                if (text.Contains("type Query", StringComparison.Ordinal)
                    || text.Contains("type Mutation", StringComparison.Ordinal))
                    ScanGraphql(text, relative, routes);
            }

            // Next.js App Router: app/**/route.ts implies HTTP handlers
            if (relative.Contains("/app/", StringComparison.OrdinalIgnoreCase)
                && (relative.EndsWith("/route.ts", StringComparison.OrdinalIgnoreCase)
                    || relative.EndsWith("/route.js", StringComparison.OrdinalIgnoreCase)))
            {
                var apiPath = NextAppRouteToPath(relative);
                if (!string.IsNullOrWhiteSpace(apiPath))
                    routes.Add(new RouteHit("ANY", apiPath, relative, 1, apiPath.Contains('{')));
            }

            if (relative.Contains("/pages/api/", StringComparison.OrdinalIgnoreCase)
                && (ext is ".ts" or ".js" or ".tsx" or ".jsx"))
            {
                var apiPath = PagesApiToPath(relative);
                if (!string.IsNullOrWhiteSpace(apiPath))
                    routes.Add(new RouteHit("ANY", apiPath, relative, 1, apiPath.Contains('{')));
            }
        }

        foreach (var (relative, text) in csharpFiles)
            ScanCsharp(text, relative, routes, authz, classRoutes, classBases);

        var deduped = routes
            .GroupBy(r => $"{r.Method}|{r.Path}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(r => r.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new Extracted(deduped, authz, filesScanned);
    }

    private static void CollectCsharpTypeRoutes(
        string text,
        Dictionary<string, string> classRoutes,
        Dictionary<string, string> classBases)
    {
        foreach (Match m in CsClassDeclRegex().Matches(text))
        {
            var name = m.Groups["name"].Value;
            if (m.Groups["base"].Success)
                classBases[name] = m.Groups["base"].Value;

            // Nearest [Route("...")] before the class keyword in a small window.
            var windowStart = Math.Max(0, m.Index - 500);
            var window = text[windowStart..m.Index];
            var routeMatches = CsRouteAttributeRegex().Matches(window);
            if (routeMatches.Count > 0)
                classRoutes[name] = routeMatches[^1].Groups["path"].Value;
        }
    }

    private static string? ResolveClassRoute(
        string className,
        IReadOnlyDictionary<string, string> classRoutes,
        IReadOnlyDictionary<string, string> classBases)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var current = className;
        while (!string.IsNullOrWhiteSpace(current) && seen.Add(current))
        {
            if (classRoutes.TryGetValue(current, out var route))
                return route;
            if (!classBases.TryGetValue(current, out current))
                break;
        }

        return null;
    }

    private static void ScanCsharp(
        string text,
        string file,
        List<RouteHit> routes,
        List<AuthzCandidate> authz,
        IReadOnlyDictionary<string, string> classRoutes,
        IReadOnlyDictionary<string, string> classBases)
    {
        var controllerName = Path.GetFileNameWithoutExtension(file);
        if (controllerName.EndsWith("Controller", StringComparison.OrdinalIgnoreCase))
            controllerName = controllerName[..^"Controller".Length];

        var className = CsClassDeclRegex().Match(text) is { Success: true } cm
            ? cm.Groups["name"].Value
            : controllerName + "Controller";
        var classRoute = ResolveClassRoute(className, classRoutes, classBases);
        var classAllowAnonymous = ClassHasAllowAnonymous(text, className);
        var classAuthorize = ClassHasAuthorize(text, className)
                             || BaseDeclaresAuthorize(className, classBases, classRoutes);

        foreach (Match m in CsHttpAttributeRegex().Matches(text))
        {
            var method = m.Groups["method"].Value.ToUpperInvariant() switch
            {
                "GET" => "GET",
                "POST" => "POST",
                "PUT" => "PUT",
                "DELETE" => "DELETE",
                "PATCH" => "PATCH",
                _ => "ANY"
            };
            var action = m.Groups["path"].Success ? m.Groups["path"].Value : "";
            var path = ComposeAspNetRoute(classRoute, controllerName, action);
            var line = LineOf(text, m.Index);
            var allowAnon = MethodHasAllowAnonymous(text, m.Index) || classAllowAnonymous;
            var ownerToken = LooksOwnerTokenGuarded(text, m.Index);
            var hit = new RouteHit(method, path, file, line, HasObjectId(path), allowAnon, ownerToken);
            routes.Add(hit);
            // Skip BOLA candidate when route is intentionally anonymous-public without object id,
            // or when a tenant/org guard is present. Owner-token routes still emit a Low hint.
            if (hit.HasObjectId && !LooksTenantGuarded(text, m.Index))
                authz.Add(new AuthzCandidate(method, path, file, line, ownerToken));
            _ = classAuthorize; // reserved for future force-auth findings
        }

        foreach (Match m in CsMapRegex().Matches(text))
        {
            var method = m.Groups["method"].Value.ToUpperInvariant();
            var path = NormalizeRouteTemplate(m.Groups["path"].Value);
            var line = LineOf(text, m.Index);
            var allowAnon = MethodHasAllowAnonymous(text, m.Index) || classAllowAnonymous;
            var ownerToken = LooksOwnerTokenGuarded(text, m.Index);
            var hit = new RouteHit(method, path, file, line, HasObjectId(path), allowAnon, ownerToken);
            routes.Add(hit);
            if (hit.HasObjectId && !LooksTenantGuarded(text, m.Index))
                authz.Add(new AuthzCandidate(method, path, file, line, ownerToken));
        }
    }

    private static bool MethodHasAllowAnonymous(string text, int index)
    {
        var start = Math.Max(0, index - 350);
        return AllowAnonymousRegex().IsMatch(text[start..Math.Min(text.Length, index + 80)]);
    }

    private static bool ClassHasAllowAnonymous(string text, string className)
    {
        var m = Regex.Match(text, $@"class\s+{Regex.Escape(className)}\b", RegexOptions.IgnoreCase);
        if (!m.Success) return false;
        var start = Math.Max(0, m.Index - 600);
        return AllowAnonymousRegex().IsMatch(text[start..m.Index]);
    }

    private static bool ClassHasAuthorize(string text, string className)
    {
        var m = Regex.Match(text, $@"class\s+{Regex.Escape(className)}\b", RegexOptions.IgnoreCase);
        if (!m.Success) return false;
        var start = Math.Max(0, m.Index - 600);
        return AuthorizeRegex().IsMatch(text[start..m.Index]);
    }

    private static bool BaseDeclaresAuthorize(
        string className,
        IReadOnlyDictionary<string, string> classBases,
        IReadOnlyDictionary<string, string> _)
    {
        // Heuristic: Security Portal BaseController is [Authorize]; treat known base name as authorized.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var current = className;
        while (!string.IsNullOrWhiteSpace(current) && seen.Add(current))
        {
            if (current.Equals("BaseController", StringComparison.OrdinalIgnoreCase)
                || current.Equals("ControllerBase", StringComparison.OrdinalIgnoreCase)
                && seen.Contains("BaseController"))
            {
                if (current.Equals("BaseController", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            if (current.Equals("BaseController", StringComparison.OrdinalIgnoreCase))
                return true;
            if (!classBases.TryGetValue(current, out current))
                break;
        }
        return false;
    }

    /// <summary>Compose ASP.NET Core [Route] + [controller] + action template into a concrete path.</summary>
    internal static string ComposeAspNetRoute(string? classRoute, string controllerName, string? actionPath)
    {
        var action = string.IsNullOrWhiteSpace(actionPath)
            ? ""
            : NormalizeRouteTemplate(actionPath).TrimStart('/');

        if (string.IsNullOrWhiteSpace(classRoute))
            return string.IsNullOrWhiteSpace(action) ? "/" + controllerName.ToLowerInvariant() : NormalizeRouteTemplate(action);

        var template = classRoute.Trim().Trim('"');
        template = Regex.Replace(template, @"\{version(?::[^}]*)?\}", "1", RegexOptions.IgnoreCase);
        template = Regex.Replace(template, @"\[controller\]", controllerName, RegexOptions.IgnoreCase);
        template = Regex.Replace(template, @"\[action\]", string.IsNullOrWhiteSpace(action) ? "" : action.Split('/')[0],
            RegexOptions.IgnoreCase);
        template = template.Replace("//", "/", StringComparison.Ordinal).Trim('/');

        var combined = string.IsNullOrWhiteSpace(action) ? template : $"{template}/{action}";
        combined = Regex.Replace(combined, @"\{([^}:]+)(?::[^}]*)?\}", "{$1}");
        return NormalizeRouteTemplate(combined);
    }

    private static void ScanJsTs(string text, string file, List<RouteHit> routes, List<AuthzCandidate> authz)
    {
        foreach (Match m in ExpressRouteRegex().Matches(text))
        {
            var method = m.Groups["method"].Value.ToUpperInvariant();
            var path = NormalizeRouteTemplate(m.Groups["path"].Value);
            var line = LineOf(text, m.Index);
            var hit = new RouteHit(method, path, file, line, HasObjectId(path));
            routes.Add(hit);
            if (hit.HasObjectId && !LooksTenantGuarded(text, m.Index))
                authz.Add(new AuthzCandidate(method, path, file, line));
        }
    }

    private static void ScanOpenApi(string text, string file, List<RouteHit> routes)
    {
        // JSON "paths": { "/foo": { "get": ...
        foreach (Match m in OpenApiJsonPathRegex().Matches(text))
        {
            var path = NormalizeRouteTemplate(m.Groups["path"].Value);
            routes.Add(new RouteHit("ANY", path, file, LineOf(text, m.Index), HasObjectId(path)));
        }

        // YAML:  /foo:
        foreach (Match m in OpenApiYamlPathRegex().Matches(text))
        {
            var path = NormalizeRouteTemplate(m.Groups["path"].Value);
            if (path.StartsWith('/') || path.Contains('{'))
                routes.Add(new RouteHit("ANY", path.StartsWith('/') ? path : "/" + path, file, LineOf(text, m.Index), HasObjectId(path)));
        }
    }

    private static void ScanGraphql(string text, string file, List<RouteHit> routes)
    {
        foreach (Match m in GraphqlFieldRegex().Matches(text))
        {
            var name = m.Groups["name"].Value;
            routes.Add(new RouteHit("GQL", name, file, LineOf(text, m.Index), false));
        }
    }

    private static bool LooksTenantGuarded(string text, int index)
    {
        var start = Math.Max(0, index - 400);
        var end = Math.Min(text.Length, index + 1200);
        var window = text[start..end];
        return TenantGuardRegex().IsMatch(window);
    }

    private static bool LooksOwnerTokenGuarded(string text, int index)
    {
        var start = Math.Max(0, index - 400);
        var end = Math.Min(text.Length, index + 1600);
        return OwnerTokenGuardRegex().IsMatch(text[start..end]);
    }

    private static string NormalizeProbePath(RouteHit route)
    {
        var path = route.Path.Trim();
        if (route.Method.Equals("GQL", StringComparison.OrdinalIgnoreCase))
            return "";
        path = path.Split('?', 2)[0];
        path = ObjectIdRegex().Replace(path, "1");
        path = path.TrimStart('~', '/');
        return path;
    }

    private static string NormalizeRouteTemplate(string raw)
    {
        var path = raw.Trim().Trim('"', '\'', '`');
        if (!path.StartsWith('/') && !path.StartsWith('~') && !path.StartsWith('{'))
            path = "/" + path;
        return path.Replace("~/", "/");
    }

    private static bool HasObjectId(string path) =>
        path.Contains('{') || path.Contains(':') || ObjectIdRegex().IsMatch(path);

    private static string NextAppRouteToPath(string relative)
    {
        var idx = relative.IndexOf("/app/", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return "";
        var rest = relative[(idx + 5)..];
        if (rest.EndsWith("/route.ts", StringComparison.OrdinalIgnoreCase))
            rest = rest[..^"/route.ts".Length];
        else if (rest.EndsWith("/route.js", StringComparison.OrdinalIgnoreCase))
            rest = rest[..^"/route.js".Length];
        rest = rest.Replace("[", "{").Replace("]", "}");
        return string.IsNullOrWhiteSpace(rest) ? "/" : "/" + rest.Trim('/');
    }

    private static string PagesApiToPath(string relative)
    {
        var marker = "/pages/api/";
        var idx = relative.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return "";
        var rest = relative[(idx + marker.Length)..];
        rest = Path.ChangeExtension(rest, null)?.Replace('\\', '/') ?? rest;
        rest = rest.Replace("[", "{").Replace("]", "}");
        return "/api/" + rest.Trim('/');
    }

    private static string MaskRepo(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return "(unknown)";
        var sanitized = ScanSecretSanitizer.Sanitize(url);
        if (!Uri.TryCreate(sanitized, UriKind.Absolute, out var uri)) return "***";
        var host = uri.Host;
        if (host.StartsWith("github_pat_", StringComparison.OrdinalIgnoreCase)
            || host.StartsWith("ghp_", StringComparison.OrdinalIgnoreCase)
            || host.StartsWith("glpat-", StringComparison.OrdinalIgnoreCase))
            return "(invalid-repository-url)";
        var path = uri.AbsolutePath.TrimEnd('/');
        var leaf = path.Length == 0 ? "" : path[(path.LastIndexOf('/') + 1)..];
        return $"{uri.Scheme}://{host}/***/{leaf}";
    }

    private static long DirSize(string path, bool excludeSkipDirs)
    {
        long total = 0;
        try
        {
            var stack = new Stack<string>();
            stack.Push(path);
            while (stack.Count > 0)
            {
                var dir = stack.Pop();
                IEnumerable<string> subdirs;
                try { subdirs = Directory.EnumerateDirectories(dir); }
                catch { continue; }

                foreach (var sub in subdirs)
                {
                    if (excludeSkipDirs)
                    {
                        var name = Path.GetFileName(sub);
                        if (SkipDirNames.Contains(name, StringComparer.OrdinalIgnoreCase))
                            continue;
                    }
                    stack.Push(sub);
                }

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir); }
                catch { continue; }

                foreach (var file in files)
                {
                    try { total += new FileInfo(file).Length; }
                    catch { /* ignore */ }
                    if (total > MaxWorktreeBytes) return total;
                }
            }
        }
        catch { /* ignore */ }
        return total;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, true);
        }
        catch
        {
            // best effort
        }
    }

    private static int LineOf(string text, int index)
    {
        var line = 1;
        for (var i = 0; i < index && i < text.Length; i++)
            if (text[i] == '\n') line++;
        return line;
    }

    private static Dictionary<string, string> P(params (string Key, string Value)[] pairs)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in pairs)
            dict[key] = value;
        return dict;
    }

    private static ScanFindingDto Finding(
        string severity,
        string code,
        IReadOnlyDictionary<string, string> parameters,
        string? evidence) =>
        new(
            CheckDef.Id,
            CheckDef.Name,
            severity,
            code,
            code,
            evidence,
            "",
            CheckDef.Tools,
            null,
            code,
            parameters);

    // Matches [HttpGet], [HttpGet("x")], [HttpGet("{id:guid}")], etc.
    [GeneratedRegex(
        """\[Http(?<method>Get|Post|Put|Delete|Patch)(?:\(\s*"(?<path>[^"]*)"\s*\))?\]""",
        RegexOptions.IgnoreCase)]
    private static partial Regex CsHttpAttributeRegex();

    [GeneratedRegex("""\[Route\(\s*"(?<path>[^"]+)"\s*\)\]""", RegexOptions.IgnoreCase)]
    private static partial Regex CsRouteAttributeRegex();

    // Supports classic and C# primary-constructor declarations:
    //   class Foo : Bar
    //   class Foo(IMediator m) : Bar(m)
    [GeneratedRegex(
        """(?:public\s+|internal\s+|protected\s+|abstract\s+|sealed\s+|partial\s+|static\s+)*class\s+(?<name>\w+)\s*(?:\([^;{]*?\))?\s*(?::\s*(?<base>\w+))?""",
        RegexOptions.IgnoreCase)]
    private static partial Regex CsClassDeclRegex();

    [GeneratedRegex("""Map(?<method>Get|Post|Put|Delete|Patch)\(\s*"(?<path>[^"]+)" """, RegexOptions.IgnoreCase)]
    private static partial Regex CsMapRegex();

    [GeneratedRegex("""\.(?<method>get|post|put|delete|patch)\(\s*['"`](?<path>[^'"`]+)['"`]""", RegexOptions.IgnoreCase)]
    private static partial Regex ExpressRouteRegex();

    [GeneratedRegex("\"(?<path>/[^\"]+)\"\\s*:\\s*\\{", RegexOptions.IgnoreCase)]
    private static partial Regex OpenApiJsonPathRegex();

    [GeneratedRegex("""^\s{0,4}(?<path>/[A-Za-z0-9_{}\-./]+):\s*$""", RegexOptions.Multiline)]
    private static partial Regex OpenApiYamlPathRegex();

    [GeneratedRegex("""(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(""", RegexOptions.Multiline)]
    private static partial Regex GraphqlFieldRegex();

    [GeneratedRegex("""\{[^}]+\}|:[A-Za-z_][A-Za-z0-9_]*""", RegexOptions.IgnoreCase)]
    private static partial Regex ObjectIdRegex();

    [GeneratedRegex(
        """ClinicId|OrganizationId|OrgId|TenantId|HospitalId|EnsureSameOrg|EnsureOrg|BelongToOrg|CurrentClinic|RequireOrganization""",
        RegexOptions.IgnoreCase)]
    private static partial Regex TenantGuardRegex();

    [GeneratedRegex(
        """OwnerToken|MatchesOwnerToken|X-Scan-Token|EnsureAccess|AccessToken|scan owner|OwnerTokenHash""",
        RegexOptions.IgnoreCase)]
    private static partial Regex OwnerTokenGuardRegex();

    [GeneratedRegex("""\[AllowAnonymous\]""", RegexOptions.IgnoreCase)]
    private static partial Regex AllowAnonymousRegex();

    [GeneratedRegex("""\[Authorize(?:\([^\]]*\))?\]""", RegexOptions.IgnoreCase)]
    private static partial Regex AuthorizeRegex();
}
