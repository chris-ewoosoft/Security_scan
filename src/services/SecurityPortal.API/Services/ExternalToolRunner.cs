using System.Diagnostics;
using System.Text;
using System.Text.Json;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.API.Services;

/// <summary>
/// Invokes optional external CLI tools when present on PATH or SCANNER_TOOLS_PATH;
/// callers fall back to built-in probes when binaries are missing.
/// </summary>
public static class ExternalToolRunner
{
    public sealed record ToolRunResult(bool Ran, string Tool, int ExitCode, string StdOut, string StdErr, string Summary);

    public static string? ToolsDirectory
    {
        get
        {
            var env = Environment.GetEnvironmentVariable("SCANNER_TOOLS_PATH");
            if (!string.IsNullOrWhiteSpace(env) && Directory.Exists(env))
                return Path.GetFullPath(env);
            var siblings = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "scanners", "bin"),
                Path.Combine(Directory.GetCurrentDirectory(), "tools", "scanners", "bin"),
                "/opt/scanners/bin",
                "/shared/bin",
            };
            return siblings.FirstOrDefault(Directory.Exists);
        }
    }

    public static string ResolveToolPath(string toolName)
    {
        var dir = ToolsDirectory;
        if (dir is not null)
        {
            foreach (var name in CandidateFileNames(toolName))
            {
                var full = Path.Combine(dir, name);
                if (File.Exists(full))
                    return full;
            }
        }
        return toolName; // rely on PATH
    }

    private static IEnumerable<string> CandidateFileNames(string toolName)
    {
        yield return toolName;
        yield return toolName + ".exe";
        if (OperatingSystem.IsWindows())
            yield return toolName + ".cmd";
    }

    public static bool IsAvailable(string toolName)
    {
        try
        {
            var fileName = ResolveToolPath(toolName);
            // Built-in catalog tools are always "available".
            if (!fileName.Contains(Path.DirectorySeparatorChar) && !fileName.Contains(Path.AltDirectorySeparatorChar)
                && !fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                && toolName.Equals(fileName, StringComparison.OrdinalIgnoreCase)
                && ScanCatalog.Tools.Any(t =>
                    t.Id.Equals(toolName, StringComparison.OrdinalIgnoreCase)
                    && t.Kind.Equals("Built-in", StringComparison.OrdinalIgnoreCase)))
                return true;

            if (fileName.Contains(Path.DirectorySeparatorChar) || fileName.Contains(Path.AltDirectorySeparatorChar))
            {
                if (!File.Exists(fileName))
                    return false;
            }

            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = GetVersionArgs(toolName),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            ApplyToolEnvironment(psi);
            using var p = Process.Start(psi);
            if (p is null) return false;
            // Drain pipes to avoid rare deadlocks when banners fill the buffer.
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(8000))
            {
                try { p.Kill(true); } catch { /* ignore */ }
                // Binary exists — treat as available; version probe may hang on first run.
                return File.Exists(fileName);
            }
            _ = stdoutTask.GetAwaiter().GetResult();
            _ = stderrTask.GetAwaiter().GetResult();
            if (p.ExitCode is 0 or 1 or 2)
                return true;
            // Some CLIs return non-zero for -h/-version but are still runnable.
            return File.Exists(fileName);
        }
        catch
        {
            try
            {
                var path = ResolveToolPath(toolName);
                return path.Contains(Path.DirectorySeparatorChar) && File.Exists(path);
            }
            catch
            {
                return false;
            }
        }
    }

    public static object DescribeAvailability()
    {
        var tools = ScanCatalog.Tools.Select(t =>
        {
            var isExternal = t.Kind.Equals("External", StringComparison.OrdinalIgnoreCase);
            var available = !isExternal || IsAvailable(t.Id);
            return new
            {
                id = t.Id,
                name = t.Name,
                kind = t.Kind,
                available,
                resolvedPath = isExternal ? ResolveToolPath(t.Id) : null
            };
        }).ToList();

        return new
        {
            toolsPath = ToolsDirectory,
            tools,
            readyExternal = tools.Count(x => x.kind == "External" && x.available),
            missingExternal = tools.Count(x => x.kind == "External" && !x.available),
            installHint = "bash scripts/install-scanners.sh  OR  docker compose up -d --build scanners"
        };
    }

    private static void ApplyToolEnvironment(ProcessStartInfo psi)
    {
        var dir = ToolsDirectory;
        if (dir is null) return;
        var path = psi.Environment["PATH"] ?? Environment.GetEnvironmentVariable("PATH") ?? "";
        if (!path.Split(Path.PathSeparator).Contains(dir, StringComparer.OrdinalIgnoreCase))
            psi.Environment["PATH"] = dir + Path.PathSeparator + path;

        var pylib = Path.GetFullPath(Path.Combine(dir, "..", "pylib"));
        if (Directory.Exists(pylib))
        {
            var existing = psi.Environment.TryGetValue("PYTHONPATH", out var py) ? py : Environment.GetEnvironmentVariable("PYTHONPATH");
            psi.Environment["PYTHONPATH"] = string.IsNullOrWhiteSpace(existing) ? pylib : pylib + Path.PathSeparator + existing;
        }

        var templates = Environment.GetEnvironmentVariable("NUCLEI_TEMPLATES_PATH");
        if (string.IsNullOrWhiteSpace(templates))
        {
            var local = Path.GetFullPath(Path.Combine(dir, "..", "nuclei-templates"));
            if (Directory.Exists(local))
                psi.Environment["NUCLEI_TEMPLATES_PATH"] = local;
        }
    }

    private static string GetVersionArgs(string tool) => tool.ToLowerInvariant() switch
    {
        "naabu" => "-version",
        "nuclei" => "-version",
        "dnsx" => "-version",
        "wafw00f" => "-h",
        "feroxbuster" => "--version",
        "ffuf" => "-V",
        "gowitness" => "version",
        "whatweb" => "--version",
        "wappalyzer" => "--version",
        _ => "--version"
    };

    public static async Task<ToolRunResult> RunAsync(
        string toolName,
        string arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = ResolveToolPath(toolName),
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            ApplyToolEnvironment(psi);
            using var process = new Process { StartInfo = psi };
            if (!process.Start())
                return new ToolRunResult(false, toolName, -1, "", "failed to start", "not started");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeout);
            var stdoutTask = process.StandardOutput.ReadToEndAsync(cts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(cts.Token);
            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                try { process.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return new ToolRunResult(false, toolName, -1, "", "timeout", $"{toolName} timed out after {timeout.TotalSeconds:0}s");
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            var summary = Truncate(string.IsNullOrWhiteSpace(stdout) ? stderr : stdout, 800);
            return new ToolRunResult(true, toolName, process.ExitCode, stdout, stderr, summary);
        }
        catch (Exception ex)
        {
            return new ToolRunResult(false, toolName, -1, "", ex.Message, $"{toolName} unavailable: {ex.Message}");
        }
    }

    public static async Task<ToolRunResult?> TryNaabuAsync(
        string host, IEnumerable<int> ports, CancellationToken ct, NaabuToolOptions? options = null)
    {
        if (!IsAvailable("naabu")) return null;
        options ??= NaabuToolOptions.CreateDefault();
        options.Normalize();
        var portList = string.Join(",", ports);
        var args = $"-host {Quote(host)} -p {portList} -silent -json -rate {options.Rate}";
        return await RunAsync("naabu", args, TimeSpan.FromSeconds(45), ct);
    }

    public static async Task<ToolRunResult?> TryNucleiAsync(
        string targetUrl, CancellationToken ct, string? extraArgs = null, NucleiToolOptions? options = null)
    {
        if (!IsAvailable("nuclei")) return null;
        options ??= NucleiToolOptions.CreateDefault();
        options.Normalize();
        var templates = Environment.GetEnvironmentVariable("NUCLEI_TEMPLATES_PATH");
        var templateArg = !string.IsNullOrWhiteSpace(templates) && Directory.Exists(templates)
            ? $" -t {Quote(templates)}"
            : "";
        var tagsArg = string.IsNullOrWhiteSpace(options.Tags) ? "" : $" -tags {Quote(options.Tags)}";
        var extra = string.IsNullOrWhiteSpace(extraArgs) ? "" : " " + extraArgs.Trim();
        var args =
            $"-u {Quote(targetUrl)} -silent -jsonl -severity {options.Severity} -c {options.Concurrency} -rl {options.RateLimit} -timeout {options.TimeoutSeconds} -retries {options.Retries}{templateArg}{tagsArg}{extra}";
        return await RunAsync("nuclei", args, TimeSpan.FromSeconds(options.MaxDurationSeconds), ct);
    }

    public static async Task<ToolRunResult?> TryNucleiExposuresAsync(
        string targetUrl, CancellationToken ct, NucleiToolOptions? options = null)
    {
        options ??= NucleiToolOptions.CreateDefault();
        options.Normalize();
        var exposure = new NucleiToolOptions
        {
            Profile = options.Profile,
            Severity = options.Severity,
            Tags = string.IsNullOrWhiteSpace(options.ExposureTags)
                ? "exposure,config,backup,token,key,file"
                : options.ExposureTags,
            ExposureTags = options.ExposureTags,
            Concurrency = options.Concurrency,
            RateLimit = options.RateLimit,
            TimeoutSeconds = options.TimeoutSeconds,
            Retries = options.Retries,
            MaxDurationSeconds = options.MaxDurationSeconds,
        };
        // Skip profile re-application of Tags; values already chosen.
        exposure.Normalize();
        return await TryNucleiAsync(targetUrl, ct, extraArgs: null, exposure);
    }

    public static async Task<ToolRunResult?> TryDnsxAsync(string host, CancellationToken ct)
    {
        if (!IsAvailable("dnsx")) return null;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = ResolveToolPath("dnsx"),
                Arguments = "-a -aaaa -resp -silent",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            ApplyToolEnvironment(psi);
            using var process = Process.Start(psi);
            if (process is null) return null;
            await process.StandardInput.WriteLineAsync(host);
            process.StandardInput.Close();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(20));
            var stdout = await process.StandardOutput.ReadToEndAsync(cts.Token);
            var stderr = await process.StandardError.ReadToEndAsync(cts.Token);
            await process.WaitForExitAsync(cts.Token);
            return new ToolRunResult(true, "dnsx", process.ExitCode, stdout, stderr, Truncate(stdout, 800));
        }
        catch (Exception ex)
        {
            return new ToolRunResult(false, "dnsx", -1, "", ex.Message, ex.Message);
        }
    }

    public static async Task<ToolRunResult?> TryWafw00fAsync(string targetUrl, CancellationToken ct)
    {
        if (!IsAvailable("wafw00f")) return null;
        return await RunAsync("wafw00f", $"-a {Quote(targetUrl)}", TimeSpan.FromSeconds(40), ct);
    }

    public static async Task<ToolRunResult?> TryWhatWebAsync(string targetUrl, CancellationToken ct)
    {
        if (!IsAvailable("whatweb")) return null;
        return await RunAsync("whatweb", $"--color=never --log-json=- {Quote(targetUrl)}", TimeSpan.FromSeconds(45), ct);
    }

    public static async Task<ToolRunResult?> TryFeroxAsync(
        string targetUrl, CancellationToken ct, FeroxToolOptions? options = null)
    {
        if (!IsAvailable("feroxbuster")) return null;
        options ??= FeroxToolOptions.CreateDefault();
        options.Normalize();
        var wordlist = FindWordlist();
        var wl = wordlist is null ? "" : $" -w {Quote(wordlist)}";
        var args = $"-u {Quote(targetUrl)} -q -t {options.Threads} -d {options.Depth} --timeout {options.TimeoutSeconds} -n --json{wl}";
        return await RunAsync("feroxbuster", args, TimeSpan.FromSeconds(options.MaxDurationSeconds), ct);
    }

    public static async Task<ToolRunResult?> TryFfufAsync(
        string targetUrl, CancellationToken ct, FfufToolOptions? options = null)
    {
        if (!IsAvailable("ffuf")) return null;
        options ??= FfufToolOptions.CreateDefault();
        options.Normalize();
        var wordlist = FindWordlist();
        if (wordlist is null) return null;
        var baseUrl = targetUrl.TrimEnd('/') + "/FUZZ";
        var args = $"-u {Quote(baseUrl)} -w {Quote(wordlist)} -mc {options.MatchCodes} -t {options.Threads} -timeout {options.TimeoutSeconds} -s";
        return await RunAsync("ffuf", args, TimeSpan.FromSeconds(options.MaxDurationSeconds), ct);
    }

    public static IReadOnlyList<string> ParseNaabuOpenPorts(string stdout)
    {
        var ports = new List<int>();
        foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                using var doc = JsonDocument.Parse(line);
                if (doc.RootElement.TryGetProperty("port", out var p) && p.TryGetInt32(out var port))
                    ports.Add(port);
            }
            catch
            {
                var idx = line.LastIndexOf(':');
                if (idx > 0 && int.TryParse(line[(idx + 1)..], out var port))
                    ports.Add(port);
            }
        }
        return ports.Distinct().OrderBy(x => x).Select(x => x.ToString()).ToList();
    }

    public static int CountNucleiFindings(string stdout)
    {
        var count = 0;
        foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (line.StartsWith('{')) count++;
        }
        return count;
    }

    public sealed record DiscoveryHit(string Url, int Status);

    public static IReadOnlyList<DiscoveryHit> ParseFeroxHits(string stdout)
    {
        var hits = new List<DiscoveryHit>();
        foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                var url = root.TryGetProperty("url", out var u) ? u.GetString()
                    : root.TryGetProperty("path", out var p) ? p.GetString()
                    : null;
                var status = root.TryGetProperty("status", out var s) && s.TryGetInt32(out var code) ? code
                    : 0;
                if (!string.IsNullOrWhiteSpace(url) && status > 0)
                    hits.Add(new DiscoveryHit(url!, status));
            }
            catch
            {
                // ignore non-json
            }
        }
        return hits
            .GroupBy(h => h.Url, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Take(80)
            .ToList();
    }

    public static IReadOnlyList<DiscoveryHit> ParseFfufHits(string stdout)
    {
        var hits = new List<DiscoveryHit>();
        foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            // ffuf -s: "URL [Status: 200, Size: ...]" or plain URL
            var statusMatch = System.Text.RegularExpressions.Regex.Match(line, @"Status:\s*(\d{3})");
            var url = line.Split(' ', 2)[0].Trim();
            if (url.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                && statusMatch.Success
                && int.TryParse(statusMatch.Groups[1].Value, out var code))
            {
                hits.Add(new DiscoveryHit(url, code));
            }
        }
        return hits.Take(80).ToList();
    }

    private static string? FindWordlist()
    {
        var dir = ToolsDirectory;
        var candidates = new List<string>();
        if (dir is not null)
        {
            candidates.Add(Path.Combine(dir, "common.txt"));
            candidates.Add(Path.GetFullPath(Path.Combine(dir, "..", "wordlists", "common.txt")));
        }
        candidates.AddRange(
        [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/opt/scanners/wordlists/common.txt",
            "/shared/wordlists/common.txt",
            Path.Combine(AppContext.BaseDirectory, "wordlists", "common.txt"),
        ]);
        return candidates.FirstOrDefault(File.Exists);
    }

    private static string Quote(string value)
    {
        // Prefer unquoted tokens when safe — ProcessStartInfo.Arguments quoting differs across OSes.
        if (value.Length > 0
            && value.All(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_' or '/' or ':' or ',' or '=' or '?' or '&' or '%' or '#' or '@'))
            return value;
        return "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "…";
}
