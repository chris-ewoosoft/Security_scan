using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace SecurityPortal.API.Services;

/// <summary>
/// Invokes optional external CLI tools when present on PATH; callers fall back to built-in probes.
/// </summary>
public static class ExternalToolRunner
{
    public sealed record ToolRunResult(bool Ran, string Tool, int ExitCode, string StdOut, string StdErr, string Summary);

    public static bool IsAvailable(string toolName)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = toolName,
                Arguments = GetVersionArgs(toolName),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return false;
            if (!p.WaitForExit(3000))
            {
                try { p.Kill(true); } catch { /* ignore */ }
                return false;
            }
            return p.ExitCode is 0 or 1 or 2; // many CLIs return non-zero for --version quirks
        }
        catch
        {
            return false;
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
                FileName = toolName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
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

    public static async Task<ToolRunResult?> TryNaabuAsync(string host, IEnumerable<int> ports, CancellationToken ct)
    {
        if (!IsAvailable("naabu")) return null;
        var portList = string.Join(",", ports);
        var args = $"-host {Quote(host)} -p {portList} -silent -json -rate 200";
        return await RunAsync("naabu", args, TimeSpan.FromSeconds(45), ct);
    }

    public static async Task<ToolRunResult?> TryNucleiAsync(string targetUrl, CancellationToken ct)
    {
        if (!IsAvailable("nuclei")) return null;
        // tags: exposure,misconfig,cve — keep runtime bounded
        var args = $"-u {Quote(targetUrl)} -silent -jsonl -severity medium,high,critical -c 25 -timeout 8 -retries 1";
        return await RunAsync("nuclei", args, TimeSpan.FromSeconds(90), ct);
    }

    public static async Task<ToolRunResult?> TryDnsxAsync(string host, CancellationToken ct)
    {
        if (!IsAvailable("dnsx")) return null;
        var args = $"-a -aaaa -resp -silent -l -";
        // dnsx reads hosts from stdin when -l -
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "dnsx",
                Arguments = "-a -aaaa -resp -silent",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
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

    public static async Task<ToolRunResult?> TryFeroxAsync(string targetUrl, CancellationToken ct)
    {
        if (!IsAvailable("feroxbuster")) return null;
        var args = $"-u {Quote(targetUrl)} -q -t 20 -d 1 --timeout 5 -n --json";
        return await RunAsync("feroxbuster", args, TimeSpan.FromSeconds(60), ct);
    }

    public static async Task<ToolRunResult?> TryFfufAsync(string targetUrl, CancellationToken ct)
    {
        if (!IsAvailable("ffuf")) return null;
        var wordlist = FindWordlist();
        if (wordlist is null) return null;
        var baseUrl = targetUrl.TrimEnd('/') + "/FUZZ";
        var args = $"-u {Quote(baseUrl)} -w {Quote(wordlist)} -mc 200,204,301,401,403 -t 20 -timeout 5 -s";
        return await RunAsync("ffuf", args, TimeSpan.FromSeconds(60), ct);
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
                // plain "host:port"
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
                    : root.TryGetProperty("status_code", out var sc) && sc.TryGetInt32(out var code2) ? code2
                    : 0;
                if (!string.IsNullOrWhiteSpace(url) && status is >= 200 and < 500)
                    hits.Add(new DiscoveryHit(url!, status));
            }
            catch
            {
                // ignore non-json lines
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
            var url = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries)[0].Trim();
            if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) continue;
            var status = 200;
            var m = System.Text.RegularExpressions.Regex.Match(line, @"Status:\s*(\d{3})",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success && int.TryParse(m.Groups[1].Value, out var code)) status = code;
            hits.Add(new DiscoveryHit(url, status));
        }
        return hits
            .GroupBy(h => h.Url, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Take(80)
            .ToList();
    }

    private static string? FindWordlist()
    {
        var candidates = new[]
        {
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            Path.Combine(AppContext.BaseDirectory, "wordlists", "common.txt"),
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private static string Quote(string value) =>
        "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "…";
}
