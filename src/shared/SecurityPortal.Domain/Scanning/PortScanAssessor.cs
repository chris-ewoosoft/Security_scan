namespace SecurityPortal.Domain.Scanning;

/// <summary>
/// Classifies open-port evidence so tarpit / accept-all firewalls do not inflate Medium findings.
/// </summary>
public static class PortScanAssessor
{
    public static readonly HashSet<int> SensitivePorts =
    [
        21, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017
    ];

    public static readonly HashSet<int> CommonWebPorts = [80, 443, 8080, 8443];

    public sealed record Assessment(
        string Severity,
        string Code,
        string Observed,
        string Impact,
        string Evidence);

    /// <summary>
    /// banners: port → optional short banner/service hint (null/empty = TCP accept only).
    /// </summary>
    public static Assessment Assess(
        string host,
        IReadOnlyList<int> openPorts,
        IReadOnlyList<int> testedPorts,
        string toolUsed,
        IReadOnlyDictionary<int, string?> banners)
    {
        var open = openPorts.Distinct().OrderBy(p => p).ToList();
        var tested = testedPorts.Distinct().OrderBy(p => p).ToList();
        var evidence =
            $"host={host}; open={string.Join(',', open)}; tool={toolUsed}; ports_tested={tested.Count}";

        if (open.Count == 0)
        {
            return new Assessment(
                "Info",
                "port.none",
                $"No TCP accept on tested ports for {host}.",
                "No additional port exposure detected on the tested set.",
                evidence);
        }

        var verified = open
            .Where(p => banners.TryGetValue(p, out var b) && !string.IsNullOrWhiteSpace(b))
            .ToList();
        var verifiedSensitive = verified.Where(SensitivePorts.Contains).ToList();
        var openSensitive = open.Where(SensitivePorts.Contains).ToList();

        // Accept-all / tarpit: nearly every probed port accepts TCP, and no sensitive
        // service was banner-verified (HTTP on 80/443 alone does not disprove tarpit).
        var acceptAll = tested.Count >= 5
                        && open.Count >= Math.Max(5, (int)Math.Ceiling(tested.Count * 0.8))
                        && verifiedSensitive.Count == 0;

        if (acceptAll)
        {
            var webBanners = verified.Where(CommonWebPorts.Contains).ToList();
            return new Assessment(
                "Info",
                "port.accept_all",
                $"TCP connect succeeded on {open.Count}/{tested.Count} probed ports ({string.Join(", ", open)}) without verified sensitive service banners — likely firewall/load-balancer accept-all or tarpit, not confirmed DB/RDP/SSH exposure.",
                "Treat as unverified noise until banner/service probes confirm real listeners. Do not assume databases or RDP are exposed.",
                evidence + $"; verified_sensitive=0; web_banners={webBanners.Count}; classification=accept_all");
        }

        if (verifiedSensitive.Count > 0)
        {
            var detail = string.Join(", ", verifiedSensitive.Select(p =>
                $"{p}({Truncate(banners[p]!, 40)})"));
            return new Assessment(
                "High",
                "port.sensitive_verified",
                $"Verified sensitive service banner(s) on {host}: {detail}.",
                "Management or database services appear reachable from the scanner network.",
                evidence + $"; verified_sensitive={string.Join(',', verifiedSensitive)}");
        }

        if (openSensitive.Count > 0 && verified.Count > 0)
        {
            // Some banners elsewhere, sensitive ports open but silent — keep Medium cautiously.
            return new Assessment(
                "Medium",
                "port.open",
                $"TCP open on {string.Join(", ", open)} including sensitive port(s) {string.Join(", ", openSensitive)} (tool={toolUsed}). Partial banners: {FormatBanners(banners, verified)}.",
                $"Sensitive management or database ports may be exposed: {string.Join(", ", openSensitive)}.",
                evidence + $"; sensitive={string.Join(',', openSensitive)}");
        }

        if (openSensitive.Count > 0)
        {
            // Sensitive ports open, no banners at all, but not accept-all pattern.
            return new Assessment(
                "Low",
                "port.sensitive_unverified",
                $"TCP connect succeeded to sensitive port(s) {string.Join(", ", openSensitive)} on {host}, but no service banner was read.",
                "Confirm with an authenticated network scan; silent accepts are often filtered or tarpitted.",
                evidence + $"; sensitive={string.Join(',', openSensitive)}; verified=0");
        }

        var onlyWeb = open.All(CommonWebPorts.Contains);
        if (onlyWeb)
        {
            return new Assessment(
                "Info",
                "port.web_ok",
                $"Only common web ports responded on {host}: {string.Join(", ", open)}.",
                "Expected for an HTTP(S) site; no extra management ports confirmed.",
                evidence);
        }

        return new Assessment(
            "Low",
            "port.open",
            $"TCP connections succeeded to {host} on {string.Join(", ", open)} (tool={toolUsed}).",
            "Open ports increase the attack surface; verify each listener is required.",
            evidence + (verified.Count > 0 ? $"; banners={FormatBanners(banners, verified)}" : ""));
    }

    private static string FormatBanners(IReadOnlyDictionary<int, string?> banners, IEnumerable<int> ports) =>
        string.Join(", ", ports.Select(p => $"{p}:{Truncate(banners[p] ?? "", 32)}"));

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "…";
}
