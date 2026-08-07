using System.Net;
using System.Net.Sockets;
using SecurityPortal.Domain.Common.Exceptions;

namespace SecurityPortal.Domain.Security;

/// <summary>
/// Blocks SSRF to loopback, private, link-local, and cloud metadata endpoints.
/// Optional allowlist via ScanTarget:AllowedCidrs / hosts (configured at call site).
/// </summary>
public static class ScanHostSafety
{
    private static readonly HashSet<string> BlockedHostNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost",
        "metadata.google.internal",
        "metadata",
        "instance-data",
    };

    public static void EnsureSafeHttpTarget(string? url, string fieldName = "URL")
    {
        if (string.IsNullOrWhiteSpace(url))
            throw new DomainException($"{fieldName} is required.");

        var input = url.Trim();
        if (!input.Contains("://", StringComparison.Ordinal))
            input = "https://" + input;

        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new DomainException($"{fieldName} must be a valid http:// or https:// address.");
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
            throw new DomainException($"{fieldName} must not include username/password in the URL.");

        EnsureSafeHost(uri.Host, fieldName);
    }

    /// <summary>
    /// Opt-in for lab/self-scan against local API (e.g. http://127.0.0.1:5088).
    /// Set SECURITYPORTAL_ALLOW_LOOPBACK_SCAN=1 — never enable on internet-facing workers.
    /// </summary>
    public static bool AllowLoopbackScan =>
        string.Equals(
            Environment.GetEnvironmentVariable("SECURITYPORTAL_ALLOW_LOOPBACK_SCAN"),
            "1",
            StringComparison.Ordinal);

    public static void EnsureSafeHost(string host, string fieldName = "Host")
    {
        if (string.IsNullOrWhiteSpace(host))
            throw new DomainException($"{fieldName} is required.");

        var h = host.Trim().TrimEnd('.');
        if (BlockedHostNames.Contains(h) || h.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            if (AllowLoopbackScan && (h.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                                      || h.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)))
                return;
            throw new DomainException($"{fieldName} '{host}' is blocked (loopback/metadata).");
        }

        if (IPAddress.TryParse(h, out var ip))
        {
            if (IsBlockedIp(ip))
            {
                if (AllowLoopbackScan && IPAddress.IsLoopback(ip))
                    return;
                throw new DomainException($"{fieldName} '{host}' resolves to a blocked private/loopback/link-local address.");
            }
            return;
        }

        // Resolve and reject if any A/AAAA is blocked (basic DNS rebinding mitigation at start time).
        try
        {
            var addresses = Dns.GetHostAddresses(h);
            if (addresses.Length == 0)
                throw new DomainException($"{fieldName} '{host}' could not be resolved.");
            foreach (var addr in addresses)
            {
                if (IsBlockedIp(addr))
                {
                    if (AllowLoopbackScan && IPAddress.IsLoopback(addr))
                        continue;
                    throw new DomainException(
                        $"{fieldName} '{host}' resolves to blocked address {addr} (private/loopback/metadata).");
                }
            }
        }
        catch (DomainException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new DomainException($"{fieldName} '{host}' DNS resolution failed: {ex.Message}");
        }
    }

    public static bool IsBlockedIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            // 0.0.0.0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, 100.64/10 (CGNAT)
            if (b[0] == 0) return true;
            if (b[0] == 10) return true;
            if (b[0] == 127) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
            // 198.18.0.0/15 benchmark
            if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return true;
            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return true;
            var bytes = ip.GetAddressBytes();
            // Unique local fc00::/7
            if ((bytes[0] & 0xfe) == 0xfc) return true;
            // IPv4-mapped
            if (ip.IsIPv4MappedToIPv6)
                return IsBlockedIp(ip.MapToIPv4());
        }

        return false;
    }

    /// <summary>Validate redirect Location stays off blocked hosts.</summary>
    public static bool IsSafeRedirectTarget(Uri? location)
    {
        if (location is null) return false;
        if (location.Scheme != Uri.UriSchemeHttp && location.Scheme != Uri.UriSchemeHttps) return false;
        try
        {
            EnsureSafeHost(location.Host, "Redirect");
            return true;
        }
        catch
        {
            return false;
        }
    }
}
