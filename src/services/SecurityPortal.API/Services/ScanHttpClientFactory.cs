using System.Net;

namespace SecurityPortal.API.Services;

/// <summary>
/// Central factory for scan HttpClient handlers.
/// Never set MaxAutomaticRedirections to 0 — SocketsHttpHandler throws
/// ArgumentOutOfRangeException: value ('0') must be a non-negative and non-zero value.
/// For SSRF-safe scanning, set AllowAutoRedirect=false and follow redirects manually
/// via SendWithSafeRedirectsAsync; leave MaxAutomaticRedirections at the default (50).
/// </summary>
internal static class ScanHttpClientFactory
{
    internal const int DefaultMaxAutomaticRedirections = 50;

    /// <param name="allowAutoRedirect">
    /// False when redirects are followed manually with per-hop host safety checks.
    /// </param>
    internal static HttpClientHandler CreateHandler(bool allowAutoRedirect = false)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = allowAutoRedirect,
            UseCookies = true,
            CookieContainer = new CookieContainer(),
            AutomaticDecompression = DecompressionMethods.All,
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        // Intentionally do NOT assign MaxAutomaticRedirections=0 when AllowAutoRedirect is false.
        // The setter rejects 0 even if auto-redirect is disabled.
        handler.MaxAutomaticRedirections = DefaultMaxAutomaticRedirections;
        return handler;
    }

    internal static HttpClient CreateClient(HttpClientHandler? handler = null, bool disposeHandler = true)
    {
        handler ??= CreateHandler();
        var client = new HttpClient(handler, disposeHandler)
        {
            Timeout = TimeSpan.FromSeconds(20)
        };
        client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "SecurityPortal-Scanner/1.0");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        return client;
    }
}
