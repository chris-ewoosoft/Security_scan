using System.Net;

namespace SecurityPortal.API.Services;

/// <summary>
/// Central factory for scan HttpClient handlers. Never set MaxAutomaticRedirections to 0 —
/// SocketsHttpHandler throws ArgumentOutOfRangeException ("value must be non-negative and non-zero").
/// </summary>
internal static class ScanHttpClientFactory
{
    internal const int DefaultMaxAutomaticRedirections = 50;

    internal static HttpClientHandler CreateHandler()
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseCookies = true,
            CookieContainer = new CookieContainer(),
            AutomaticDecompression = DecompressionMethods.All,
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
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
