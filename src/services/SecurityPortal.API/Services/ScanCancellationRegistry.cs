using System.Collections.Concurrent;

namespace SecurityPortal.API.Services;

/// <summary>In-process cancel signals so running AnalyzeAsync can abort immediately.</summary>
public sealed class ScanCancellationRegistry
{
    private readonly ConcurrentDictionary<Guid, CancellationTokenSource> _tokens = new();

    public CancellationToken Register(Guid scanId)
    {
        var cts = new CancellationTokenSource();
        _tokens.AddOrUpdate(scanId, cts, (_, existing) =>
        {
            existing.Dispose();
            return cts;
        });
        return cts.Token;
    }

    public void RequestCancel(Guid scanId)
    {
        if (_tokens.TryGetValue(scanId, out var cts))
        {
            try { cts.Cancel(); }
            catch (ObjectDisposedException) { /* ignore */ }
        }
    }

    public void Unregister(Guid scanId)
    {
        if (_tokens.TryRemove(scanId, out var cts))
            cts.Dispose();
    }
}
