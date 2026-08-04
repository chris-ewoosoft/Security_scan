using SecurityPortal.Application.Common.Interfaces;

namespace SecurityPortal.API.Services;

public sealed class ScanAbortSignal(ScanCancellationRegistry registry) : IScanAbortSignal
{
    public void Abort(Guid scanId) => registry.RequestCancel(scanId);
}
