using SecurityPortal.Application.Common.Interfaces;

namespace SecurityPortal.API.Services;

public sealed class ServerScanRawOutputCleanupService(
    IServiceScopeFactory scopeFactory,
    ILogger<ServerScanRawOutputCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var repository = scope.ServiceProvider.GetRequiredService<IServerScanRepository>();
                var deleted = await repository.PurgeExpiredRawOutputAsync(DateTime.UtcNow, stoppingToken);
                if (deleted > 0)
                    logger.LogInformation("Purged raw output from {Count} expired server scans", deleted);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to purge expired server scan raw output");
            }
        }
    }
}