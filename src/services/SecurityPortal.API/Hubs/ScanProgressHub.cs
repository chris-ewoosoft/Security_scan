using Microsoft.AspNetCore.SignalR;

namespace SecurityPortal.API.Hubs;

public sealed class ScanProgressHub : Hub
{
    public async Task JoinProject(string projectId) =>
        await Groups.AddToGroupAsync(Context.ConnectionId, $"project-{projectId}");

    public async Task LeaveProject(string projectId) =>
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"project-{projectId}");
}
