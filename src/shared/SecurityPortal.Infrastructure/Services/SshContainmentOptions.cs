namespace SecurityPortal.Infrastructure.Services;

public sealed class SshContainmentOptions
{
    public bool ApplyEnabled { get; set; }
    public bool AllowPrivateNetworks { get; set; }
    public string[] AllowedDestinations { get; set; } = [];
    public int RuleLifetimeMinutes { get; set; } = 30;
}
