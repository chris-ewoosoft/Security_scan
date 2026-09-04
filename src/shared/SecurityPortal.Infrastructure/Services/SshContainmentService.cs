using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Options;
using Renci.SshNet;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.ServerScans.DTOs;

namespace SecurityPortal.Infrastructure.Services;

public sealed class SshContainmentService(IOptions<SshContainmentOptions> options) : ISshContainmentService
{
    private readonly SshContainmentOptions settings = options.Value;

    public async Task<SshContainmentPreviewDto> PreviewAsync(SshContainmentRequest request, CancellationToken cancellationToken = default)
    {
        var addresses = await ResolveAllowedAddressesAsync(request.Destinations, cancellationToken);
        var expiresAt = DateTime.UtcNow.AddMinutes(GetLifetime());
        return new(request.Host, addresses, BuildCommands(addresses, expiresAt, rollback: false), expiresAt, settings.ApplyEnabled);
    }

    public async Task<SshContainmentResultDto> ApplyAsync(SshContainmentRequest request, CancellationToken cancellationToken = default)
    {
        if (!settings.ApplyEnabled)
            throw new InvalidOperationException("SSH containment apply is disabled by configuration.");
        if (!request.Confirm)
            throw new InvalidOperationException("Explicit containment confirmation is required.");

        var preview = await PreviewAsync(request, cancellationToken);
        await ExecuteAsRootAsync(request, preview.Commands, cancellationToken);
        return new(request.Host, preview.ResolvedAddresses, preview.ExpiresAt, true,
            "Outbound nftables containment applied; rules expire automatically.");
    }

    public async Task<SshContainmentResultDto> RollbackAsync(SshContainmentRequest request, CancellationToken cancellationToken = default)
    {
        var addresses = await ResolveAllowedAddressesAsync(request.Destinations, cancellationToken);
        await ExecuteAsRootAsync(request, BuildCommands(addresses, DateTime.UtcNow, rollback: true), cancellationToken);
        return new(request.Host, addresses, DateTime.UtcNow, true, "Outbound nftables containment rules removed.");
    }

    private async Task<IReadOnlyList<string>> ResolveAllowedAddressesAsync(IEnumerable<string> destinations, CancellationToken cancellationToken)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var destination in destinations.Select(x => x.Trim()).Where(x => x.Length > 0))
        {
            cancellationToken.ThrowIfCancellationRequested();
            IPAddress[] resolved;
            if (IPAddress.TryParse(destination, out var address))
                resolved = [address];
            else
                resolved = await Dns.GetHostAddressesAsync(destination, cancellationToken);

            foreach (var candidate in resolved.Where(IsAllowedAddress))
                result.Add(candidate.ToString());
        }

        if (result.Count == 0)
            throw new InvalidOperationException("No public A or AAAA destination resolved; private/local addresses are excluded.");
        return result.OrderBy(x => x, StringComparer.Ordinal).ToArray();
    }

    private bool IsAllowedAddress(IPAddress address) =>
        (settings.AllowPrivateNetworks || !IsPrivateOrLocal(address)) &&
        (settings.AllowedDestinations.Length == 0 || settings.AllowedDestinations.Any(x => Matches(x, address)));

    private static bool IsPrivateOrLocal(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.IsIPv4MappedToIPv6)
            return true;
        var bytes = address.GetAddressBytes();
        return address.AddressFamily == AddressFamily.InterNetwork
            ? bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168) || bytes[0] == 169 && bytes[1] == 254
            : (bytes[0] & 0xfe) == 0xfc || (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80);
    }

    private static bool Matches(string configured, IPAddress address)
    {
        if (IPAddress.TryParse(configured, out var exact)) return exact.Equals(address);
        var parts = configured.Split('/', 2);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) || !int.TryParse(parts[1], out var prefix)) return false;
        var left = network.GetAddressBytes(); var right = address.GetAddressBytes();
        if (left.Length != right.Length || prefix < 0 || prefix > left.Length * 8) return false;
        for (var i = 0; i < left.Length && prefix > 0; i++) { var bits = Math.Min(prefix, 8); var mask = (byte)(0xff << (8 - bits)); if ((left[i] & mask) != (right[i] & mask)) return false; prefix -= bits; }
        return true;
    }

    private string[] BuildCommands(IReadOnlyList<string> addresses, DateTime expiresAt, bool rollback)
    {
        var v4 = addresses.Where(x => IPAddress.Parse(x).AddressFamily == AddressFamily.InterNetwork).ToArray();
        var v6 = addresses.Where(x => IPAddress.Parse(x).AddressFamily == AddressFamily.InterNetworkV6).ToArray();
        var commands = new List<string> { "id -u" };
        if (rollback)
        {
            if (v4.Length > 0) commands.Add($"nft delete element inet security_portal_containment blocked_ipv4 {{ {string.Join(", ", v4)} }} || true");
            if (v6.Length > 0) commands.Add($"nft delete element inet security_portal_containment blocked_ipv6 {{ {string.Join(", ", v6)} }} || true");
            return commands.ToArray();
        }
        var timeout = $"{GetLifetime()}m";
        commands.Add("nft add table inet security_portal_containment 2>/dev/null || true");
        commands.Add("nft add chain inet security_portal_containment output { type filter hook output priority 0; policy accept; } 2>/dev/null || true");
        if (v4.Length > 0) { commands.Add($"nft add set inet security_portal_containment blocked_ipv4 {{ type ipv4_addr; flags timeout; timeout {timeout}; }} 2>/dev/null || true"); commands.Add($"nft add element inet security_portal_containment blocked_ipv4 {{ {string.Join(", ", v4.Select(x => x + " timeout " + timeout))} }}"); commands.Add("nft add rule inet security_portal_containment output ip daddr @blocked_ipv4 drop"); }
        if (v6.Length > 0) { commands.Add($"nft add set inet security_portal_containment blocked_ipv6 {{ type ipv6_addr; flags timeout; timeout {timeout}; }} 2>/dev/null || true"); commands.Add($"nft add element inet security_portal_containment blocked_ipv6 {{ {string.Join(", ", v6.Select(x => x + " timeout " + timeout))} }}"); commands.Add("nft add rule inet security_portal_containment output ip6 daddr @blocked_ipv6 drop"); }
        commands.Add($"# expires {expiresAt:O}");
        return commands.ToArray();
    }

    private Task ExecuteAsRootAsync(SshContainmentRequest request, IReadOnlyList<string> commands, CancellationToken cancellationToken)
    {
        var secret = request.AuthType.Equals("privatekey", StringComparison.OrdinalIgnoreCase) ? request.PrivateKey : request.Password;
        if (string.IsNullOrWhiteSpace(secret)) throw new InvalidOperationException("SSH credential is required.");
        using var client = new SshClient(BuildConnection(request, secret));
        cancellationToken.ThrowIfCancellationRequested(); client.Connect();
        try
        {
            foreach (var command in commands)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var cmd = client.CreateCommand(command);
                cmd.CommandTimeout = TimeSpan.FromSeconds(15);
                var output = cmd.Execute();
                if (command == "id -u" && output.Trim() != "0")
                    throw new InvalidOperationException("SSH containment requires a root session (uid 0).");
                if (cmd.ExitStatus != 0)
                    throw new InvalidOperationException("Remote containment command failed.");
            }
        }
        finally { client.Disconnect(); }
        return Task.CompletedTask;
    }

    private static ConnectionInfo BuildConnection(SshContainmentRequest request, string secret)
    {
        if (request.AuthType.Equals("privatekey", StringComparison.OrdinalIgnoreCase))
        {
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(secret));
            var key = string.IsNullOrWhiteSpace(request.Passphrase) ? new PrivateKeyFile(stream) : new PrivateKeyFile(stream, request.Passphrase);
            return new ConnectionInfo(request.Host, request.Port, request.Username, new PrivateKeyAuthenticationMethod(request.Username, key));
        }
        return new ConnectionInfo(request.Host, request.Port, request.Username, new PasswordAuthenticationMethod(request.Username, secret));
    }

    private int GetLifetime() => settings.RuleLifetimeMinutes is > 0 and <= 30 ? settings.RuleLifetimeMinutes : 30;
}