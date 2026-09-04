using System.Text.Json;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Application.Features.ServerScans.DTOs;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Features.ServerScans;

public static class ServerScanMappings
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static string SerializeFindings(IReadOnlyList<ServerScanFinding> findings) =>
        JsonSerializer.Serialize(findings, JsonOptions);

    public static IReadOnlyList<ServerScanFindingDto> DeserializeFindings(string? findingsJson)
    {
        if (string.IsNullOrWhiteSpace(findingsJson))
            return [];

        var findings = JsonSerializer.Deserialize<List<ServerScanFinding>>(findingsJson, JsonOptions) ?? [];
        return findings.Select(f => new ServerScanFindingDto(
            f.Id,
            f.Name,
            f.Severity,
            f.Status,
            f.Detail,
            f.Category,
            f.Confidence,
            f.Recommendation,
            f.Analysis)).ToList();
    }

    public static ServerScanDto ToDto(ServerScan scan, string? accessToken = null) => new(
        scan.Id,
        scan.Host,
        scan.Port,
        scan.Username,
        scan.Status.ToString(),
        scan.Summary,
        scan.ErrorMessage,
        scan.StartedAt,
        scan.CompletedAt,
        scan.CreatedAt,
        DeserializeFindings(scan.FindingsJson),
        accessToken);
}
