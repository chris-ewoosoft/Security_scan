using SecurityPortal.Domain.Common;
using SecurityPortal.Domain.Common.Exceptions;

namespace SecurityPortal.Domain.Entities;

public class Organization : AggregateRoot
{
    public string Name { get; private set; } = string.Empty;
    public string Slug { get; private set; } = string.Empty;
    public string? Description { get; private set; }
    public bool IsActive { get; private set; } = true;

    private Organization() { }

    public static Organization Create(string name, string? description = null)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new DomainException("Organization name is required.");

        return new Organization
        {
            Name = name,
            Slug = GenerateSlug(name),
            Description = description
        };
    }

    private static string GenerateSlug(string name) =>
        System.Text.RegularExpressions.Regex.Replace(name.ToLowerInvariant(), @"[^a-z0-9]+", "-").Trim('-');
}
