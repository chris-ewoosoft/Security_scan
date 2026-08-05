using System.Text.RegularExpressions;

namespace SecurityPortal.API.Services;

/// <summary>Strip credentials / PATs from user-visible scan errors and findings.</summary>
public static partial class ScanSecretSanitizer
{
    public static string Sanitize(string? text, params string?[] knownSecrets)
    {
        if (string.IsNullOrEmpty(text))
            return text ?? string.Empty;

        var result = text;

        foreach (var secret in knownSecrets)
        {
            if (string.IsNullOrEmpty(secret) || secret.Length < 4)
                continue;
            result = result.Replace(secret, "***", StringComparison.Ordinal);
            // UriBuilder / git may percent-encode parts of the secret.
            var encoded = Uri.EscapeDataString(secret);
            if (!encoded.Equals(secret, StringComparison.Ordinal))
                result = result.Replace(encoded, "***", StringComparison.Ordinal);
        }

        // https://user:password@host → strip userinfo
        result = UrlUserInfoRegex().Replace(result, "$1://***:***@");

        // Common Git forge tokens (pattern-based; do not rely on exact match only)
        result = GithubPatRegex().Replace(result, "github_pat_***");
        result = GithubClassicRegex().Replace(result, "***");
        result = GitlabPatRegex().Replace(result, "glpat-***");
        result = BasicAuthHeaderRegex().Replace(result, "AUTHORIZATION: basic ***");

        return result;
    }

    [GeneratedRegex(@"(https?)://[^/\s'""]+?:[^/\s'""]+?@", RegexOptions.IgnoreCase)]
    private static partial Regex UrlUserInfoRegex();

    [GeneratedRegex(@"github_pat_[A-Za-z0-9_]{20,}", RegexOptions.IgnoreCase)]
    private static partial Regex GithubPatRegex();

    [GeneratedRegex(@"\bgh[pousr]_[A-Za-z0-9]{20,}\b", RegexOptions.IgnoreCase)]
    private static partial Regex GithubClassicRegex();

    [GeneratedRegex(@"\bglpat-[A-Za-z0-9\-_]{20,}\b", RegexOptions.IgnoreCase)]
    private static partial Regex GitlabPatRegex();

    [GeneratedRegex(@"AUTHORIZATION:\s*basic\s+[A-Za-z0-9+/=]+", RegexOptions.IgnoreCase)]
    private static partial Regex BasicAuthHeaderRegex();
}
