using FluentAssertions;
using SecurityPortal.Domain.Security;
using Xunit;

namespace SecurityPortal.Domain.Tests.Scanning;

/// <summary>
/// ComposeAspNetRoute lives on the API analyzer; mirror the pure composition rules here
/// so Domain tests document the expected Security Portal self-scan paths.
/// </summary>
public class AspNetRouteComposeTests
{
    [Theory]
    [InlineData("api/v{version:apiVersion}/[controller]", "Scans", "build-info", "/api/v1/Scans/build-info")]
    [InlineData("api/v{version:apiVersion}/[controller]", "Scans", "catalog", "/api/v1/Scans/catalog")]
    [InlineData("api/v{version:apiVersion}/[controller]", "Scans", "", "/api/v1/Scans")]
    [InlineData("api/v{version:apiVersion}/[controller]", "Auth", "login", "/api/v1/Auth/login")]
    [InlineData("api/v{version:apiVersion}/[controller]", "Scans", "{id:guid}", "/api/v1/Scans/{id}")]
    public void Composes_security_portal_controller_routes(
        string classRoute, string controller, string action, string expected)
    {
        Compose(classRoute, controller, action).Should().Be(expected);
    }

    [Fact]
    public void Loopback_allow_flag_is_off_by_default()
    {
        var previous = Environment.GetEnvironmentVariable("SECURITYPORTAL_ALLOW_LOOPBACK_SCAN");
        try
        {
            Environment.SetEnvironmentVariable("SECURITYPORTAL_ALLOW_LOOPBACK_SCAN", null);
            ScanHostSafety.AllowLoopbackScan.Should().BeFalse();
        }
        finally
        {
            Environment.SetEnvironmentVariable("SECURITYPORTAL_ALLOW_LOOPBACK_SCAN", previous);
        }
    }

    // Keep in sync with SourceRouteInventoryAnalyzer.ComposeAspNetRoute
    private static string Compose(string? classRoute, string controllerName, string? actionPath)
    {
        var action = string.IsNullOrWhiteSpace(actionPath)
            ? ""
            : Normalize(actionPath).TrimStart('/');

        if (string.IsNullOrWhiteSpace(classRoute))
            return string.IsNullOrWhiteSpace(action) ? "/" + controllerName : Normalize(action);

        var template = classRoute.Trim().Trim('"');
        template = System.Text.RegularExpressions.Regex.Replace(
            template, @"\{version(?::[^}]*)?\}", "1", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        template = System.Text.RegularExpressions.Regex.Replace(
            template, @"\[controller\]", controllerName, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        template = template.Replace("//", "/", StringComparison.Ordinal).Trim('/');

        var combined = string.IsNullOrWhiteSpace(action) ? template : $"{template}/{action}";
        combined = System.Text.RegularExpressions.Regex.Replace(combined, @"\{([^}:]+)(?::[^}]*)?\}", "{$1}");
        return Normalize(combined);
    }

    private static string Normalize(string raw)
    {
        var path = raw.Trim().Trim('"', '\'', '`');
        if (!path.StartsWith('/') && !path.StartsWith('~') && !path.StartsWith('{'))
            path = "/" + path;
        return path.Replace("~/", "/");
    }
}
