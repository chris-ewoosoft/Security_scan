using FluentAssertions;
using SecurityPortal.Domain.Entities;
using SecurityPortal.Domain.Scanning;
using Xunit;

namespace SecurityPortal.Domain.Tests.Scanning;

public class PortScanAssessorTests
{
    [Fact]
    public void Accept_all_silent_ports_are_info_not_medium()
    {
        var tested = new[] { 22, 80, 443, 3306, 3389, 5432, 6379, 8080, 8443 };
        var banners = tested.ToDictionary(p => p, _ => (string?)null);

        var result = PortScanAssessor.Assess(
            "example.com", tested, tested, "naabu", banners);

        result.Code.Should().Be("port.accept_all");
        result.Severity.Should().Be("Info");
    }

    [Fact]
    public void Accept_all_still_applies_when_only_web_banner_exists()
    {
        var tested = new[] { 21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443 };
        var banners = tested.ToDictionary(p => p, _ => (string?)null);
        banners[80] = "HTTP/1.0 200 OK";

        var result = PortScanAssessor.Assess("example.com", tested, tested, "naabu", banners);

        result.Code.Should().Be("port.accept_all");
        result.Severity.Should().Be("Info");
    }

    [Fact]
    public void Verified_sensitive_banner_is_high()
    {
        var open = new[] { 443, 3306 };
        var banners = new Dictionary<int, string?>
        {
            [443] = "HTTP/1.1 200 OK",
            [3306] = "5.7.44-MySQL Community Server",
        };

        var result = PortScanAssessor.Assess("db.example.com", open, open, "naabu", banners);

        result.Code.Should().Be("port.sensitive_verified");
        result.Severity.Should().Be("High");
    }

    [Fact]
    public void Only_web_ports_are_info()
    {
        var open = new[] { 80, 443 };
        var banners = new Dictionary<int, string?>
        {
            [80] = "HTTP/1.0 200 OK",
            [443] = null,
        };

        var result = PortScanAssessor.Assess("web.example.com", open, open, "naabu", banners);

        result.Code.Should().Be("port.web_ok");
        result.Severity.Should().Be("Info");
    }

    [Fact]
    public void Deep_nuclei_defaults_prefer_completable_budget()
    {
        var opts = new NucleiToolOptions { Profile = "deep" };
        opts.Normalize();

        opts.MaxDurationSeconds.Should().Be(300);
        opts.Tags.Should().Be("cve,misconfig,default-login");
        opts.Severity.Should().Contain("low");
    }
}
