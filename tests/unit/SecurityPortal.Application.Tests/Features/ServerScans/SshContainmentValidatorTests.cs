using FluentAssertions;
using SecurityPortal.Application.Features.ServerScans.DTOs;
using SecurityPortal.Application.Features.ServerScans.Validators;
using Xunit;

namespace SecurityPortal.Application.Tests.Features.ServerScans;

public sealed class SshContainmentValidatorTests
{
    [Fact]
    public async Task Validate_RequiresCredentialForSelectedAuthType()
    {
        var request = new SshContainmentRequest("example.com", 22, "root", "password", null, null, null, ["203.0.113.10"]);
        var result = await new SshContainmentRequestValidator().ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(x => x.ErrorMessage == "The selected SSH credential is required.");
    }

    [Fact]
    public async Task Validate_RejectsMoreThan32Destinations()
    {
        var destinations = Enumerable.Range(1, 33).Select(x => $"203.0.113.{x % 255}").ToArray();
        var request = new SshContainmentRequest("example.com", 22, "root", "password", "secret", null, null, destinations);
        var result = await new SshContainmentRequestValidator().ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(x => x.ErrorMessage == "At most 32 destinations may be contained at once.");
    }
}