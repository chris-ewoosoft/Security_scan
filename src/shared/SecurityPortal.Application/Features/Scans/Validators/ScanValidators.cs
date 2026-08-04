using FluentValidation;
using SecurityPortal.Application.Features.Scans.Commands;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Features.Scans.Validators;

public class StartWebsiteScanCommandValidator : AbstractValidator<StartWebsiteScanCommand>
{
    public StartWebsiteScanCommandValidator()
    {
        RuleFor(x => x.TargetUrl)
            .NotEmpty().WithMessage("Website address is required.")
            .MaximumLength(2048)
            .Must(BeValidWebsiteUrl).WithMessage("Enter a valid website address (e.g. https://example.com).");

        RuleForEach(x => x.Checks!)
            .Must(id => ScanCatalog.ValidCheckIds.Contains(id))
            .When(x => x.Checks is { Count: > 0 })
            .WithMessage("Unknown security check selected.");

        RuleForEach(x => x.Tools!)
            .Must(id => ScanCatalog.ValidToolIds.Contains(id))
            .When(x => x.Tools is { Count: > 0 })
            .WithMessage("Unknown tool selected.");

        RuleFor(x => x.ReportType!)
            .Must(id => ScanCatalog.ValidReportIds.Contains(id))
            .When(x => !string.IsNullOrWhiteSpace(x.ReportType))
            .WithMessage("Unknown report type selected.");
    }

    private static bool BeValidWebsiteUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var input = value.Trim();
        if (!input.Contains("://", StringComparison.Ordinal))
            input = "https://" + input;

        return Uri.TryCreate(input, UriKind.Absolute, out var uri)
               && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
               && !string.IsNullOrWhiteSpace(uri.Host);
    }
}
