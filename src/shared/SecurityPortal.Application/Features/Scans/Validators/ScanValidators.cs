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

        When(x => x.Auth is not null && !string.IsNullOrWhiteSpace(x.Auth.Type)
                  && !x.Auth.Type.Equals("none", StringComparison.OrdinalIgnoreCase), () =>
        {
            RuleFor(x => x.Auth!.Type!)
                .Must(t => t.Equals("form", StringComparison.OrdinalIgnoreCase)
                           || t.Equals("basic", StringComparison.OrdinalIgnoreCase)
                           || t.Equals("graphql", StringComparison.OrdinalIgnoreCase))
                .WithMessage("Auth type must be form, basic, or graphql.");

            RuleFor(x => x.Auth!.Username)
                .NotEmpty().WithMessage("Username is required for authenticated scans.")
                .MaximumLength(256);

            RuleFor(x => x.Auth!.Password)
                .NotEmpty().WithMessage("Password is required for authenticated scans.")
                .MaximumLength(512);

            RuleFor(x => x.Auth!.LoginUrl!)
                .MaximumLength(2048)
                .Must(BeValidWebsiteUrl)
                .When(x => !string.IsNullOrWhiteSpace(x.Auth!.LoginUrl))
                .WithMessage("Enter a valid login / GraphQL URL.");
        });

        When(x => x.Source is not null && !string.IsNullOrWhiteSpace(x.Source.RepositoryUrl), () =>
        {
            RuleFor(x => x.Source!.RepositoryUrl!)
                .MaximumLength(2048)
                .Must(BeValidWebsiteUrl)
                .WithMessage("Enter a valid https Git repository URL.");

            RuleFor(x => x.Source!.Branch!)
                .MaximumLength(200)
                .When(x => !string.IsNullOrWhiteSpace(x.Source!.Branch));

            RuleFor(x => x.Source!.Token!)
                .MaximumLength(2048)
                .When(x => !string.IsNullOrWhiteSpace(x.Source!.Token));
        });
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
