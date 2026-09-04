using FluentValidation;
using SecurityPortal.Application.Features.ServerScans.DTOs;

namespace SecurityPortal.Application.Features.ServerScans.Validators;

public sealed class SshContainmentRequestValidator : AbstractValidator<SshContainmentRequest>
{
    public SshContainmentRequestValidator()
    {
        RuleFor(x => x.Host).NotEmpty().MaximumLength(255);
        RuleFor(x => x.Port).InclusiveBetween(1, 65535);
        RuleFor(x => x.Username).NotEmpty().MaximumLength(255);
        RuleFor(x => x.AuthType)
            .Must(x => x.Equals("password", StringComparison.OrdinalIgnoreCase)
                       || x.Equals("privatekey", StringComparison.OrdinalIgnoreCase))
            .WithMessage("AuthType must be password or privatekey.");
        RuleFor(x => x.Destinations).NotEmpty().Must(x => x.Count <= 32)
            .WithMessage("At most 32 destinations may be contained at once.");
        RuleForEach(x => x.Destinations).NotEmpty().MaximumLength(255);
        RuleFor(x => x).Must(x => !x.AuthType.Equals("privatekey", StringComparison.OrdinalIgnoreCase)
                                  ? !string.IsNullOrWhiteSpace(x.Password)
                                  : !string.IsNullOrWhiteSpace(x.PrivateKey))
            .WithMessage("The selected SSH credential is required.");
    }
}