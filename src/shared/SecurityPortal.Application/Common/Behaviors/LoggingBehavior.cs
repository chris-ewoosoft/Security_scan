using System.Reflection;
using MediatR;
using Microsoft.Extensions.Logging;

namespace SecurityPortal.Application.Common.Behaviors;

public sealed class LoggingBehavior<TRequest, TResponse>(
    ILogger<LoggingBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    private static readonly HashSet<string> SensitiveNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "passwordcipher", "token", "accesstoken", "refreshtoken", "secret", "apikey"
    };

    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        var requestName = typeof(TRequest).Name;
        if (ContainsSensitiveData(request))
            logger.LogInformation("Handling {RequestName} (sensitive fields redacted)", requestName);
        else
            logger.LogInformation("Handling {RequestName}: {@Request}", requestName, request);

        var response = await next();

        logger.LogInformation("Handled {RequestName} successfully", requestName);
        return response;
    }

    private static bool ContainsSensitiveData(object value, int depth = 0)
    {
        if (value is null || depth > 4) return false;

        var type = value.GetType();
        if (type.IsPrimitive || value is string or decimal or Guid or DateTime or DateTimeOffset)
            return false;

        foreach (var prop in type.GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            if (!prop.CanRead || prop.GetIndexParameters().Length > 0) continue;
            if (SensitiveNames.Contains(prop.Name))
                return true;

            object? child;
            try { child = prop.GetValue(value); }
            catch { continue; }

            if (child is not null && !child.GetType().IsPrimitive && child is not string
                && ContainsSensitiveData(child, depth + 1))
                return true;
        }

        return false;
    }
}
