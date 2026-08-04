using System.Net;
using System.Text.Json;
using FluentValidation;
using SecurityPortal.Application.Common.Exceptions;
using SecurityPortal.Domain.Common.Exceptions;
using ValidationException = SecurityPortal.Application.Common.Exceptions.ValidationException;

namespace SecurityPortal.API.Middleware;

public sealed class GlobalExceptionMiddleware(RequestDelegate next, ILogger<GlobalExceptionMiddleware> logger)
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unhandled exception for {Path}", context.Request.Path);
            await HandleExceptionAsync(context, ex);
        }
    }

    private static Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.ContentType = "application/json";

        var (statusCode, response) = exception switch
        {
            ValidationException ve => (HttpStatusCode.UnprocessableEntity, new ErrorResponse(
                "Validation Failed", ve.Message, ve.Errors)),

            NotFoundException nfe => (HttpStatusCode.NotFound, new ErrorResponse(
                "Not Found", nfe.Message)),

            ForbiddenAccessException => (HttpStatusCode.Forbidden, new ErrorResponse(
                "Forbidden", "You do not have permission to perform this action.")),

            UnauthorizedAccessException => (HttpStatusCode.Unauthorized, new ErrorResponse(
                "Unauthorized", "Authentication is required.")),

            DomainException de => (HttpStatusCode.BadRequest, new ErrorResponse(
                "Business Rule Violation", de.Message)),

            _ => (HttpStatusCode.InternalServerError, new ErrorResponse(
                "Internal Server Error", "An unexpected error occurred."))
        };

        context.Response.StatusCode = (int)statusCode;
        return context.Response.WriteAsync(JsonSerializer.Serialize(response, JsonOptions));
    }
}

public record ErrorResponse(string Title, string Detail, IDictionary<string, string[]>? Errors = null)
{
    public string TraceId { get; init; } = Guid.NewGuid().ToString();
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
}
