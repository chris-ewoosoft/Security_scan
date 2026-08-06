using Asp.Versioning;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Prometheus;
using SecurityPortal.API;
using SecurityPortal.API.Middleware;
using SecurityPortal.API.Services;
using SecurityPortal.Application;
using SecurityPortal.Infrastructure;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// ─── Serilog ─────────────────────────────────────────────
builder.Host.UseSerilog((ctx, lc) => lc
    .ReadFrom.Configuration(ctx.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithThreadId()
    .WriteTo.Console()
    .WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day));

// ─── Application & Infrastructure ────────────────────────
builder.Services.AddApplication();
builder.Services.AddInfrastructure(builder.Configuration);

// ─── API Versioning ───────────────────────────────────────
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
}).AddApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});

// ─── Controllers ─────────────────────────────────────────
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// ─── Swagger ─────────────────────────────────────────────
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new() { Title = "Security Portal API", Version = "v1" });
    options.AddSecurityDefinition("Bearer", new()
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter your JWT token."
    });
    options.AddSecurityRequirement(new()
    {
        {
            new() { Reference = new() { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "Bearer" } },
            []
        }
    });
});

// ─── Authentication ───────────────────────────────────────
builder.Services.AddJwtAuthentication(builder.Configuration);

// ─── CORS ────────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
        policy.WithOrigins(builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? ["http://localhost:3000"])
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials());
});

// ─── SignalR ──────────────────────────────────────────────
builder.Services.AddSignalR();

// ─── Health Checks ────────────────────────────────────────
builder.Services.AddHealthChecks()
    .AddNpgSql(builder.Configuration.GetConnectionString("DefaultConnection")!, name: "postgres")
    .AddRedis(builder.Configuration.GetConnectionString("Redis")!, name: "redis");

// ─── HTTP Context ─────────────────────────────────────────
builder.Services.AddHttpContextAccessor();

builder.Services.AddHttpClient("WebsiteScanner", client =>
{
    client.Timeout = TimeSpan.FromSeconds(20);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("SecurityPortal-Scanner/1.0");
}).ConfigurePrimaryHttpMessageHandler(ScanHttpClientFactory.CreateHandler);

builder.Services.AddSingleton<SecurityPortal.API.Services.ScanCancellationRegistry>();
builder.Services.AddSingleton<SecurityPortal.Application.Common.Interfaces.IScanAbortSignal, SecurityPortal.API.Services.ScanAbortSignal>();
builder.Services.AddHostedService<SecurityPortal.API.Services.WebsiteScanProcessor>();

var buildStamp = Environment.GetEnvironmentVariable("SECURITYPORTAL_BUILD_STAMP") ?? "2026-08-06.4";
builder.Logging.AddFilter("SecurityPortal.API", LogLevel.Information);

var app = builder.Build();

app.Logger.LogInformation(
    "SecurityPortal.API starting buildStamp={BuildStamp} maxAutomaticRedirections={Redirects}",
    buildStamp,
    ScanHttpClientFactory.DefaultMaxAutomaticRedirections);

// Ensure schema exists (no migrations checked in yet)
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<SecurityPortal.Infrastructure.Persistence.ApplicationDbContext>();
    await db.Database.EnsureCreatedAsync();
    await db.Database.ExecuteSqlRawAsync("""
        CREATE TABLE IF NOT EXISTS website_scans (
            id uuid PRIMARY KEY,
            target_url varchar(2048) NOT NULL,
            normalized_host varchar(255) NOT NULL,
            status varchar(32) NOT NULL,
            created_by_user_id uuid NULL,
            organization_id uuid NULL,
            started_at timestamptz NULL,
            completed_at timestamptz NULL,
            error_message varchar(2000) NULL,
            summary varchar(4000) NULL,
            http_status_code int NULL,
            response_time_ms bigint NULL,
            has_https boolean NULL,
            server_header varchar(512) NULL,
            config_json text NOT NULL DEFAULT '{{}}',
            findings_json text NULL,
            report_type varchar(64) NOT NULL DEFAULT 'technical',
            created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL
        );
        ALTER TABLE website_scans ADD COLUMN IF NOT EXISTS config_json text;
        ALTER TABLE website_scans ADD COLUMN IF NOT EXISTS findings_json text NULL;
        ALTER TABLE website_scans ADD COLUMN IF NOT EXISTS report_type varchar(64);
        UPDATE website_scans SET config_json = '{{}}' WHERE config_json IS NULL;
        UPDATE website_scans SET report_type = 'technical' WHERE report_type IS NULL;
        CREATE INDEX IF NOT EXISTS ix_website_scans_status ON website_scans (status);
        CREATE INDEX IF NOT EXISTS ix_website_scans_host ON website_scans (normalized_host);
        CREATE INDEX IF NOT EXISTS ix_website_scans_created_at ON website_scans (created_at);
        """);
}

// ─── Middleware Pipeline ──────────────────────────────────
app.UseMiddleware<GlobalExceptionMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Security Portal API v1"));
}

app.UseSerilogRequestLogging();
app.UseHttpsRedirection();
app.UseRouting();
app.UseCors("AllowFrontend");
app.UseAuthentication();
app.UseAuthorization();
app.UseMetricServer();
app.UseHttpMetrics();
app.MapControllers();
app.MapHub<SecurityPortal.API.Hubs.ScanProgressHub>("/hubs/scan-progress");
app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new HealthCheckOptions { ResponseWriter = HealthChecks.UI.Client.UIResponseWriter.WriteHealthCheckUIResponse });

app.Run();

public partial class Program { }
