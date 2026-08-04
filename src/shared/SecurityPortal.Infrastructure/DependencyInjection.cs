using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Minio;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Infrastructure.Cache;
using SecurityPortal.Infrastructure.Persistence;
using SecurityPortal.Infrastructure.Persistence.Repositories;
using SecurityPortal.Infrastructure.Repositories;
using SecurityPortal.Infrastructure.Security;
using SecurityPortal.Infrastructure.Services;
using SecurityPortal.Infrastructure.Storage;

namespace SecurityPortal.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseNpgsql(
                configuration.GetConnectionString("DefaultConnection"),
                b => b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName)));

        services.AddScoped<IUnitOfWork, UnitOfWork>();

        // Auth repositories
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IRoleRepository, RoleRepository>();
        services.AddScoped<IWebsiteScanRepository, WebsiteScanRepository>();

        // Auth services
        services.AddSingleton<IJwtService, JwtService>();
        services.AddSingleton<IPasswordHasher, BcryptPasswordHasher>();
        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentUser, CurrentUserService>();

        services.AddStackExchangeRedisCache(options =>
            options.Configuration = configuration.GetConnectionString("Redis"));
        services.AddSingleton<ICacheService, RedisCacheService>();

        var minioConfig = configuration.GetSection("Minio");
        services.AddMinio(client =>
        {
            client.WithEndpoint(minioConfig["Endpoint"] ?? "localhost:9000")
                  .WithCredentials(
                      minioConfig["AccessKey"] ?? "minioadmin",
                      minioConfig["SecretKey"] ?? "minioadmin")
                  .WithSSL(bool.Parse(minioConfig["UseSSL"] ?? "false"))
                  .Build();
        });
        services.AddScoped<IFileStorage, MinioFileStorage>();

        return services;
    }
}
