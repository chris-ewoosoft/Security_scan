using Microsoft.EntityFrameworkCore;
using SecurityPortal.Application.Common.Interfaces;
using SecurityPortal.Domain.Entities;
using SecurityPortal.Infrastructure.Persistence;
using SecurityPortal.Infrastructure.Persistence.Repositories;

namespace SecurityPortal.Infrastructure.Repositories;

public class UserRepository(ApplicationDbContext context)
    : BaseRepository<User>(context), IUserRepository
{
    public async Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default) =>
        await DbSet.FirstOrDefaultAsync(u => u.Email == email.ToLowerInvariant(), cancellationToken);

    public async Task<User?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default) =>
        await DbSet.FirstOrDefaultAsync(u => u.Username == username.ToLowerInvariant(), cancellationToken);

    public async Task<User?> GetWithRolesAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await DbSet
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
                    .ThenInclude(r => r!.RolePermissions)
                        .ThenInclude(rp => rp.Permission)
            .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);

    public async Task<bool> EmailExistsAsync(string email, CancellationToken cancellationToken = default) =>
        await DbSet.AnyAsync(u => u.Email == email.ToLowerInvariant(), cancellationToken);

    public async Task<bool> UsernameExistsAsync(string username, CancellationToken cancellationToken = default) =>
        await DbSet.AnyAsync(u => u.Username == username.ToLowerInvariant(), cancellationToken);

    public async Task<IEnumerable<string>> GetPermissionsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await context.Set<UserRole>()
            .Where(ur => ur.UserId == userId)
            .SelectMany(ur => ur.Role!.RolePermissions)
            .Select(rp => rp.Permission!.Name)
            .Distinct()
            .ToListAsync(cancellationToken);
    }
}

public class RefreshTokenRepository(ApplicationDbContext context)
    : BaseRepository<RefreshToken>(context), IRefreshTokenRepository
{
    public async Task<RefreshToken?> GetByTokenAsync(string token, CancellationToken cancellationToken = default) =>
        await DbSet.FirstOrDefaultAsync(rt => rt.Token == token, cancellationToken);

    public async Task RevokeAllUserTokensAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var tokens = await DbSet
            .Where(rt => rt.UserId == userId && !rt.IsRevoked)
            .ToListAsync(cancellationToken);

        foreach (var token in tokens) token.Revoke();
    }
}

public class RoleRepository(ApplicationDbContext context)
    : BaseRepository<Role>(context), IRoleRepository
{
    public async Task<Role?> GetByNameAsync(string name, CancellationToken cancellationToken = default) =>
        await DbSet.FirstOrDefaultAsync(r => r.Name == name, cancellationToken);

    public async Task<Role?> GetWithPermissionsAsync(Guid roleId, CancellationToken cancellationToken = default) =>
        await DbSet
            .Include(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission)
            .FirstOrDefaultAsync(r => r.Id == roleId, cancellationToken);
}
