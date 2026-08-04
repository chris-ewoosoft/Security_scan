using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Infrastructure.Persistence.Configurations;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users");
        builder.HasKey(u => u.Id);
        builder.Property(u => u.Id).HasColumnName("id");
        builder.Property(u => u.OrganizationId).HasColumnName("organization_id").IsRequired();
        builder.Property(u => u.Email).HasColumnName("email").HasMaxLength(256).IsRequired();
        builder.Property(u => u.Username).HasColumnName("username").HasMaxLength(100).IsRequired();
        builder.Property(u => u.PasswordHash).HasColumnName("password_hash").HasMaxLength(512).IsRequired();
        builder.Property(u => u.FirstName).HasColumnName("first_name").HasMaxLength(100).IsRequired();
        builder.Property(u => u.LastName).HasColumnName("last_name").HasMaxLength(100).IsRequired();
        builder.Property(u => u.AvatarUrl).HasColumnName("avatar_url").HasMaxLength(512);
        builder.Property(u => u.IsActive).HasColumnName("is_active").HasDefaultValue(true);
        builder.Property(u => u.EmailVerified).HasColumnName("email_verified").HasDefaultValue(false);
        builder.Property(u => u.LastLoginAt).HasColumnName("last_login_at");
        builder.Property(u => u.CreatedAt).HasColumnName("created_at");
        builder.Property(u => u.UpdatedAt).HasColumnName("updated_at");

        builder.HasIndex(u => u.Email).IsUnique().HasDatabaseName("ix_users_email");
        builder.HasIndex(u => u.Username).IsUnique().HasDatabaseName("ix_users_username");
        builder.HasIndex(u => u.OrganizationId).HasDatabaseName("ix_users_organization_id");

        builder.HasMany(u => u.UserRoles)
            .WithOne()
            .HasForeignKey(ur => ur.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.Ignore(u => u.DomainEvents);
    }
}

public class RoleConfiguration : IEntityTypeConfiguration<Role>
{
    public void Configure(EntityTypeBuilder<Role> builder)
    {
        builder.ToTable("roles");
        builder.HasKey(r => r.Id);
        builder.Property(r => r.Id).HasColumnName("id");
        builder.Property(r => r.Name).HasColumnName("name").HasMaxLength(100).IsRequired();
        builder.Property(r => r.Description).HasColumnName("description").HasMaxLength(500);
        builder.Property(r => r.IsSystem).HasColumnName("is_system").HasDefaultValue(false);
        builder.Property(r => r.CreatedAt).HasColumnName("created_at");
        builder.Property(r => r.UpdatedAt).HasColumnName("updated_at");

        builder.HasIndex(r => r.Name).IsUnique().HasDatabaseName("ix_roles_name");

        builder.HasMany(r => r.RolePermissions)
            .WithOne()
            .HasForeignKey(rp => rp.RoleId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

public class PermissionConfiguration : IEntityTypeConfiguration<Permission>
{
    public void Configure(EntityTypeBuilder<Permission> builder)
    {
        builder.ToTable("permissions");
        builder.HasKey(p => p.Id);
        builder.Property(p => p.Id).HasColumnName("id");
        builder.Property(p => p.Name).HasColumnName("name").HasMaxLength(200).IsRequired();
        builder.Property(p => p.Resource).HasColumnName("resource").HasMaxLength(100).IsRequired();
        builder.Property(p => p.Action).HasColumnName("action").HasMaxLength(100).IsRequired();
        builder.Property(p => p.CreatedAt).HasColumnName("created_at");
        builder.Property(p => p.UpdatedAt).HasColumnName("updated_at");

        builder.HasIndex(p => p.Name).IsUnique().HasDatabaseName("ix_permissions_name");
    }
}

public class UserRoleConfiguration : IEntityTypeConfiguration<UserRole>
{
    public void Configure(EntityTypeBuilder<UserRole> builder)
    {
        builder.ToTable("user_roles");
        builder.HasKey(ur => ur.Id);
        builder.Property(ur => ur.Id).HasColumnName("id");
        builder.Property(ur => ur.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(ur => ur.RoleId).HasColumnName("role_id").IsRequired();
        builder.Property(ur => ur.CreatedAt).HasColumnName("created_at");
        builder.Property(ur => ur.UpdatedAt).HasColumnName("updated_at");

        builder.HasIndex(ur => new { ur.UserId, ur.RoleId }).IsUnique()
            .HasDatabaseName("ix_user_roles_user_role");

        builder.HasOne(ur => ur.Role)
            .WithMany()
            .HasForeignKey(ur => ur.RoleId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}

public class RolePermissionConfiguration : IEntityTypeConfiguration<RolePermission>
{
    public void Configure(EntityTypeBuilder<RolePermission> builder)
    {
        builder.ToTable("role_permissions");
        builder.HasKey(rp => rp.Id);
        builder.Property(rp => rp.Id).HasColumnName("id");
        builder.Property(rp => rp.RoleId).HasColumnName("role_id").IsRequired();
        builder.Property(rp => rp.PermissionId).HasColumnName("permission_id").IsRequired();
        builder.Property(rp => rp.CreatedAt).HasColumnName("created_at");
        builder.Property(rp => rp.UpdatedAt).HasColumnName("updated_at");

        builder.HasIndex(rp => new { rp.RoleId, rp.PermissionId }).IsUnique()
            .HasDatabaseName("ix_role_permissions_role_permission");

        builder.HasOne(rp => rp.Permission)
            .WithMany()
            .HasForeignKey(rp => rp.PermissionId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");
        builder.HasKey(rt => rt.Id);
        builder.Property(rt => rt.Id).HasColumnName("id");
        builder.Property(rt => rt.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(rt => rt.Token).HasColumnName("token").HasMaxLength(512).IsRequired();
        builder.Property(rt => rt.ExpiresAt).HasColumnName("expires_at").IsRequired();
        builder.Property(rt => rt.IsRevoked).HasColumnName("is_revoked").HasDefaultValue(false);
        builder.Property(rt => rt.RevokedAt).HasColumnName("revoked_at");
        builder.Property(rt => rt.IpAddress).HasColumnName("ip_address").HasMaxLength(50);
        builder.Property(rt => rt.UserAgent).HasColumnName("user_agent").HasMaxLength(512);
        builder.Property(rt => rt.CreatedAt).HasColumnName("created_at");
        builder.Property(rt => rt.UpdatedAt).HasColumnName("updated_at");

        builder.HasIndex(rt => rt.Token).IsUnique().HasDatabaseName("ix_refresh_tokens_token");
        builder.HasIndex(rt => rt.UserId).HasDatabaseName("ix_refresh_tokens_user_id");
    }
}

public class OrganizationConfiguration : IEntityTypeConfiguration<Organization>
{
    public void Configure(EntityTypeBuilder<Organization> builder)
    {
        builder.ToTable("organizations");
        builder.HasKey(o => o.Id);
        builder.Property(o => o.Id).HasColumnName("id");
        builder.Property(o => o.Name).HasColumnName("name").HasMaxLength(100).IsRequired();
        builder.Property(o => o.Slug).HasColumnName("slug").HasMaxLength(100).IsRequired();
        builder.Property(o => o.Description).HasColumnName("description").HasMaxLength(500);
        builder.Property(o => o.IsActive).HasColumnName("is_active").HasDefaultValue(true);
        builder.Property(o => o.CreatedAt).HasColumnName("created_at");
        builder.Property(o => o.UpdatedAt).HasColumnName("updated_at");

        builder.HasIndex(o => o.Slug).IsUnique().HasDatabaseName("ix_organizations_slug");
        builder.Ignore(o => o.DomainEvents);
    }
}

public class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        builder.ToTable("audit_logs");
        builder.HasKey(al => al.Id);
        builder.Property(al => al.Id).HasColumnName("id");
        builder.Property(al => al.UserId).HasColumnName("user_id");
        builder.Property(al => al.Action).HasColumnName("action").HasMaxLength(200).IsRequired();
        builder.Property(al => al.ResourceType).HasColumnName("resource_type").HasMaxLength(100).IsRequired();
        builder.Property(al => al.ResourceId).HasColumnName("resource_id").HasMaxLength(100);
        builder.Property(al => al.OldValues).HasColumnName("old_values").HasColumnType("jsonb");
        builder.Property(al => al.NewValues).HasColumnName("new_values").HasColumnType("jsonb");
        builder.Property(al => al.IpAddress).HasColumnName("ip_address").HasMaxLength(50);
        builder.Property(al => al.UserAgent).HasColumnName("user_agent").HasMaxLength(512);
        builder.Property(al => al.CorrelationId).HasColumnName("correlation_id").HasMaxLength(100);
        builder.Property(al => al.CreatedAt).HasColumnName("created_at");
        builder.Property(al => al.UpdatedAt).HasColumnName("updated_at");

        builder.HasIndex(al => al.UserId).HasDatabaseName("ix_audit_logs_user_id");
        builder.HasIndex(al => al.CreatedAt).HasDatabaseName("ix_audit_logs_created_at");
        builder.HasIndex(al => al.ResourceType).HasDatabaseName("ix_audit_logs_resource_type");
    }
}
