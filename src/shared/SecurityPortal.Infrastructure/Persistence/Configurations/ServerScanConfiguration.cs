using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Infrastructure.Persistence.Configurations;

public class ServerScanConfiguration : IEntityTypeConfiguration<ServerScan>
{
    public void Configure(EntityTypeBuilder<ServerScan> builder)
    {
        builder.ToTable("server_scans");
        builder.HasKey(s => s.Id);
        builder.Property(s => s.Id).HasColumnName("id");
        builder.Property(s => s.Host).HasColumnName("host").HasMaxLength(255).IsRequired();
        builder.Property(s => s.Port).HasColumnName("port").IsRequired();
        builder.Property(s => s.Username).HasColumnName("username").HasMaxLength(255).IsRequired();
        builder.Property(s => s.AuthType).HasColumnName("auth_type").HasConversion<string>().HasMaxLength(32).IsRequired();
        builder.Property(s => s.SecretCipher).HasColumnName("secret_cipher").HasColumnType("text").IsRequired();
        builder.Property(s => s.PassphraseCipher).HasColumnName("passphrase_cipher").HasColumnType("text");
        builder.Property(s => s.Status).HasColumnName("status").HasConversion<string>().HasMaxLength(32).IsRequired();
        builder.Property(s => s.CreatedByUserId).HasColumnName("created_by_user_id");
        builder.Property(s => s.OrganizationId).HasColumnName("organization_id");
        builder.Property(s => s.StartedAt).HasColumnName("started_at");
        builder.Property(s => s.CompletedAt).HasColumnName("completed_at");
        builder.Property(s => s.ErrorMessage).HasColumnName("error_message").HasMaxLength(2000);
        builder.Property(s => s.Summary).HasColumnName("summary").HasMaxLength(4000);
        builder.Property(s => s.FindingsJson).HasColumnName("findings_json").HasColumnType("text");
        builder.Property(s => s.RawOutputJson).HasColumnName("raw_output_json").HasColumnType("text");
        builder.Property(s => s.RawOutputExpiresAt).HasColumnName("raw_output_expires_at");
        builder.Property(s => s.OwnerTokenHash).HasColumnName("owner_token_hash").HasMaxLength(128).IsRequired();
        builder.Property(s => s.CreatedAt).HasColumnName("created_at");
        builder.Property(s => s.UpdatedAt).HasColumnName("updated_at");

        builder.HasIndex(s => s.Status).HasDatabaseName("ix_server_scans_status");
        builder.HasIndex(s => s.CreatedAt).HasDatabaseName("ix_server_scans_created_at");
        builder.Ignore(s => s.DomainEvents);
    }
}
