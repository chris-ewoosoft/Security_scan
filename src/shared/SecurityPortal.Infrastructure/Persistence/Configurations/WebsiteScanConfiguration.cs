using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Infrastructure.Persistence.Configurations;

public class WebsiteScanConfiguration : IEntityTypeConfiguration<WebsiteScan>
{
    public void Configure(EntityTypeBuilder<WebsiteScan> builder)
    {
        builder.ToTable("website_scans");
        builder.HasKey(s => s.Id);
        builder.Property(s => s.Id).HasColumnName("id");
        builder.Property(s => s.TargetUrl).HasColumnName("target_url").HasMaxLength(2048).IsRequired();
        builder.Property(s => s.NormalizedHost).HasColumnName("normalized_host").HasMaxLength(255).IsRequired();
        builder.Property(s => s.Status).HasColumnName("status").HasConversion<string>().HasMaxLength(32).IsRequired();
        builder.Property(s => s.CreatedByUserId).HasColumnName("created_by_user_id");
        builder.Property(s => s.OrganizationId).HasColumnName("organization_id");
        builder.Property(s => s.StartedAt).HasColumnName("started_at");
        builder.Property(s => s.CompletedAt).HasColumnName("completed_at");
        builder.Property(s => s.ErrorMessage).HasColumnName("error_message").HasMaxLength(2000);
        builder.Property(s => s.Summary).HasColumnName("summary").HasMaxLength(4000);
        builder.Property(s => s.HttpStatusCode).HasColumnName("http_status_code");
        builder.Property(s => s.ResponseTimeMs).HasColumnName("response_time_ms");
        builder.Property(s => s.HasHttps).HasColumnName("has_https");
        builder.Property(s => s.ServerHeader).HasColumnName("server_header").HasMaxLength(512);
        builder.Property(s => s.ConfigJson).HasColumnName("config_json").HasColumnType("text").IsRequired();
        builder.Property(s => s.FindingsJson).HasColumnName("findings_json").HasColumnType("text");
        builder.Property(s => s.ReportType).HasColumnName("report_type").HasMaxLength(64).IsRequired();
        builder.Property(s => s.CreatedAt).HasColumnName("created_at");
        builder.Property(s => s.UpdatedAt).HasColumnName("updated_at");

        builder.HasIndex(s => s.Status).HasDatabaseName("ix_website_scans_status");
        builder.HasIndex(s => s.NormalizedHost).HasDatabaseName("ix_website_scans_host");
        builder.HasIndex(s => s.CreatedAt).HasDatabaseName("ix_website_scans_created_at");
        builder.Ignore(s => s.DomainEvents);
    }
}
