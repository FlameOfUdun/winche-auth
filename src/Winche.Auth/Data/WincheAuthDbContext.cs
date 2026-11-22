using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Winche.Auth.Data;

/// <summary>Winche Auth's tables, all prefixed <c>auth_</c>, with their own migrations history table.</summary>
internal sealed class WincheAuthDbContext(DbContextOptions<WincheAuthDbContext> options) : IdentityUserContext<WincheUser>(options)
{
    public const string MigrationsTable = "__winche_auth_migrations";

    public DbSet<AuthSession> Sessions => Set<AuthSession>();
    public DbSet<AuthSigningKey> SigningKeys => Set<AuthSigningKey>();
    public DbSet<AuthActionCode> ActionCodes => Set<AuthActionCode>();
    public DbSet<AuthEmailTemplate> EmailTemplates => Set<AuthEmailTemplate>();
    public DbSet<AuthUserPhoto> Photos => Set<AuthUserPhoto>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<WincheUser>(e =>
        {
            e.ToTable("auth_users");
            e.Property(u => u.Id).HasMaxLength(64);
            e.Property(u => u.CustomClaims).HasColumnType("jsonb");
            e.Property(u => u.PhotoSource).HasMaxLength(80);
            // Unique among users that have one (anonymous users have none).
            e.HasIndex(u => u.NormalizedEmail).IsUnique().HasFilter("\"NormalizedEmail\" IS NOT NULL").HasDatabaseName("auth_users_email");
            e.HasIndex(u => u.CreatedAt).HasDatabaseName("auth_users_created");
            // Index names are per database, and ASP.NET Identity's defaults ("UserNameIndex") clash with other Identity
            // tables in the same one (the Winche console's): every name here is prefixed.
            e.HasIndex(u => u.NormalizedUserName).IsUnique().HasDatabaseName("auth_users_username");
        });
        builder.Entity<IdentityUserClaim<string>>().ToTable("auth_user_claims");
        builder.Entity<IdentityUserLogin<string>>().ToTable("auth_user_logins");
        builder.Entity<IdentityUserToken<string>>().ToTable("auth_user_tokens");

        builder.Entity<AuthSession>(e =>
        {
            e.ToTable("auth_sessions");
            e.HasKey(s => s.Id);
            e.Property(s => s.UserId).HasMaxLength(64).IsRequired();
            e.HasIndex(s => s.UserId).HasDatabaseName("auth_sessions_user");
            e.HasIndex(s => s.ExpiresAt).HasDatabaseName("auth_sessions_expires");
            e.Property(s => s.ProviderSessionId).HasMaxLength(256);
            e.HasIndex(s => new { s.Provider, s.ProviderSessionId }).HasDatabaseName("auth_sessions_provider_session");
            e.HasOne<WincheUser>().WithMany().HasForeignKey(s => s.UserId).OnDelete(DeleteBehavior.Cascade);
        });
        builder.Entity<AuthActionCode>(e =>
        {
            e.ToTable("auth_action_codes");
            e.HasKey(c => c.Id);
            e.Property(c => c.Kind).HasMaxLength(32).IsRequired();
            e.Property(c => c.UserId).HasMaxLength(64);
            e.Property(c => c.Email).HasMaxLength(256).IsRequired();
            e.HasIndex(c => c.CodeHash).IsUnique().HasDatabaseName("auth_action_codes_hash");
            e.HasIndex(c => new { c.Email, c.CreatedAt }).HasDatabaseName("auth_action_codes_email");
            e.HasIndex(c => c.ExpiresAt).HasDatabaseName("auth_action_codes_expires");
            e.HasOne<WincheUser>().WithMany().HasForeignKey(c => c.UserId).OnDelete(DeleteBehavior.Cascade);
        });
        builder.Entity<AuthEmailTemplate>(e =>
        {
            e.ToTable("auth_email_templates");
            e.HasKey(t => t.Kind);
            e.Property(t => t.Kind).HasMaxLength(32);
        });
        builder.Entity<AuthUserPhoto>(e =>
        {
            e.ToTable("auth_user_photos");
            e.HasKey(p => p.UserId);
            e.Property(p => p.UserId).HasMaxLength(64);
            e.Property(p => p.PhotoId).HasMaxLength(40).IsRequired();
            e.Property(p => p.ContentType).HasMaxLength(32).IsRequired();
            e.HasIndex(p => p.PhotoId).IsUnique().HasDatabaseName("auth_user_photos_photo");
            e.HasOne<WincheUser>().WithOne().HasForeignKey<AuthUserPhoto>(p => p.UserId).OnDelete(DeleteBehavior.Cascade);
        });
        builder.Entity<AuthSigningKey>(e =>
        {
            e.ToTable("auth_signing_keys");
            e.HasKey(k => k.Kid);
        });
    }
}

/// <summary>Used only by <c>dotnet ef</c> to build the model at design time.</summary>
internal sealed class DesignTimeFactory : Microsoft.EntityFrameworkCore.Design.IDesignTimeDbContextFactory<WincheAuthDbContext>
{
    public WincheAuthDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<WincheAuthDbContext>()
            .UseNpgsql("Host=localhost;Database=winche_auth;Username=postgres;Password=postgres",
                x => x.MigrationsHistoryTable(WincheAuthDbContext.MigrationsTable))
            .Options);
}
