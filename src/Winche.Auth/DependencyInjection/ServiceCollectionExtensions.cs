using Microsoft.EntityFrameworkCore.Infrastructure;
using Winche.Core;
using Npgsql;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Winche.Auth.Data;
using Winche.Auth.Sessions;
using Winche.Auth.Tokens;
using Winche.Auth.Users;

namespace Winche.Auth.DependencyInjection;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds Winche Auth: users (ASP.NET Core Identity on PostgreSQL), sessions and token signing. Its tables are made or
    /// migrated on start. Map the endpoints with <c>app.MapWincheAuth()</c> and accept its tokens with
    /// <c>AddAuthentication().AddWincheTokens(t =&gt; t.TrustWincheAuth())</c> (Winche.Auth.AspNetCore).
    /// </summary>
    public static IServiceCollection AddWincheAuth(this IServiceCollection services, Action<WincheAuthOptions> configure)
    {
        var options = new WincheAuthOptions();
        configure(options);
        options.Validate();
        services.AddSingleton(options);
        AuthChanges.Add(services);   // user events for webhooks and functions
        if (options.SettingsEnabled)
        {
            // The console may change these: the code's values are where they start.
            var code = Settings.WincheAuthSettings.CodeParts.From(options);
            var area = Winche.Core.ServiceCollectionExtensions.AddWincheSettingsArea(services, Settings.WincheAuthSettings.Area, "Winche Auth sign-in",
                Settings.WincheAuthSettings.From(options), s => s.Problems(code));
            area.Changed += s => s.ApplyTo(options, code);
            services.AddSingleton(code);
        }
        services.TryAddSingleton(TimeProvider.System);

        // One connection pool for everything Winche Auth does: its tables, its event feed, its attempt counts.
        services.AddKeyedSingleton(AuthUserEvents.DataSourceKey, (_, _) => NpgsqlDataSource.Create(options.ConnectionString));
        services.AddDbContextFactory<WincheAuthDbContext>((sp, o) =>
            o.UseNpgsql(sp.GetRequiredKeyedService<NpgsqlDataSource>(AuthUserEvents.DataSourceKey),
                x => x.MigrationsHistoryTable(WincheAuthDbContext.MigrationsTable)));   // the factory is a singleton; the context scoped

        // Identity's options are app-wide; Winche Auth's user manager carries its own (WincheUserManager).
        services.AddIdentityCore<WincheUser>()
            .AddUserManager<WincheUserManager>()
            .AddEntityFrameworkStores<WincheAuthDbContext>();

        services.AddSingleton(sp => new AuthUserEvents(sp.GetRequiredKeyedService<NpgsqlDataSource>(AuthUserEvents.DataSourceKey),
            sp.GetServices<IWincheAuthObserver>(), options));
        services.AddSingleton<Winche.Core.Feeds.IWincheFeedConsumers>(sp => sp.GetRequiredService<AuthUserEvents>());
        services.AddSingleton(sp => new SigningKeyStore(sp.GetRequiredService<IDbContextFactory<WincheAuthDbContext>>(), options,
            sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<ILogger<SigningKeyStore>>(), sp.GetService<Winche.Core.WincheKeys>()));
        services.AddSingleton(sp => new AttemptLimiter(sp.GetRequiredKeyedService<NpgsqlDataSource>(AuthUserEvents.DataSourceKey), sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton<TokenIssuer>();
        services.AddSingleton<Providers.IdTokenValidator>();
        services.AddScoped<SessionStore>();
        services.AddScoped<IWincheAuth, WincheAuthService>();
        // Background work starts once Auth is set up (at once, unless the host sets products up on demand).
        services.AddWincheProductService<WincheAuthStartup>(WincheProductNames.Authentication);
        services.AddWincheProductService<AuthEventService>(WincheProductNames.Authentication);
        services.AddSingleton<IWincheProductSetup, AuthProductSetup>();
        // user: for the database's expand (a document field holding a uid comes back with the user's public profile).
        services.AddSingleton<IWincheReferenceResolver>(sp => new Users.UserReferenceResolver(sp, options));
        services.AddSingleton(sp => new Providers.ProviderSyncs(sp.GetRequiredKeyedService<NpgsqlDataSource>(AuthUserEvents.DataSourceKey), options,
            sp.GetService<Winche.Core.SecretStore>()));   // a sync set in settings keeps its client secret there
        services.AddWincheProductService<Providers.KeycloakSyncService>(WincheProductNames.Authentication);
        return services;
    }
}

/// <summary>Auth's setup, step by step, for hosts that set products up on demand (otherwise <see cref="WincheAuthStartup"/> does it).</summary>
internal sealed class AuthProductSetup(IServiceProvider services, SigningKeyStore keys, AuthUserEvents events, AttemptLimiter attempts,
    Providers.ProviderSyncs syncs) : IWincheProductSetup
{
    public string Product => WincheProductNames.Authentication;

    public IReadOnlyList<string> Steps { get; } = ["Create the user tables", "Prepare the user events", "Make the token signing key"];

    public async Task RunStepAsync(int step, CancellationToken ct)
    {
        switch (step)
        {
            case 0:
                await using (var scope = services.CreateAsyncScope())
                    await scope.ServiceProvider.GetRequiredService<WincheAuthDbContext>().MigrateQuietlyAsync(ct);
                // Tables otherwise made on first use: sign-in attempts, provider sync.
                await attempts.EnsureAsync(ct);
                await WincheSchema.EnsureAsync(syncs.Db, "auth-provider-sync", Providers.ProviderSyncs.Schema, ct);
                break;
            case 1: await events.StartAsync(ct); break;
            case 2: await keys.EnsureAsync(force: false, ct); break;
            default: throw new ArgumentOutOfRangeException(nameof(step));
        }
    }
}

/// <summary>Migrates the tables and makes the first signing key on start; then prunes old sessions and rotates keys hourly.</summary>
internal sealed class WincheAuthStartup(IServiceProvider services, SigningKeyStore keys, AuthUserEvents events, ILogger<WincheAuthStartup> logger) : BackgroundService
{
    public override async Task StartAsync(CancellationToken ct)
    {
        await using (var scope = services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<WincheAuthDbContext>().MigrateQuietlyAsync(ct);
        await events.StartAsync(ct);
        await keys.EnsureAsync(force: false, ct);
        await base.StartAsync(ct);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await keys.EnsureAsync(force: false, stoppingToken);
                await using var scope = services.CreateAsyncScope();
                var pruned = await scope.ServiceProvider.GetRequiredService<SessionStore>().PruneAsync(stoppingToken);
                var cutoff = DateTimeOffset.UtcNow.AddDays(-1);
                await scope.ServiceProvider.GetRequiredService<WincheAuthDbContext>().ActionCodes.Where(c => c.ExpiresAt < cutoff).ExecuteDeleteAsync(stoppingToken);
                if (pruned > 0) logger.LogInformation("Deleted {Count} ended sessions.", pruned);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Winche Auth upkeep failed.");
            }
        }
    }
}

internal static class WincheAuthMigrations
{
    /// <summary>
    /// Migrates, its history table made first: on a new database EF otherwise reads the missing table before making it
    /// and logs that as a failed command, though nothing failed.
    /// </summary>
    public static async Task MigrateQuietlyAsync(this WincheAuthDbContext db, CancellationToken ct)
    {
        await db.GetService<Microsoft.EntityFrameworkCore.Migrations.IHistoryRepository>().CreateIfNotExistsAsync(ct);
        await db.Database.MigrateAsync(ct);
    }
}
