using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Winche.Core;
using Winche.Core.Feeds;
using Winche.Auth.Users;

namespace Winche.Auth.Providers;

/// <summary>How a provider's Keycloak sync is doing.</summary>
/// <param name="EventsAfter">Keycloak events up to this time have been read.</param>
/// <param name="LastError">The last run's failure, if it failed.</param>
public sealed record ProviderSyncStatus(string Provider, DateTimeOffset? LastRunAt, DateTimeOffset? EventsAfter, DateTimeOffset? ReconciledAt,
    string? LastError, DateTimeOffset? LastChangeAt);

/// <summary>The Keycloak syncs: their status, and waking one now (the webhook).</summary>
public sealed class ProviderSyncs : IDisposable
{
    private readonly ConcurrentDictionary<string, (KeycloakSyncOptions Options, KeycloakReader Reader)> _readers = new();

    /// <summary>The reader for <paramref name="provider"/>'s Keycloak (one per provider and its sync options).</summary>
    internal KeycloakReader Reader(IdentityProviderOptions provider)
    {
        var sync = provider.KeycloakSync!;
        if (_readers.TryGetValue(provider.Name, out var known) && ReferenceEquals(known.Options, sync)) return known.Reader;
        var reader = new KeycloakReader(provider, _secrets);
        _readers[provider.Name] = (sync, reader);
        return reader;
    }

    public void Dispose()
    {
        foreach (var (_, reader) in _readers.Values) reader.Dispose();
    }

    internal const string Table = "auth_provider_sync", Channel = "auth_provider_sync";
    internal static readonly string[] Schema =
    [
        $"""
        CREATE TABLE IF NOT EXISTS {Table} (
            provider       text        PRIMARY KEY,
            events_after   bigint      NOT NULL,
            reconciled_at  timestamptz NULL,
            last_run_at    timestamptz NULL,
            last_error     text        NULL,
            last_change_at timestamptz NULL
        );
        """,
    ];

    internal NpgsqlDataSource Db { get; }
    private readonly WincheAuthOptions _options;

    private readonly Winche.Secrets.SecretStore? _secrets;

    internal ProviderSyncs(NpgsqlDataSource db, WincheAuthOptions options, Winche.Secrets.SecretStore? secrets = null) => (Db, _options, _secrets) = (db, options, secrets);

    internal IEnumerable<IdentityProviderOptions> Synced => _options.IdentityProviders.Where(p => p.KeycloakSync is not null);

    /// <summary>Each synced provider's status.</summary>
    public async Task<IReadOnlyList<ProviderSyncStatus>> StatusAsync(CancellationToken ct = default)
    {
        if (!Synced.Any()) return [];
        await WincheSchema.EnsureAsync(Db, "auth-provider-sync", Schema, ct);
        var rows = new Dictionary<string, ProviderSyncStatus>();
        await using (var cmd = Db.CreateCommand($"SELECT provider, last_run_at, events_after, reconciled_at, last_error, last_change_at FROM {Table}"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
                rows[r.GetString(0)] = new ProviderSyncStatus(r.GetString(0), At(r, 1), DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(2)), At(r, 3),
                    r.IsDBNull(4) ? null : r.GetString(4), At(r, 5));
        return [.. Synced.Select(p => rows.GetValueOrDefault(p.Name) ?? new ProviderSyncStatus(p.Name, null, null, null, null, null))];
    }

    private static DateTimeOffset? At(NpgsqlDataReader r, int i) => r.IsDBNull(i) ? null : r.GetFieldValue<DateTimeOffset>(i);

    /// <summary>Reads <paramref name="provider"/>'s Keycloak events now, on whichever server runs its sync.</summary>
    public async Task WakeAsync(string provider, CancellationToken ct = default)
    {
        await using var cmd = Db.CreateCommand("SELECT pg_notify($1, $2)");
        cmd.Parameters.AddWithValue(Channel);
        cmd.Parameters.AddWithValue(provider);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

/// <summary>
/// Runs each provider's Keycloak sync on one server at a time (an advisory lease): reads Keycloak's events every
/// <see cref="KeycloakSyncOptions.PollInterval"/> (or when woken) and applies the users they name; compares every
/// linked user every <see cref="KeycloakSyncOptions.ReconcileInterval"/>.
/// </summary>
internal sealed class KeycloakSyncService(IServiceProvider services, ProviderSyncs syncs, TimeProvider time, ILogger<KeycloakSyncService> logger)
    : BackgroundService
{
    private readonly ConcurrentDictionary<string, string> _lastError = new();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var providers = syncs.Synced.ToList();
        if (providers.Count == 0) return;
        try { await WincheSchema.EnsureAsync(syncs.Db, "auth-provider-sync", ProviderSyncs.Schema, stoppingToken); }
        catch (OperationCanceledException) { return; }
        await Task.WhenAll(providers.Select(p => RunAsync(p, stoppingToken)));
    }

    private async Task RunAsync(IdentityProviderOptions provider, CancellationToken ct)
    {
        var sync = provider.KeycloakSync!;
        var reader = syncs.Reader(provider);
        while (!ct.IsCancellationRequested)
        {
            AdvisoryLease? lease = null;
            try
            {
                lease = await AdvisoryLease.TryAcquireAsync(syncs.Db, $"auth-sync:{provider.Name}", TimeSpan.FromSeconds(10), ct);
                if (lease is null) { await Task.Delay(TimeSpan.FromSeconds(5), ct); continue; }
                using var held = CancellationTokenSource.CreateLinkedTokenSource(ct, lease.Lost);
                await using var wake = new WincheFeedWake(syncs.Db, ProviderSyncs.Channel, sync.PollInterval, logger);
                while (!held.IsCancellationRequested)
                {
                    await RunOnceAsync(provider, reader, held.Token);
                    await wake.WaitAsync(held.Token);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (OperationCanceledException) { }   // the lease was lost: try again
            catch (Exception ex)
            {
                logger.LogWarning(ex, "The Keycloak sync of {Provider} stopped; it starts again shortly.", provider.Name);
                try { await Task.Delay(TimeSpan.FromSeconds(5), ct); } catch (OperationCanceledException) { break; }
            }
            finally { if (lease is not null) await lease.DisposeAsync(); }
        }
    }

    /// <summary>One run: events since the last, or (when due, or too many) every linked user.</summary>
    internal async Task RunOnceAsync(IdentityProviderOptions provider, KeycloakReader reader, CancellationToken ct)
    {
        var sync = provider.KeycloakSync!;
        var claims = reader.ClaimNames;
        var now = time.GetUtcNow();
        var (eventsAfter, reconciledAt) = await StateAsync(provider.Name, now, ct);
        var changed = 0;
        try
        {
            if (reconciledAt is null || now - reconciledAt >= sync.ReconcileInterval)
            {
                eventsAfter = now.AddMinutes(-1).ToUnixTimeMilliseconds();   // events from here on are read next time
                changed = await ReconcileAsync(provider, reader, claims, ct);
                reconciledAt = now;
            }
            else
            {
                var (ids, newest, complete) = await reader.ChangedSinceAsync(eventsAfter, ct);
                foreach (var id in ids)
                    if (await ApplyAsync(provider, id, await reader.UserAsync(id, ct), claims, ct)) changed++;
                eventsAfter = newest;
                if (!complete) reconciledAt = null;   // more than a poll reads: compare everyone next time
            }
            await SaveAsync(provider.Name, eventsAfter, reconciledAt, now, null, changed > 0, ct);
            if (_lastError.TryRemove(provider.Name, out _))
                logger.LogInformation("The Keycloak sync of {Provider} works again.", provider.Name);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await SaveAsync(provider.Name, eventsAfter, reconciledAt, now, ex.Message, changed > 0, ct);
            if (_lastError.GetValueOrDefault(provider.Name) != ex.Message)   // each new problem once, not every poll
                logger.LogWarning(ex, "The Keycloak sync of {Provider} failed: {Message}", provider.Name, ex.Message);
            _lastError[provider.Name] = ex.Message;
        }
    }

    private async Task<int> ReconcileAsync(IdentityProviderOptions provider, KeycloakReader reader, IReadOnlyList<string> claims, CancellationToken ct)
    {
        var changed = 0;
        string? after = null;
        while (true)
        {
            IReadOnlyList<(string Uid, string Subject)> page;
            await using (var scope = services.CreateAsyncScope())
                page = await ((WincheAuthService)scope.ServiceProvider.GetRequiredService<IWincheAuth>()).LinkedAsync(provider.Name, after, 200, ct);
            if (page.Count == 0) return changed;
            foreach (var (_, subject) in page)
                if (await ApplyAsync(provider, subject, await reader.UserAsync(subject, ct), claims, ct)) changed++;
            after = page[^1].Uid;
        }
    }

    private async Task<bool> ApplyAsync(IdentityProviderOptions provider, string subject, KeycloakUserState? state, IReadOnlyList<string> claims, CancellationToken ct)
    {
        await using var scope = services.CreateAsyncScope();
        var auth = (WincheAuthService)scope.ServiceProvider.GetRequiredService<IWincheAuth>();
        try { return await auth.SyncFromProviderAsync(provider, subject, state, claims, ct) is not null; }
        catch (AuthException ex)
        {
            logger.LogWarning("The Keycloak sync of {Provider} couldn't apply user {Subject}: {Message}", provider.Name, subject, ex.Message);
            return false;
        }
    }

    private async Task<(long EventsAfter, DateTimeOffset? ReconciledAt)> StateAsync(string provider, DateTimeOffset now, CancellationToken ct)
    {
        await using (var insert = syncs.Db.CreateCommand($"INSERT INTO {ProviderSyncs.Table} (provider, events_after) VALUES ($1, $2) ON CONFLICT (provider) DO NOTHING"))
        {
            insert.Parameters.AddWithValue(provider);
            insert.Parameters.AddWithValue(now.ToUnixTimeMilliseconds());
            await insert.ExecuteNonQueryAsync(ct);
        }
        await using var cmd = syncs.Db.CreateCommand($"SELECT events_after, reconciled_at FROM {ProviderSyncs.Table} WHERE provider = $1");
        cmd.Parameters.AddWithValue(provider);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        await r.ReadAsync(ct);
        return (r.GetInt64(0), r.IsDBNull(1) ? null : r.GetFieldValue<DateTimeOffset>(1));
    }

    private async Task SaveAsync(string provider, long eventsAfter, DateTimeOffset? reconciledAt, DateTimeOffset runAt, string? error, bool changed, CancellationToken ct)
    {
        await using var cmd = syncs.Db.CreateCommand($"""
            UPDATE {ProviderSyncs.Table} SET events_after = $2, reconciled_at = $3, last_run_at = $4, last_error = $5,
                last_change_at = CASE WHEN $6 THEN $4 ELSE last_change_at END
            WHERE provider = $1
            """);
        cmd.Parameters.AddWithValue(provider);
        cmd.Parameters.AddWithValue(eventsAfter);
        cmd.Parameters.Add(new NpgsqlParameter { Value = (object?)reconciledAt ?? DBNull.Value, NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.TimestampTz });
        cmd.Parameters.AddWithValue(runAt);
        cmd.Parameters.Add(new NpgsqlParameter { Value = (object?)error ?? DBNull.Value, NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Text });
        cmd.Parameters.AddWithValue(changed);
        await cmd.ExecuteNonQueryAsync(CancellationToken.None);
    }
}
