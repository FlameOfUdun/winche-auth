using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;
using Winche.Auth.Tokens;

namespace Winche.Auth.AspNetCore;

/// <summary>
/// Unhealthy when Winche Auth's database can't be reached or there's no key to sign tokens with; degraded when user
/// events fall behind (an observer still has one older than <c>maxLag</c>) or some were given up on (dead letters), or a
/// Keycloak sync fails or hasn't run for <c>maxLag</c>.
/// </summary>
public sealed class WincheAuthHealthCheck : IHealthCheck
{
    private readonly NpgsqlDataSource _db;
    private readonly SigningKeyStore _keys;
    private readonly AuthUserEvents _events;
    private readonly TimeSpan _maxLag;
    private readonly Providers.ProviderSyncs _syncs;

    internal WincheAuthHealthCheck(NpgsqlDataSource db, SigningKeyStore keys, AuthUserEvents events, Providers.ProviderSyncs syncs, TimeSpan maxLag) =>
        (_db, _keys, _events, _syncs, _maxLag) = (db, keys, events, syncs, maxLag);

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            await using (var cmd = _db.CreateCommand("SELECT 1")) await cmd.ExecuteScalarAsync(ct);
            if (!(await _keys.ListAsync(ct)).Any(k => k.RetiredAt is null))
                return HealthCheckResult.Unhealthy("No signing key: tokens can't be issued.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return HealthCheckResult.Unhealthy("Winche Auth's database can't be reached.", ex);
        }

        var consumers = await _events.ConsumersAsync(ct);
        var deadLetters = consumers.Sum(c => c.DeadLetters);
        var failing = consumers.Count(c => c.FailingSince is not null);
        var data = new Dictionary<string, object> { ["observers"] = consumers.Count, ["failing"] = failing, ["deadLetters"] = deadLetters };
        var problems = new List<string>();
        if (consumers.Min(c => c.OldestPendingAt) is { } oldest && DateTimeOffset.UtcNow - oldest > _maxLag)
            problems.Add($"an observer still has a user event from {oldest:u} to take");
        if (deadLetters > 0) problems.Add($"{deadLetters} user event(s) given up on");
        foreach (var sync in await _syncs.StatusAsync(ct))
        {
            if (sync.LastError is { } error) problems.Add($"the Keycloak sync of {sync.Provider} fails: {error}");
            else if (sync.LastRunAt is { } at && DateTimeOffset.UtcNow - at > _maxLag) problems.Add($"the Keycloak sync of {sync.Provider} last ran at {at:u}");
        }
        return problems.Count == 0 ? HealthCheckResult.Healthy(data: data) : HealthCheckResult.Degraded(string.Join("; ", problems), data: data);
    }
}

public static class WincheAuthHealthCheckExtensions
{
    /// <summary>Adds <see cref="WincheAuthHealthCheck"/> (user events degraded past <paramref name="maxLag"/>, default 5 minutes).</summary>
    public static IHealthChecksBuilder AddWincheAuth(this IHealthChecksBuilder builder, string name = "winche-auth", TimeSpan? maxLag = null,
        IEnumerable<string>? tags = null) =>
        builder.Add(new HealthCheckRegistration(
            name,
            sp => new WincheAuthHealthCheck(sp.GetRequiredKeyedService<NpgsqlDataSource>(AuthUserEvents.DataSourceKey), sp.GetRequiredService<SigningKeyStore>(),
                sp.GetRequiredService<AuthUserEvents>(), sp.GetRequiredService<Providers.ProviderSyncs>(), maxLag ?? TimeSpan.FromMinutes(5)),
            HealthStatus.Unhealthy,
            tags));
}
