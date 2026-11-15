using Npgsql;

namespace Winche.Auth;

/// <summary>
/// Counts attempts per kind and key (an IP address, an account) per minute, in Postgres: every server shares the
/// counts, so running more of them doesn't multiply what an attacker may try. On top of the per-account lockout.
/// Uses Winche Auth's connection pool.
/// </summary>
internal sealed class AttemptLimiter(NpgsqlDataSource db, TimeProvider time)
{
    private volatile bool _ready;

    /// <summary>Makes its table (setup; otherwise made on first use).</summary>
    internal async Task EnsureAsync(CancellationToken ct)
    {
        await using var _ = await OpenAsync(ct);
    }

    private async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
    {
        var conn = await db.OpenConnectionAsync(ct);
        if (_ready) return conn;
        try
        {
            await using var create = new NpgsqlCommand(
                "CREATE TABLE IF NOT EXISTS auth_attempts (key text NOT NULL, minute bigint NOT NULL, count int NOT NULL, PRIMARY KEY (key, minute))", conn);
            await create.ExecuteNonQueryAsync(ct);
        }
        catch (PostgresException ex) when (ex.SqlState is PostgresErrorCodes.UniqueViolation or PostgresErrorCodes.DuplicateTable) { }   // another server made it
        _ready = true;
        return conn;
    }

    /// <summary>Counts one attempt of <paramref name="kind"/> by <paramref name="key"/>; throws TOO_MANY_ATTEMPTS past <paramref name="perMinute"/>.</summary>
    public async Task CheckAsync(string kind, string? key, int perMinute, CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);
        var minute = time.GetUtcNow().ToUnixTimeSeconds() / 60;
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO auth_attempts (key, minute, count) VALUES ($1, $2, 1)
            ON CONFLICT (key, minute) DO UPDATE SET count = auth_attempts.count + 1
            RETURNING count
            """, conn);
        cmd.Parameters.AddWithValue($"{kind}|{key}");
        cmd.Parameters.AddWithValue(minute);
        var count = (int)(await cmd.ExecuteScalarAsync(ct))!;
        if (count == 1 && Random.Shared.Next(100) == 0)
        {
            // Now and then, forget finished minutes.
            await using var prune = new NpgsqlCommand("DELETE FROM auth_attempts WHERE minute < $1", conn);
            prune.Parameters.AddWithValue(minute - 2);
            await prune.ExecuteNonQueryAsync(ct);
        }
        if (count > perMinute)
            throw new AuthException(AuthErrorCodes.TooManyAttempts, "Too many attempts from this address. Wait a minute and try again.");
    }
}
