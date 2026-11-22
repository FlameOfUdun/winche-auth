using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.Data;

namespace Winche.Auth.Sessions;

/// <summary>
/// Sessions and their refresh tokens (<c>{session}.{secret}</c>, only the secret's hash stored). Each refresh replaces the
/// token; the replaced one presented again means it was copied, so the session ends — unless it's within a few seconds
/// (two requests from the same app refreshing at once), when that request is just refused.
/// </summary>
internal sealed class SessionStore(WincheAuthDbContext db, WincheAuthOptions options, TimeProvider time)
{
    private static readonly TimeSpan RaceGrace = TimeSpan.FromSeconds(10);

    public async Task<string> CreateAsync(string userId, string provider, DateTimeOffset authTime, AuthRequestInfo info, CancellationToken ct, string? secondFactor = null,
        string? providerSessionId = null)
    {
        var now = time.GetUtcNow();
        var (secret, hash) = NewSecret();
        var session = new AuthSession
        {
            Id = Guid.NewGuid(), UserId = userId, Provider = provider, SecondFactor = secondFactor, ProviderSessionId = Truncate(providerSessionId, 256),
            TokenHash = hash, CreatedAt = now, AuthTime = authTime,
            LastUsedAt = now, ExpiresAt = now + options.RefreshTokenLifetime,
            UserAgent = Truncate(info.UserAgent, 300), IpAddress = Truncate(info.IpAddress, 64),
        };
        db.Sessions.Add(session);
        await db.SaveChangesAsync(ct);
        return Format(session.Id, secret);
    }

    /// <summary>
    /// Ends the sessions a provider's sign-out names: the one from its session <paramref name="sid"/>, or every session of
    /// <paramref name="userId"/> that came through it. How many ended.
    /// </summary>
    public async Task<int> EndProviderSessionsAsync(string provider, string? sid, string? userId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var open = db.Sessions.Where(s => s.Provider == provider && s.RevokedAt == null);
        open = sid is not null ? open.Where(s => s.ProviderSessionId == sid) : open.Where(s => s.UserId == userId);
        return await open.ExecuteUpdateAsync(u => u.SetProperty(s => s.RevokedAt, now).SetProperty(s => s.RevokedReason, "signed out at the provider"), ct);
    }

    /// <summary>The session for a refresh token, with a new token in its place; throws INVALID_REFRESH_TOKEN.</summary>
    public async Task<(AuthSession Session, string RefreshToken)> RotateAsync(string refreshToken, AuthRequestInfo info, CancellationToken ct)
    {
        var (id, presented) = Parse(refreshToken);
        var session = await db.Sessions.FirstOrDefaultAsync(s => s.Id == id, ct) ?? throw Invalid();
        var now = time.GetUtcNow();
        if (session.RevokedAt is not null || session.ExpiresAt <= now) throw Invalid();
        var hash = SHA256.HashData(presented);
        if (!CryptographicOperations.FixedTimeEquals(hash, session.TokenHash))
        {
            if (session.PreviousTokenHash is { } previous && CryptographicOperations.FixedTimeEquals(hash, previous) && now - session.LastUsedAt > RaceGrace)
            {
                session.RevokedAt = now;
                session.RevokedReason = "refresh token reused";
                await db.SaveChangesAsync(ct);
            }
            throw Invalid();
        }

        var (secret, newHash) = NewSecret();
        // Only if nobody rotated it meanwhile: a concurrent refresh wins, this one is refused.
        var updated = await db.Sessions
            .Where(s => s.Id == id && s.TokenHash == session.TokenHash && s.RevokedAt == null)
            .ExecuteUpdateAsync(u => u
                .SetProperty(s => s.PreviousTokenHash, session.TokenHash)
                .SetProperty(s => s.TokenHash, newHash)
                .SetProperty(s => s.LastUsedAt, now)
                .SetProperty(s => s.ExpiresAt, now + options.RefreshTokenLifetime)
                .SetProperty(s => s.IpAddress, Truncate(info.IpAddress, 64) ?? session.IpAddress), ct);
        if (updated == 0) throw Invalid();
        return (session, Format(id, secret));
    }

    /// <summary>Ends the session a refresh token belongs to (its current or previous token).</summary>
    public async Task<bool> RevokeByTokenAsync(string refreshToken, CancellationToken ct)
    {
        Guid id;
        byte[] presented;
        try { (id, presented) = Parse(refreshToken); }
        catch (AuthException) { return false; }
        var session = await db.Sessions.FirstOrDefaultAsync(s => s.Id == id && s.RevokedAt == null, ct);
        if (session is null) return false;
        var hash = SHA256.HashData(presented);
        if (!CryptographicOperations.FixedTimeEquals(hash, session.TokenHash)
            && !(session.PreviousTokenHash is { } p && CryptographicOperations.FixedTimeEquals(hash, p))) return false;
        session.RevokedAt = time.GetUtcNow();
        session.RevokedReason = "signed out";
        await db.SaveChangesAsync(ct);
        return true;
    }

    public Task<int> RevokeAllAsync(string userId, string reason, CancellationToken ct, Guid? except = null)
    {
        var now = time.GetUtcNow();
        return db.Sessions.Where(s => s.UserId == userId && s.RevokedAt == null && s.Id != except)
            .ExecuteUpdateAsync(u => u.SetProperty(s => s.RevokedAt, now).SetProperty(s => s.RevokedReason, reason), ct);
    }

    public async Task<bool> RevokeAsync(string userId, Guid sessionId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        return await db.Sessions.Where(s => s.Id == sessionId && s.UserId == userId && s.RevokedAt == null)
            .ExecuteUpdateAsync(u => u.SetProperty(s => s.RevokedAt, now).SetProperty(s => s.RevokedReason, "revoked"), ct) > 0;
    }

    /// <summary>Whether <paramref name="sessionId"/> of <paramref name="userId"/> still stands (not ended, not expired).</summary>
    public Task<bool> IsActiveAsync(string userId, Guid sessionId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        return db.Sessions.AsNoTracking().AnyAsync(s => s.Id == sessionId && s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now, ct);
    }

    public async Task<IReadOnlyList<SessionInfo>> ActiveAsync(string userId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        return await db.Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
            .OrderByDescending(s => s.LastUsedAt)
            .Select(s => new SessionInfo(s.Id, s.Provider, s.CreatedAt, s.LastUsedAt, s.ExpiresAt, s.UserAgent, s.IpAddress))
            .ToListAsync(ct);
    }

    /// <summary>Deletes sessions that ended or expired over a day ago.</summary>
    public Task<int> PruneAsync(CancellationToken ct)
    {
        var cutoff = time.GetUtcNow().AddDays(-1);
        return db.Sessions.Where(s => s.ExpiresAt < cutoff || s.RevokedAt < cutoff).ExecuteDeleteAsync(ct);
    }

    private static (byte[] Secret, byte[] Hash) NewSecret()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        return (secret, SHA256.HashData(secret));
    }

    private static string Format(Guid id, byte[] secret) => $"{Base64UrlEncoder.Encode(id.ToByteArray())}.{Base64UrlEncoder.Encode(secret)}";

    /// <summary>The session a refresh token belongs to, or null if it isn't one.</summary>
    internal static Guid? IdOf(string refreshToken)
    {
        try { return Parse(refreshToken).Id; }
        catch (Exception) { return null; }
    }

    private static (Guid Id, byte[] Secret) Parse(string token)
    {
        var dot = token.IndexOf('.');
        if (dot <= 0) throw Invalid();
        try
        {
            var id = Base64UrlEncoder.DecodeBytes(token[..dot]);
            var secret = Base64UrlEncoder.DecodeBytes(token[(dot + 1)..]);
            if (id.Length != 16 || secret.Length != 32) throw Invalid();
            return (new Guid(id), secret);
        }
        catch (FormatException) { throw Invalid(); }
        catch (ArgumentException) { throw Invalid(); }
    }

    private static AuthException Invalid() =>
        new(AuthErrorCodes.InvalidRefreshToken, "The session has ended or the refresh token isn't valid. Sign in again.");

    private static string? Truncate(string? s, int max) => s is null ? null : s.Length <= max ? s : s[..max];
}
