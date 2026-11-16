using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.Data;

namespace Winche.Auth.Tokens;

/// <summary>
/// The ES256 keys that sign Winche tokens, kept encrypted in <c>auth_signing_keys</c> and cached. One key signs. The
/// next is made <see cref="WincheAuthOptions.KeyPublishAhead"/> before the active one is
/// <see cref="WincheAuthOptions.KeyRotationInterval"/> old and published straight away, so whoever caches the key set
/// knows it before it signs anything; the retired one keeps checking the tokens it signed until they've expired. Every
/// instance reads the same keys, and only one changes them at a time (a Postgres advisory lock).
/// </summary>
public sealed class SigningKeyStore
{
    private readonly IDbContextFactory<WincheAuthDbContext> contexts;
    private readonly WincheAuthOptions options;
    private readonly TimeProvider time;
    private readonly ILogger<SigningKeyStore> logger;
    private readonly Winche.Core.WincheKeys? masterKeys;

    internal SigningKeyStore(IDbContextFactory<WincheAuthDbContext> contexts, WincheAuthOptions options, TimeProvider time,
        ILogger<SigningKeyStore> logger, Winche.Core.WincheKeys? masterKeys = null)
    {
        this.contexts = contexts;
        this.options = options;
        this.time = time;
        this.logger = logger;
        this.masterKeys = masterKeys;
    }

    /// <summary>
    /// What encrypts the signing keys: <see cref="WincheAuthOptions.KeyEncryptionSecret"/>, else the key Winche.Core
    /// derives from the project's master key for <c>auth-signing-keys</c>.
    /// </summary>
    private string? Secret => options.KeyEncryptionSecret ?? masterKeys?.TryDerive("auth-signing-keys");

    internal sealed record CachedKey(string Kid, ECDsaSecurityKey Key, DateTimeOffset CreatedAt, DateTimeOffset? RetiredAt);

    private volatile IReadOnlyList<CachedKey> _keys = [];
    private DateTimeOffset _loadedAt = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private static readonly TimeSpan CacheFor = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan MissReloadAfter = TimeSpan.FromSeconds(10);

    private TimeSpan PublishAhead =>
        options.KeyPublishAhead < options.KeyRotationInterval / 2 ? options.KeyPublishAhead : options.KeyRotationInterval / 2;

    /// <summary>The key new tokens are signed with, making or rotating one when needed.</summary>
    public async Task<SigningCredentials> SigningCredentialsAsync(CancellationToken ct = default)
    {
        var now = time.GetUtcNow();
        if (now - _loadedAt > CacheFor) await LoadAsync(ct);
        if (Active(_keys, now) is null || NextDue(_keys, now)) await EnsureAsync(force: false, ct);
        var active = Active(_keys, now) ?? throw new InvalidOperationException("Winche Auth: no signing key.");
        return new SigningCredentials(active.Key, SecurityAlgorithms.EcdsaSha256);
    }

    /// <summary>
    /// Makes sure the key that signed a token is known: reloads once when <paramref name="kid"/> is new to this
    /// instance (another may have just made it). Call before checking a token with <see cref="ValidationKeys"/>.
    /// </summary>
    public async Task KnowAsync(string? kid, CancellationToken ct = default)
    {
        var now = time.GetUtcNow();
        if (now - _loadedAt > CacheFor || (kid is not null && _keys.All(k => k.Kid != kid) && now - _loadedAt > MissReloadAfter))
            await LoadAsync(ct);
    }

    /// <summary>The public keys that check tokens, for the token handler (from the cache: see <see cref="KnowAsync"/>).</summary>
    public IEnumerable<SecurityKey> ValidationKeys(string? kid)
    {
        var keys = _keys;
        return kid is null ? keys.Select(k => (SecurityKey)k.Key) : keys.Where(k => k.Kid == kid).Select(k => (SecurityKey)k.Key);
    }

    /// <summary>The public keys as a JWKS document (<c>/.well-known/jwks.json</c>): the next key too, before it signs.</summary>
    public async Task<object> JwksAsync(CancellationToken ct = default)
    {
        if (time.GetUtcNow() - _loadedAt > CacheFor) await LoadAsync(ct);
        return new
        {
            keys = _keys.Select(k =>
            {
                var p = k.Key.ECDsa.ExportParameters(false);
                return new Dictionary<string, string>
                {
                    ["kty"] = "EC", ["crv"] = "P-256", ["alg"] = "ES256", ["use"] = "sig", ["kid"] = k.Kid,
                    ["x"] = Base64UrlEncoder.Encode(p.Q.X), ["y"] = Base64UrlEncoder.Encode(p.Q.Y),
                };
            }).ToArray(),
        };
    }

    /// <summary>The keys and their state, newest first, for the console.</summary>
    public async Task<IReadOnlyList<(string Kid, DateTimeOffset CreatedAt, DateTimeOffset? RetiredAt)>> ListAsync(CancellationToken ct = default)
    {
        await LoadAsync(ct);
        return [.. _keys.OrderByDescending(k => k.CreatedAt).Select(k => (k.Kid, k.CreatedAt, k.RetiredAt))];
    }

    /// <summary>
    /// Makes a new signing key that signs from now on; every other one retires (still checking the tokens it signed).
    /// For a key that may have leaked: services caching the key set may refuse new tokens until they refetch it.
    /// </summary>
    public Task RotateAsync(CancellationToken ct = default) => EnsureAsync(force: true, ct);

    /// <summary>
    /// The key that signs: the newest unretired one that's been published for <see cref="PublishAhead"/>, else (just
    /// after a forced rotation or the very first key) the newest unretired one.
    /// </summary>
    private CachedKey? Active(IReadOnlyList<CachedKey> keys, DateTimeOffset now)
    {
        var live = keys.Where(k => k.RetiredAt is null).OrderByDescending(k => k.CreatedAt).ToList();
        return live.FirstOrDefault(k => now - k.CreatedAt >= PublishAhead) ?? live.FirstOrDefault();
    }

    /// <summary>Whether it's time to publish the next key: the newest one is due for replacement within <see cref="PublishAhead"/>.</summary>
    private bool NextDue(IReadOnlyList<CachedKey> keys, DateTimeOffset now) =>
        keys.Where(k => k.RetiredAt is null).MaxBy(k => k.CreatedAt) is not { } newest
        || now - newest.CreatedAt >= options.KeyRotationInterval - PublishAhead;

    /// <summary>
    /// Brings the keys up to date under a cluster-wide lock: makes the first or the next key (or, with
    /// <paramref name="force"/>, one that signs at once), retires the ones the active key replaced, deletes those no
    /// token can need any more, and encrypts any left unencrypted by an older version.
    /// </summary>
    internal async Task EnsureAsync(bool force, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            await using var db = await contexts.CreateDbContextAsync(ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(hashtext('winche-auth-signing-keys'))", ct);
            var now = time.GetUtcNow();
            var all = await db.SigningKeys.ToListAsync(ct);
            var live = all.Where(k => k.RetiredAt is null).ToList();
            if (force)
            {
                foreach (var k in live) k.RetiredAt = now;
                Add(db, all, now);
            }
            else if (live.MaxBy(k => k.CreatedAt) is not { } newest || now - newest.CreatedAt >= options.KeyRotationInterval - PublishAhead)
            {
                Add(db, all, now);
            }
            // Keys older than the one that signs are done signing.
            if (Active(Build(all), now) is { } active)
                foreach (var k in all.Where(k => k.RetiredAt is null && k.Kid != active.Kid && k.CreatedAt < active.CreatedAt)) k.RetiredAt = now;
            // Retired keys go once no token they signed can still be valid.
            var keepFor = options.AccessTokenLifetime + TimeSpan.FromDays(1);
            foreach (var k in all.Where(k => k.RetiredAt is { } r && now - r > keepFor).ToList())
            {
                db.SigningKeys.Remove(k);
                all.Remove(k);
            }
            // After a master key change: keys under a previous master key move to the current one.
            foreach (var k in all.Where(k => k.Encrypted && TryDecrypt(EncryptionKey(), k.PrivateKey) is null))
            {
                k.PrivateKey = Encrypt(Decrypt(k.PrivateKey));
                logger.LogInformation("Re-encrypted token signing key {Kid} with the current master key.", k.Kid);
            }
            foreach (var k in all.Where(k => !k.Encrypted))
            {
                k.PrivateKey = Encrypt(k.PrivateKey);
                k.Encrypted = true;
                logger.LogInformation("Encrypted token signing key {Kid}, stored unencrypted by an older version.", k.Kid);
            }
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            Cache(all, now);
        }
        finally
        {
            _lock.Release();
        }
    }

    private void Add(WincheAuthDbContext db, List<AuthSigningKey> all, DateTimeOffset now)
    {
        var fresh = NewKey(now);
        db.SigningKeys.Add(fresh);
        all.Add(fresh);
        logger.LogInformation("Made a new token signing key {Kid}.", fresh.Kid);
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        await using var db = await contexts.CreateDbContextAsync(ct);
        var all = await db.SigningKeys.AsNoTracking().ToListAsync(ct);
        Cache(all, time.GetUtcNow());
    }

    private void Cache(List<AuthSigningKey> all, DateTimeOffset now)
    {
        _keys = Build(all);
        _loadedAt = now;
    }

    /// <summary><paramref name="all"/> as cached keys, reusing those already loaded (a key never changes, only its retirement).</summary>
    private List<CachedKey> Build(List<AuthSigningKey> all)
    {
        var loaded = _keys.ToDictionary(k => k.Kid);
        return [.. all.Select(k => loaded.TryGetValue(k.Kid, out var known)
            ? known with { RetiredAt = k.RetiredAt }
            : new CachedKey(k.Kid, Import(k), k.CreatedAt, k.RetiredAt))];
    }

    private ECDsaSecurityKey Import(AuthSigningKey k)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(k.Encrypted ? Decrypt(k.PrivateKey) : k.PrivateKey, out _);
        return new ECDsaSecurityKey(ecdsa) { KeyId = k.Kid };
    }

    private AuthSigningKey NewKey(DateTimeOffset now)
    {
        // PostgreSQL keeps microseconds: the time cached here must be the one read back, or the key looks older than itself.
        now = now.AddTicks(-(now.Ticks % TimeSpan.TicksPerMicrosecond));
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new AuthSigningKey
        {
            Kid = $"k-{now:yyyyMMdd}-{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(3))}",
            Algorithm = "ES256",
            PrivateKey = Encrypt(ecdsa.ExportPkcs8PrivateKey()),
            Encrypted = true,
            CreatedAt = now,
        };
    }

    private byte[] EncryptionKey() => KeyFrom(Secret
        ?? throw new InvalidOperationException(
            "Winche Auth: signing keys are stored encrypted: set KeyEncryptionSecret (32+ characters), or a Winche master key with AddWincheConfig."));

    private static byte[] KeyFrom(string secret) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(secret), 32, Encoding.UTF8.GetBytes("winche-auth-signing-keys"));

    /// <summary>The current key, then (when it comes from the master key) those of previous master keys.</summary>
    private IEnumerable<byte[]> DecryptionKeys()
    {
        yield return EncryptionKey();
        if (options.KeyEncryptionSecret is null && masterKeys is not null)
            foreach (var previous in masterKeys.DerivePrevious("auth-signing-keys")) yield return KeyFrom(previous);
    }

    private static byte[]? TryDecrypt(byte[] key, byte[] stored)
    {
        using var aes = new AesGcm(key, 16);
        var plain = new byte[stored.Length - 28];
        try { aes.Decrypt(stored.AsSpan(0, 12), stored.AsSpan(28), stored.AsSpan(12, 16), plain); }
        catch (AuthenticationTagMismatchException) { return null; }
        return plain;
    }

    private byte[] Encrypt(byte[] plain)
    {
        using var aes = new AesGcm(EncryptionKey(), 16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[plain.Length];
        aes.Encrypt(nonce, plain, cipher, tag);
        return [.. nonce, .. tag, .. cipher];
    }

    private byte[] Decrypt(byte[] stored) =>
        DecryptionKeys().Select(k => TryDecrypt(k, stored)).FirstOrDefault(p => p is not null)
        ?? throw new CryptographicException("Winche Auth: a token signing key can't be read with this key: was the master key changed? Set the old one as a previous master key.");
}
