using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.Data;

namespace Winche.Auth.Tokens;

/// <summary>Writes access tokens: ES256 JWTs carrying the uid, profile and custom claims.</summary>
internal sealed class TokenIssuer(SigningKeyStore keys, WincheAuthOptions options, TimeProvider time)
{
    /// <summary>Claim names Winche sets itself; custom claims can't use them.</summary>
    public static readonly HashSet<string> Reserved = new(StringComparer.Ordinal)
    {
        "iss", "aud", "sub", "uid", "exp", "iat", "nbf", "jti", "auth_time", "provider", "email", "email_verified", "name",
        "picture", "anonymous", "issuer", "mfa", "sid", "amr", "acr", "azp", "nonce", "at_hash", "c_hash",
    };

    public async Task<(string Token, DateTimeOffset ExpiresAt)> IssueAsync(WincheUser user, string provider, DateTimeOffset authTime, CancellationToken ct,
        bool mfa = false, Guid? session = null)
    {
        var now = time.GetUtcNow();
        var expires = now + options.AccessTokenLifetime;
        var claims = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var (k, v) in CustomClaims.Parse(user.CustomClaims))
            if (v is not null) claims[k] = v;
        claims["sub"] = user.Id;
        claims["uid"] = user.Id;
        claims["provider"] = provider;
        claims["auth_time"] = authTime.ToUnixTimeSeconds();
        if (user.IsAnonymous) claims["anonymous"] = true;
        if (mfa) claims["mfa"] = true;   // this session passed a second step
        if (session is { } sid) claims["sid"] = sid.ToString("N");   // its session, so it can be kept when others are ended
        if (user.Email is not null)
        {
            claims["email"] = user.Email;
            claims["email_verified"] = user.EmailConfirmed;
        }
        if (user.DisplayName is not null) claims["name"] = user.DisplayName;
        if (options.PhotoUrlOf(user) is { } picture) claims["picture"] = picture;

        var token = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,
            Audience = options.EffectiveAudience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            Claims = claims,
            SigningCredentials = await keys.SigningCredentialsAsync(ct),
        });
        return (token, expires);
    }

    /// <summary>The audience of custom tokens: never an access token's, so neither passes for the other.</summary>
    internal string CustomAudience => $"{options.Issuer.TrimEnd('/')}/auth/v1/signIn/custom";

    /// <summary>A token the app's server gives a client to sign in as <paramref name="uid"/> (signIn/custom).</summary>
    public async Task<string> CustomTokenAsync(string uid, TimeSpan lifetime, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,
            Audience = CustomAudience,
            TokenType = "winche-custom+jwt",
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = (now + lifetime).UtcDateTime,
            Claims = new Dictionary<string, object> { ["uid"] = uid, ["sub"] = uid },
            SigningCredentials = await keys.SigningCredentialsAsync(ct),
        });
    }

    /// <summary>The uid of a valid custom token, or null.</summary>
    public async Task<string?> ReadCustomTokenAsync(string token, CancellationToken ct)
    {
        var handler = new JsonWebTokenHandler();
        if (!handler.CanReadToken(token)) return null;
        await keys.KnowAsync(handler.ReadJsonWebToken(token).Kid, ct);
        var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = options.Issuer,
            ValidAudience = CustomAudience,
            ValidTypes = ["winche-custom+jwt"],
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            IssuerSigningKeyResolver = (_, _, kid, _) => keys.ValidationKeys(kid),
            LifetimeValidator = (nbf, exp, _, _) =>
            {
                var at = time.GetUtcNow().UtcDateTime;
                return (nbf is null || nbf <= at.AddSeconds(30)) && exp is { } e && e > at.AddSeconds(-30);
            },
        });
        return result.IsValid && result.Claims.TryGetValue("uid", out var uid) ? uid as string : null;
    }
}

/// <summary>Custom claims: a JSON object of strings, numbers, booleans, lists and objects, at most 1,000 bytes.</summary>
public static class CustomClaims
{
    public const int MaxBytes = 1000;

    public static IReadOnlyDictionary<string, object?> Parse(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new Dictionary<string, object?>();
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => Convert(p.Value), StringComparer.Ordinal);
    }

    /// <summary>The claims as stored JSON, or throws <see cref="AuthException"/> (INVALID_CLAIMS) when they can't be used.</summary>
    public static string? Serialize(IReadOnlyDictionary<string, object?>? claims)
    {
        if (claims is null || claims.Count == 0) return null;
        if (claims.Keys.FirstOrDefault(TokenIssuer.Reserved.Contains) is { } reserved)
            throw new AuthException(AuthErrorCodes.InvalidClaims, $"'{reserved}' is set by Winche and can't be a custom claim.");
        string json;
        try { json = JsonSerializer.Serialize(claims); }
        catch (Exception ex) when (ex is NotSupportedException or JsonException)
        {
            throw new AuthException(AuthErrorCodes.InvalidClaims, "Custom claims must be strings, numbers, booleans, lists or objects.");
        }
        if (System.Text.Encoding.UTF8.GetByteCount(json) > MaxBytes)
            throw new AuthException(AuthErrorCodes.InvalidClaims, $"Custom claims are limited to {MaxBytes} bytes of JSON.");
        return json;
    }

    internal static object? Convert(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.TryGetInt64(out var l) ? l : e.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Array => e.EnumerateArray().Select(Convert).ToList(),
        JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => Convert(p.Value), StringComparer.Ordinal),
        _ => null,
    };
}
