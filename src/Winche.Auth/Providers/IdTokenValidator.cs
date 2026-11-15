using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Winche.Auth.Providers;

/// <summary>Who an ID token says the user is, once its signature, issuer, audience and expiry check out.</summary>
public sealed record IdTokenIdentity(string Provider, string Subject, string? Email, bool EmailVerified, string? Name, string? Picture,
    IReadOnlyDictionary<string, object?> Claims)
{
    /// <summary>The second step the provider says it checked (an <c>amr</c> value like "otp", or "acr:2"); null: none.</summary>
    public string? SecondStep { get; init; }
}

/// <summary>Checks providers' ID tokens; keys come from each provider's discovery document (cached, refreshed by the library).</summary>
internal sealed class IdTokenValidator(TimeProvider time)
{
    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _metadata = new();

    public async Task<IdTokenIdentity> ValidateAsync(IdentityProviderOptions provider, string idToken, string? nonce, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(idToken) || idToken.Length > 16_000) throw Invalid("No ID token was sent.");
        var handler = new JsonWebTokenHandler();
        JsonWebToken jwt;
        if (provider.AllowUnsignedTokensForTesting && IsUnsigned(idToken))
        {
            jwt = handler.ReadJsonWebToken(idToken);
            var now = time.GetUtcNow().UtcDateTime;
            if (!provider.EffectiveIssuers.Contains(jwt.Issuer)) throw Invalid("The token isn't from this provider.");
            if (!jwt.Audiences.Any(provider.Audiences.Contains)) throw Invalid("The token isn't for this app.");
            if (jwt.ValidTo != DateTime.MinValue && jwt.ValidTo < now) throw Invalid("The token has expired.");
        }
        else
        {
            var parameters = new TokenValidationParameters
            {
                ValidIssuers = provider.EffectiveIssuers,
                ValidAudiences = provider.Audiences,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.FromMinutes(1),
            };
            if (provider.SigningKeys is { } keys) parameters.IssuerSigningKeys = keys;
            else parameters.ConfigurationManager = _metadata.GetOrAdd(provider.Name, _ => new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{provider.Authority.TrimEnd('/')}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = provider.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase) }));
            var result = await handler.ValidateTokenAsync(idToken, parameters);
            if (!result.IsValid || result.SecurityToken is not JsonWebToken valid)
                throw Invalid(result.Exception switch
                {
                    SecurityTokenExpiredException => "The token has expired: sign in with the provider again.",
                    SecurityTokenInvalidAudienceException => "The token isn't for this app.",
                    SecurityTokenInvalidIssuerException => "The token isn't from this provider.",
                    _ => "The token couldn't be checked.",
                });
            jwt = valid;
        }

        var claims = Payload(jwt);
        if (nonce is { Length: > 0 })
        {
            // Google puts the nonce as sent; Apple its SHA-256 (hex).
            var sent = claims.GetValueOrDefault("nonce") as string;
            var hashed = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(nonce)));
            if (sent != nonce && sent != hashed) throw Invalid("The token's nonce doesn't match.");
        }
        if (claims.GetValueOrDefault("sub") is not string sub || sub.Length == 0) throw Invalid("The token has no subject.");
        var email = claims.GetValueOrDefault("email") as string;
        var verified = claims.GetValueOrDefault("email_verified") switch
        {
            bool b => b,
            string s => string.Equals(s, "true", StringComparison.OrdinalIgnoreCase),   // Apple sends a string
            _ => false,
        };
        // Apple's relay addresses are real, verified mailboxes.
        var name = claims.GetValueOrDefault("name") as string
            ?? string.Join(' ', new[] { claims.GetValueOrDefault("given_name") as string, claims.GetValueOrDefault("family_name") as string }.Where(n => !string.IsNullOrEmpty(n)));
        return new IdTokenIdentity(provider.Name, sub, email, email is not null && verified, string.IsNullOrWhiteSpace(name) ? null : name,
            claims.GetValueOrDefault("picture") as string, claims) { SecondStep = SecondStepOf(provider, claims) ?? (provider.CountsAsSecondStep ? "provider" : null) };
    }

    /// <summary>
    /// A back-channel logout token (OpenID Connect Back-Channel Logout): signed by the provider, for this app, recent, about a
    /// sign-out, with no nonce. Its session (<c>sid</c>) and/or person (<c>sub</c>).
    /// </summary>
    public async Task<(string? Sid, string? Subject)> ValidateLogoutTokenAsync(IdentityProviderOptions provider, string logoutToken, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(logoutToken) || logoutToken.Length > 16_000) throw Invalid("No logout token was sent.");
        var handler = new JsonWebTokenHandler();
        JsonWebToken jwt;
        if (provider.AllowUnsignedTokensForTesting && IsUnsigned(logoutToken))
        {
            jwt = handler.ReadJsonWebToken(logoutToken);
            if (!provider.EffectiveIssuers.Contains(jwt.Issuer)) throw Invalid("The token isn't from this provider.");
            if (!jwt.Audiences.Any(provider.Audiences.Contains)) throw Invalid("The token isn't for this app.");
        }
        else
        {
            var parameters = new TokenValidationParameters
            {
                ValidIssuers = provider.EffectiveIssuers, ValidAudiences = provider.Audiences,
                RequireExpirationTime = false, ValidateLifetime = false,   // logout tokens may carry no exp: iat is checked below
            };
            if (provider.SigningKeys is { } keys) parameters.IssuerSigningKeys = keys;
            else parameters.ConfigurationManager = _metadata.GetOrAdd(provider.Name, _ => new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{provider.Authority.TrimEnd('/')}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = provider.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase) }));
            var result = await handler.ValidateTokenAsync(logoutToken, parameters);
            if (!result.IsValid || result.SecurityToken is not JsonWebToken valid) throw Invalid("The logout token couldn't be checked.");
            jwt = valid;
        }
        var claims = Payload(jwt);
        if (claims.GetValueOrDefault("events") is not IReadOnlyDictionary<string, object?> events
            || !events.ContainsKey("http://schemas.openid.net/event/backchannel-logout"))
            throw Invalid("The token isn't a logout token.");
        if (claims.ContainsKey("nonce")) throw Invalid("A logout token has no nonce.");
        var now = time.GetUtcNow().UtcDateTime;
        if (jwt.IssuedAt < now.AddMinutes(-10) || jwt.IssuedAt > now.AddMinutes(5)) throw Invalid("The logout token is too old.");
        var sid = claims.GetValueOrDefault("sid") as string;
        var sub = claims.GetValueOrDefault("sub") as string;
        if (string.IsNullOrEmpty(sid) && string.IsNullOrEmpty(sub)) throw Invalid("The logout token names no session or person.");
        return (string.IsNullOrEmpty(sid) ? null : sid, string.IsNullOrEmpty(sub) ? null : sub);
    }

    /// <summary>Authentication methods (RFC 8176) that are a second step, or count as one on their own.</summary>
    private static readonly HashSet<string> SecondStepMethods = new(StringComparer.OrdinalIgnoreCase)
        { "mfa", "otp", "sms", "tel", "hwk", "sc", "fpt", "face", "iris", "retina", "vbm" };

    /// <summary>The second step the token says the provider checked: from <c>amr</c>, else the provider's <c>acr</c> values.</summary>
    internal static string? SecondStepOf(IdentityProviderOptions provider, IReadOnlyDictionary<string, object?> claims)
    {
        var amr = claims.GetValueOrDefault("amr") switch
        {
            string s => [s],
            IEnumerable<object?> list => list.OfType<string>(),
            _ => [],
        };
        if (amr.FirstOrDefault(SecondStepMethods.Contains) is { } method) return method.ToLowerInvariant();
        if (claims.GetValueOrDefault("acr") is string acr && provider.SecondStepAcrValues.Contains(acr)) return $"acr:{acr}";
        return null;
    }

    private static bool IsUnsigned(string token) =>
        token.Split('.') is { Length: 3 } parts && parts[2].Length == 0 && Header(parts[0]) is "none";

    private static string? Header(string encoded)
    {
        try
        {
            using var doc = JsonDocument.Parse(Base64UrlEncoder.Decode(encoded));
            return doc.RootElement.TryGetProperty("alg", out var alg) ? alg.GetString() : null;
        }
        catch (Exception) { return null; }
    }

    private static Dictionary<string, object?> Payload(JsonWebToken jwt)
    {
        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload)));
        return doc.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => Tokens.CustomClaims.Convert(p.Value), StringComparer.Ordinal);
    }

    private static AuthException Invalid(string message) => new(AuthErrorCodes.InvalidIdToken, message);
}
