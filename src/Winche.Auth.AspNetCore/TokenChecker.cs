using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.Tokens;

namespace Winche.Auth.AspNetCore;

/// <summary>The outcome of checking one token against the trusted providers.</summary>
internal sealed record CheckedToken(
    bool Valid, string? Error, string? Provider, string? ProviderLabel, JsonWebToken? Jwt,
    Dictionary<string, object?>? Claims, IReadOnlyList<string> NotPassed);

/// <summary>Checks tokens for the authentication handler and the console's token test: one implementation of the rules.</summary>
internal sealed class TokenChecker(IServiceProvider services, WincheTokenProviders providers)
{
    private TimeProvider Clock => services.GetService<TimeProvider>() ?? TimeProvider.System;

    /// <summary>Token lifetimes on the app's clock (the one tokens are issued by), with 30 seconds' leeway.</summary>
    private bool OnClock(DateTime? notBefore, DateTime? expires, SecurityToken _, TokenValidationParameters parameters)
    {
        if (!parameters.ValidateLifetime) return true;
        var now = Clock.GetUtcNow().UtcDateTime;
        var skew = TimeSpan.FromSeconds(30);
        return (notBefore is null || notBefore <= now + skew) && (expires is null || expires > now - skew);
    }

    private static readonly HashSet<string> AlwaysKept = new(StringComparer.Ordinal) { "sub", "iss", "exp", "iat", "auth_time", "email", "email_verified", "name" };

    /// <summary>Claims only Winche sets: never taken from an outside token, by default or by a mapping.</summary>
    internal static readonly HashSet<string> WincheOnly = new(StringComparer.Ordinal) { "uid", "issuer", "provider", "anonymous", "mfa", "sid" };
    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _metadata = new();

    public async Task<CheckedToken> CheckAsync(string raw, IdentityProvidersSettings settings, bool ownOnly, bool ignoreLifetime, CancellationToken ct)
    {
        var handler = new JsonWebTokenHandler();
        if (!handler.CanReadToken(raw)) return Fail("That isn't a token: a token is three parts separated by dots.");
        JsonWebToken unverified;
        try { unverified = handler.ReadJsonWebToken(raw); }
        catch (Exception) { return Fail("That token can't be read."); }
        var iss = unverified.Issuer;

        // Winche Auth's own tokens.
        if (settings.TrustWincheAuth && services.GetService<WincheAuthOptions>() is { } own && SameIssuer(own.Issuer, iss))
        {
            var keys = services.GetRequiredService<SigningKeyStore>();
            await keys.KnowAsync(unverified.Kid);
            var result = await handler.ValidateTokenAsync(raw, new TokenValidationParameters
            {
                ValidIssuer = own.Issuer,
                ValidAudience = string.IsNullOrEmpty(own.Audience) ? own.Issuer : own.Audience,
                ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
                IssuerSigningKeyResolver = (_, _, kid, _) => keys.ValidationKeys(kid),
                ValidateLifetime = !ignoreLifetime,
                ClockSkew = TimeSpan.FromSeconds(30),
                LifetimeValidator = OnClock,
            });
            if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt) return Fail(Describe(result.Exception));
            var claims = Payload(jwt);
            if (claims.GetValueOrDefault("uid") is not string uid || uid.Length == 0) return Fail("The token has no uid.");
            claims["issuer"] = WincheAuthDefaults.WincheIssuerName;
            return new CheckedToken(true, null, WincheAuthDefaults.WincheIssuerName, "Winche Auth", jwt, claims, []);
        }
        if (ownOnly) return Fail("That isn't a Winche Auth token.");

        var provider = settings.Providers.FirstOrDefault(p => SameIssuer(p.Issuer, iss));
        if (provider is null)
            return Fail(string.IsNullOrEmpty(iss) ? "The token doesn't say who issued it." : $"Tokens from {iss} aren't trusted: add it under Identity providers.");

        var parameters = new TokenValidationParameters
        {
            ValidIssuers = [provider.Issuer, provider.Issuer.TrimEnd('/'), provider.Issuer.TrimEnd('/') + "/"],
            ValidAudiences = provider.Audiences,
            ValidateAudience = provider.ValidateAudience,
            ValidateLifetime = !ignoreLifetime,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            LifetimeValidator = OnClock,
        };
        if (providers.CodeSigningKeys.GetValueOrDefault(provider.Name) is { } codeKeys) parameters.IssuerSigningKeys = codeKeys;
        else parameters.ConfigurationManager = Metadata(provider);

        var checkedResult = await handler.ValidateTokenAsync(raw, parameters);
        if (!checkedResult.IsValid || checkedResult.SecurityToken is not JsonWebToken valid) return Fail(Describe(checkedResult.Exception), provider);

        var payload = Payload(valid);
        if (Resolve(payload, provider.UidClaim) is not { } uidValue || uidValue.ToString() is not { Length: > 0 } uidText)
            return Fail($"The token has no '{provider.UidClaim}' field for the user's id.", provider);

        Dictionary<string, object?> mapped;
        var notPassed = new List<string>();
        // Everything passed on, except what Winche sets itself: an outside token mustn't pass for a Winche one (mfa,
        // anonymous, provider, sid) or name its own uid or issuer.
        if (provider.Claims is null)
            mapped = payload.Where(kv => !WincheOnly.Contains(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
        else
        {
            mapped = payload.Where(kv => AlwaysKept.Contains(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
            var used = new HashSet<string>(provider.Claims.SelectMany(m => m.From.Split('+').Select(f => f.Trim().Split('.')[0])), StringComparer.Ordinal);
            foreach (var m in provider.Claims)
                if (!WincheOnly.Contains(m.To) && Resolve(payload, m.From) is { } v) mapped[m.To] = v;
            notPassed.AddRange(payload.Keys.Where(k => !AlwaysKept.Contains(k) && !used.Contains(k) && k is not ("aud" or "nbf" or "jti" or "typ" or "azp" or "sid" or "session_state" or "acr" or "nonce" or "at_hash" or "scope")));
        }
        mapped["uid"] = uidText;
        mapped["issuer"] = provider.Name;
        return new CheckedToken(true, null, provider.Name, provider.DisplayName ?? provider.Name, valid, mapped, notPassed);
    }

    /// <summary>A field by path: <c>realm_access.roles</c>; or several joined with spaces: <c>given_name + family_name</c>.</summary>
    internal static object? Resolve(IReadOnlyDictionary<string, object?> payload, string path)
    {
        if (path.Contains('+'))
        {
            var parts = path.Split('+').Select(p => Resolve(payload, p.Trim())?.ToString()).Where(s => !string.IsNullOrEmpty(s)).ToList();
            return parts.Count == 0 ? null : string.Join(' ', parts);
        }
        object? current = payload;
        foreach (var segment in path.Trim().Split('.'))
        {
            if (current is not IReadOnlyDictionary<string, object?> map || !map.TryGetValue(segment, out current)) return null;
        }
        return current;
    }

    internal ConfigurationManager<OpenIdConnectConfiguration> Metadata(TrustedProviderSettings provider)
    {
        var authority = (provider.Authority is { Length: > 0 } a ? a : provider.Issuer).TrimEnd('/');
        return _metadata.GetOrAdd($"{authority}|{provider.RequireHttps}", _ => new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever { RequireHttps = provider.RequireHttps }));
    }

    internal static Dictionary<string, object?> Payload(JsonWebToken jwt)
    {
        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload)));
        return doc.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => ToReadOnly(CustomClaims.Convert(p.Value)), StringComparer.Ordinal);
    }

    /// <summary>Nested objects as read-only dictionaries, so paths can walk them.</summary>
    private static object? ToReadOnly(object? v) => v switch
    {
        Dictionary<string, object?> d => d.ToDictionary(kv => kv.Key, kv => ToReadOnly(kv.Value), StringComparer.Ordinal),
        List<object?> l => l.Select(ToReadOnly).ToList(),
        _ => v,
    };

    internal static bool SameIssuer(string a, string? b) => b is not null && string.Equals(a.TrimEnd('/'), b.TrimEnd('/'), StringComparison.Ordinal);

    private static string Describe(Exception? ex) => ex switch
    {
        SecurityTokenExpiredException => "The token has expired.",
        SecurityTokenInvalidAudienceException => "The token is for another app (its audience doesn't match).",
        SecurityTokenInvalidIssuerException => "The token's issuer doesn't match.",
        SecurityTokenSignatureKeyNotFoundException or SecurityTokenInvalidSignatureException => "The signature doesn't match the provider's keys.",
        SecurityTokenNotYetValidException => "The token isn't valid yet (is a clock wrong?).",
        null => "The token couldn't be checked.",
        _ when ex.InnerException is HttpRequestException or IOException || ex.Message.Contains("IDX20803", StringComparison.Ordinal)
            => "The provider's keys couldn't be fetched: is its address right and reachable?",
        _ => "The token couldn't be checked: " + ex.Message,
    };

    private static CheckedToken Fail(string error, TrustedProviderSettings? provider = null) =>
        new(false, error, provider?.Name, provider?.DisplayName ?? provider?.Name, null, null, []);
}
