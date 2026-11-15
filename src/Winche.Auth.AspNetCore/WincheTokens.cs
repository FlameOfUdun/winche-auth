using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Winche.Core;

namespace Winche.Auth.AspNetCore;

public static class WincheAuthDefaults
{
    /// <summary>The scheme that accepts every trusted token, checked against the provider that issued it.</summary>
    public const string Scheme = "Winche";
    /// <summary>Only tokens issued by Winche Auth.</summary>
    public const string OwnScheme = "Winche.Auth";
    /// <summary>The <c>issuer</c> claim of tokens from Winche Auth.</summary>
    public const string WincheIssuerName = "winche";
    /// <summary>The settings area that holds the trusted providers and their mapping.</summary>
    public const string SettingsArea = "auth.identityProviders";
    internal const string ClaimsItem = "winche.claims";
}

/// <summary>Which tokens Database, Storage and your endpoints accept: the code's starting values.</summary>
public sealed class WincheTokenOptions
{
    internal bool Own { get; private set; }
    internal List<TrustedIssuer> Issuers { get; } = [];
    internal bool Managed { get; private set; }

    /// <summary>Accept tokens issued by Winche Auth (<c>AddWincheAuth</c>).</summary>
    public WincheTokenOptions TrustWincheAuth()
    {
        Own = true;
        return this;
    }

    /// <summary>
    /// Accept tokens from another identity provider (Keycloak, Auth0, Entra ID, …) as they are. The user's uid comes from
    /// <see cref="TrustedIssuer.UidClaim"/>; those users aren't Winche Auth users.
    /// </summary>
    public WincheTokenOptions TrustIssuer(string name, Action<TrustedIssuer> configure)
    {
        if (!IdentityProvidersSettings.NamePattern.IsMatch(name ?? "") || name == WincheAuthDefaults.WincheIssuerName)
            throw new ArgumentException("A trusted issuer's name is lower-case letters, digits, - and _.", nameof(name));
        if (Issuers.Any(i => i.Name == name)) throw new ArgumentException($"The issuer name '{name}' is taken.", nameof(name));
        var issuer = new TrustedIssuer { Name = name! };
        configure(issuer);
        issuer.Validate();
        Issuers.Add(issuer);
        return this;
    }

    /// <summary>
    /// Let the console (or anything using Winche.Core) change these: the providers and their mapping become the
    /// settings area <c>auth.identityProviders</c>, with the values above as its starting point. Applied live, no restart.
    /// Needs <c>AddWincheConfig</c>; without it, the values above simply apply.
    /// </summary>
    public WincheTokenOptions UseSettings()
    {
        Managed = true;
        return this;
    }

    internal IdentityProvidersSettings ToSettings() => new()
    {
        TrustWincheAuth = Own,
        Providers = [.. Issuers.Select(i => i.ToSettings())],
    };
}

/// <summary>An external identity provider whose tokens are accepted directly (in code; the console edits the same thing).</summary>
public sealed class TrustedIssuer
{
    public string Name { get; internal set; } = "";
    public string? DisplayName { get; set; }
    /// <summary>Its OpenID Connect address; keys come from its discovery document.</summary>
    public string? Authority { get; set; }
    /// <summary>The <c>iss</c> its tokens carry; the authority when not set.</summary>
    public string? Issuer { get; set; }
    /// <summary>The <c>aud</c> its tokens must carry. Required unless <see cref="ValidateAudience"/> is false.</summary>
    public string? Audience { get; set; }
    public bool ValidateAudience { get; set; } = true;
    /// <summary>The claim that becomes the uid (default <c>sub</c>).</summary>
    public string UidClaim { get; set; } = "sub";
    /// <summary>The fields passed to the rules besides uid, sub, email and name; null passes them all.</summary>
    public IReadOnlyList<ClaimMapping>? Claims { get; private set; }
    public bool RequireHttpsMetadata { get; set; } = true;
    /// <summary>Keys to check its tokens with instead of fetching them (tests, offline setups). Code only.</summary>
    public IReadOnlyList<SecurityKey>? SigningKeys { get; set; }

    /// <summary>Passes only these claims on, under the same names.</summary>
    public TrustedIssuer MapClaims(params string[] claims)
    {
        Claims = [.. claims.Select(c => new ClaimMapping(c, c))];
        return this;
    }

    /// <summary>Passes a field under another name: <c>Map("realm_access.roles", "roles")</c>.</summary>
    public TrustedIssuer Map(string from, string to)
    {
        if (TokenChecker.WincheOnly.Contains(to))
            throw new ArgumentException($"'{to}' is set by Winche itself; map the claim to another name.", nameof(to));
        Claims = [.. Claims ?? [], new ClaimMapping(from, to)];
        return this;
    }

    internal string EffectiveIssuer => (Issuer ?? Authority)!;

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Authority) && string.IsNullOrWhiteSpace(Issuer))
            throw new InvalidOperationException($"Trusted issuer '{Name}': set Authority (or Issuer with SigningKeys).");
        if (string.IsNullOrWhiteSpace(Authority) && SigningKeys is null)
            throw new InvalidOperationException($"Trusted issuer '{Name}': without an Authority, set SigningKeys.");
        if (ValidateAudience && string.IsNullOrWhiteSpace(Audience))
            throw new InvalidOperationException($"Trusted issuer '{Name}': set Audience, or ValidateAudience = false.");
    }

    internal TrustedProviderSettings ToSettings() => new()
    {
        Name = Name, DisplayName = DisplayName, Issuer = EffectiveIssuer, Authority = Authority,
        Audiences = Audience is null ? [] : [Audience], ValidateAudience = ValidateAudience, UidClaim = UidClaim,
        Claims = Claims is null ? null : [.. Claims], RequireHttps = RequireHttpsMetadata,
    };
}

/// <summary>The trusted providers in force: the console's saved version, or the code's.</summary>
public sealed class WincheTokenProviders
{
    private readonly IdentityProvidersSettings _code;

    internal WincheTokenProviders(IdentityProvidersSettings code, SettingsArea<IdentityProvidersSettings>? area,
        IReadOnlyDictionary<string, IReadOnlyList<SecurityKey>> codeKeys)
    {
        _code = code;
        Area = area;
        CodeSigningKeys = codeKeys;
    }

    public IdentityProvidersSettings Current => Area?.Current ?? _code;

    /// <summary>The settings area, when the console may change them (<c>UseSettings()</c>); null when they're code only.</summary>
    public SettingsArea<IdentityProvidersSettings>? Area { get; }

    internal IReadOnlyDictionary<string, IReadOnlyList<SecurityKey>> CodeSigningKeys { get; }
}

public sealed class WincheTokensSchemeOptions : AuthenticationSchemeOptions
{
    /// <summary>Only Winche Auth's own tokens.</summary>
    public bool OwnOnly { get; set; }
}

/// <summary>Reads the bearer token (or <c>access_token</c> for WebSockets), checks it against its provider, maps its claims.</summary>
internal sealed class WincheTokensHandler(
    IOptionsMonitor<WincheTokensSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, TokenChecker checker, WincheTokenProviders providers)
    : AuthenticationHandler<WincheTokensSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var raw = WincheTokensAuthenticationExtensions.TokenOf(Request);
        if (raw is null) return AuthenticateResult.NoResult();
        var result = await checker.CheckAsync(raw, providers.Current, Options.OwnOnly, ignoreLifetime: false, Context.RequestAborted);
        if (!result.Valid) return AuthenticateResult.Fail(result.Error ?? "The token isn't valid.");
        Context.Items[WincheAuthDefaults.ClaimsItem] = result.Claims;
        var identity = new ClaimsIdentity(Scheme.Name, "uid", "roles");
        foreach (var (key, value) in result.Claims!)
            foreach (var v in value is List<object?> list ? list : [value])
                if (v is not null) identity.AddClaim(new Claim(key, v is IReadOnlyDictionary<string, object?> ? System.Text.Json.JsonSerializer.Serialize(v) : v.ToString()!));
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }
}

public static class WincheTokensAuthenticationExtensions
{
    /// <summary>
    /// Adds the <see cref="WincheAuthDefaults.Scheme"/> scheme: it accepts tokens from Winche Auth and from trusted
    /// providers, checked against the provider that issued them, and becomes the default scheme unless the app set one.
    /// With <c>t.UseSettings()</c> the providers and their mapping can be changed in the console without a restart.
    /// </summary>
    public static AuthenticationBuilder AddWincheTokens(this AuthenticationBuilder builder, Action<WincheTokenOptions>? configure = null)
    {
        var tokens = new WincheTokenOptions();
        configure?.Invoke(tokens);
        if (!tokens.Own && tokens.Issuers.Count == 0 && !tokens.Managed)
            throw new InvalidOperationException("AddWincheTokens: trust Winche Auth (TrustWincheAuth), an issuer (TrustIssuer), or let the console choose (UseSettings).");
        builder.Services.AddSingleton(tokens);

        var code = tokens.ToSettings();
        var area = tokens.Managed
            ? builder.Services.AddWincheSettingsArea(WincheAuthDefaults.SettingsArea, "Identity providers", code, s => s.Problems())
            : null;
        var codeKeys = tokens.Issuers.Where(i => i.SigningKeys is not null).ToDictionary(i => i.Name, i => i.SigningKeys!);
        builder.Services.AddSingleton(new WincheTokenProviders(code, area, codeKeys));
        builder.Services.TryAddSingleton<TokenChecker>();
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.TryAddSingleton(sp => new WincheTokenInspector(
            sp.GetRequiredService<TokenChecker>(), sp.GetRequiredService<WincheTokenProviders>(), sp.GetRequiredService<TimeProvider>()));

        builder.AddScheme<WincheTokensSchemeOptions, WincheTokensHandler>(WincheAuthDefaults.Scheme, "Winche", _ => { });
        builder.AddScheme<WincheTokensSchemeOptions, WincheTokensHandler>(WincheAuthDefaults.OwnScheme, "Winche Auth", o => o.OwnOnly = true);
        builder.Services.PostConfigure<AuthenticationOptions>(o => o.DefaultScheme ??= WincheAuthDefaults.Scheme);
        return builder;
    }

    internal static string? TokenOf(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return header[7..].Trim();
        // In the address only for WebSocket upgrades (browsers can't set headers there): elsewhere it would end up in logs.
        if (!request.HttpContext.WebSockets.IsWebSocketRequest) return null;
        return request.Query["access_token"].FirstOrDefault() is { Length: > 0 } q ? q : null;
    }
}

/// <summary>The caller's claims for Winche's access rules (<c>request.auth</c>).</summary>
public static class WincheClaims
{
    private static readonly object None = new();

    /// <summary>
    /// The verified token's claims — <c>uid</c>, <c>issuer</c> (<c>winche</c> or the provider's name) and the fields its
    /// mapping passes — or null when signed out. For the host's <c>AddWincheCaller(WincheClaims.FromAsync)</c>, which
    /// gives every Winche package the same caller.
    /// </summary>
    public static async ValueTask<IReadOnlyDictionary<string, object?>?> FromAsync(HttpContext ctx)
    {
        if (ctx.Items.TryGetValue(WincheAuthDefaults.ClaimsItem, out var cached))
            return cached as IReadOnlyDictionary<string, object?>;
        // The app's default scheme isn't Winche's: authenticate with it here (once per request).
        var result = await ctx.AuthenticateAsync(WincheAuthDefaults.Scheme);
        if (!result.Succeeded) ctx.Items[WincheAuthDefaults.ClaimsItem] = None;
        return ctx.Items.TryGetValue(WincheAuthDefaults.ClaimsItem, out var found) ? found as IReadOnlyDictionary<string, object?> : null;
    }

    /// <summary>
    /// <see cref="FromAsync"/>, waiting synchronously when the request hasn't been authenticated yet: prefer
    /// <see cref="FromAsync"/> (with <c>AddWincheCaller</c>).
    /// </summary>
    public static IReadOnlyDictionary<string, object?>? From(HttpContext ctx)
    {
        if (ctx.Items.TryGetValue(WincheAuthDefaults.ClaimsItem, out var cached))
            return cached as IReadOnlyDictionary<string, object?>;
        // The app's default scheme isn't Winche's: authenticate with it here (once per request).
        var result = ctx.AuthenticateAsync(WincheAuthDefaults.Scheme).GetAwaiter().GetResult();
        if (!result.Succeeded) ctx.Items[WincheAuthDefaults.ClaimsItem] = None;
        return ctx.Items.TryGetValue(WincheAuthDefaults.ClaimsItem, out var found) ? found as IReadOnlyDictionary<string, object?> : null;
    }

    /// <summary>The caller's uid, or null when signed out.</summary>
    public static string? Uid(HttpContext ctx) => From(ctx)?.GetValueOrDefault("uid") as string;
}
