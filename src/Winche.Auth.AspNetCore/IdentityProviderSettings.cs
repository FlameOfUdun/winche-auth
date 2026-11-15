using System.Text.RegularExpressions;

namespace Winche.Auth.AspNetCore;

/// <summary>
/// Which sign-in systems' tokens are accepted, and how each one's tokens become <c>request.auth</c> — the settings area
/// <c>auth.identityProviders</c>. The code's <c>AddWincheTokens(t =&gt; …)</c> gives the starting values; with
/// <c>t.UseSettings()</c> the console can change them.
/// </summary>
public sealed record IdentityProvidersSettings
{
    /// <summary>Accept tokens issued by Winche Auth.</summary>
    public bool TrustWincheAuth { get; init; }

    public List<TrustedProviderSettings> Providers { get; init; } = [];

    internal static readonly Regex NamePattern = new("^[a-z0-9][a-z0-9_-]{0,39}$", RegexOptions.Compiled);
    private static readonly Regex FieldPattern = new("^[A-Za-z_][A-Za-z0-9_]{0,63}$", RegexOptions.Compiled);

    /// <summary>What's wrong with these settings, if anything.</summary>
    public IReadOnlyList<string> Problems()
    {
        var problems = new List<string>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in Providers)
        {
            var label = string.IsNullOrWhiteSpace(p.Name) ? "A provider" : $"Provider '{p.Name}'";
            if (!NamePattern.IsMatch(p.Name ?? "") || p.Name == WincheAuthDefaults.WincheIssuerName)
                problems.Add($"{label}: the name is lower-case letters, digits, - and _ (and not \"winche\").");
            else if (!names.Add(p.Name!)) problems.Add($"{label} is listed twice.");
            if (!Uri.TryCreate(p.Issuer, UriKind.Absolute, out var issuer))
                problems.Add($"{label}: the issuer must be a full address, like https://auth.example.com/realms/app.");
            else if (issuer.Scheme != Uri.UriSchemeHttps && p.RequireHttps)
                problems.Add($"{label}: the issuer must use https (or turn off \"require https\" for local testing).");
            if (p.Authority is { Length: > 0 } a && !Uri.TryCreate(a, UriKind.Absolute, out _))
                problems.Add($"{label}: the discovery address must be a full address.");
            if (p.ValidateAudience && (p.Audiences.Count == 0 || p.Audiences.Any(string.IsNullOrWhiteSpace)))
                problems.Add($"{label}: give the audience (the app's client id at the provider), or stop checking it.");
            if (string.IsNullOrWhiteSpace(p.UidClaim)) problems.Add($"{label}: say which field holds the user's id (usually sub).");
            var targets = new HashSet<string>(StringComparer.Ordinal);
            foreach (var m in p.Claims ?? [])
            {
                if (string.IsNullOrWhiteSpace(m.From)) problems.Add($"{label}: a field to pass has no source.");
                if (!FieldPattern.IsMatch(m.To ?? "") || m.To is "uid" or "issuer")
                    problems.Add($"{label}: '{m.To}' can't be a name in the rules (letters, digits and _; not uid or issuer).");
                else if (!targets.Add(m.To!)) problems.Add($"{label}: '{m.To}' is set twice.");
            }
        }
        return problems;
    }
}

/// <summary>One trusted sign-in system: Keycloak, Auth0, Entra ID, Google Workspace, or any OpenID Connect provider.</summary>
public sealed record TrustedProviderSettings
{
    /// <summary>A short name (<c>keycloak</c>); rules see it as <c>request.auth.token.issuer</c>.</summary>
    public string Name { get; init; } = "";

    /// <summary>A name for people ("Example Health Keycloak").</summary>
    public string? DisplayName { get; init; }

    /// <summary>keycloak, auth0, entra, google or oidc: only changes hints in the console.</summary>
    public string Kind { get; init; } = "oidc";

    /// <summary>The <c>iss</c> its tokens carry, e.g. <c>https://auth.example.com/realms/app</c>.</summary>
    public string Issuer { get; init; } = "";

    /// <summary>Where its discovery document and keys are, when not at the issuer.</summary>
    public string? Authority { get; init; }

    /// <summary>The <c>aud</c> values its tokens may carry.</summary>
    public List<string> Audiences { get; init; } = [];

    public bool ValidateAudience { get; init; } = true;

    /// <summary>The field that becomes <c>request.auth.uid</c> (default <c>sub</c>).</summary>
    public string UidClaim { get; init; } = "sub";

    /// <summary>
    /// The fields the rules see, besides uid, issuer, sub, email and name: <c>From</c> is a path in the token
    /// (<c>realm_access.roles</c>, or <c>given_name + family_name</c> to join), <c>To</c> its name in the rules. Null
    /// passes every field as it is.
    /// </summary>
    public List<ClaimMapping>? Claims { get; init; }

    /// <summary>Require https for the issuer and its keys (turn off only for local testing).</summary>
    public bool RequireHttps { get; init; } = true;
}

/// <summary>A token field passed to the rules: <see cref="From"/> in the token, <see cref="To"/> in <c>request.auth.token</c>.</summary>
public sealed record ClaimMapping(string From, string To);
