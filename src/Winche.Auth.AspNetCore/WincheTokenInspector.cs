using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Winche.Auth.AspNetCore;

/// <summary>One line of a token test: <c>ok</c>, <c>warning</c> or <c>error</c>.</summary>
public sealed record TokenCheck(string Outcome, string Text);

/// <summary>What a pasted token would become: the checks, and <c>request.auth</c> as the rules would see it.</summary>
public sealed record TokenInspection(bool WouldSignIn, string? Provider, IReadOnlyList<TokenCheck> Checks,
    IReadOnlyDictionary<string, object?>? Auth, IReadOnlyList<string> NotPassed);

/// <summary>What a provider's address turned out to be.</summary>
public sealed record ProviderCheck(bool Found, string? Issuer, int Keys, IReadOnlyList<string> Algorithms, string? Error);

/// <summary>For the console: test a token against the providers (saved or a draft), and check a provider's address.</summary>
public sealed class WincheTokenInspector
{
    private readonly TokenChecker _checker;
    private readonly WincheTokenProviders _providers;
    private readonly TimeProvider _time;

    internal WincheTokenInspector(TokenChecker checker, WincheTokenProviders providers, TimeProvider time)
    {
        _checker = checker;
        _providers = providers;
        _time = time;
    }

    /// <summary>
    /// Checks <paramref name="token"/> against <paramref name="draft"/> (or the settings in force) and shows what the rules
    /// would see. An expired token is still mapped — handy for trying a mapping — but marked as unable to sign in.
    /// </summary>
    public async Task<TokenInspection> InspectAsync(string token, IdentityProvidersSettings? draft = null, CancellationToken ct = default)
    {
        token = (token ?? "").Trim();
        if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) token = token[7..].Trim();
        var result = await _checker.CheckAsync(token, draft ?? _providers.Current, ownOnly: false, ignoreLifetime: true, ct);
        if (!result.Valid) return new TokenInspection(false, result.Provider, [new TokenCheck("error", result.Error!)], null, []);

        var jwt = result.Jwt!;
        var checks = new List<TokenCheck>
        {
            new("ok", $"Signed by {result.ProviderLabel}{(string.IsNullOrEmpty(jwt.Kid) ? "" : $" (key {jwt.Kid})")}"),
        };
        if (jwt.Audiences.Any()) checks.Add(new("ok", $"For {string.Join(", ", jwt.Audiences)}"));
        var now = _time.GetUtcNow().UtcDateTime;
        var expired = jwt.ValidTo != DateTime.MinValue && jwt.ValidTo < now;
        checks.Add(expired
            ? new("error", $"Expired {Ago(now - jwt.ValidTo)} ago: the mapping below is still shown, but this token can't sign in.")
            : new("ok", jwt.ValidTo == DateTime.MinValue ? "Doesn't expire" : $"Not expired ({Ago(jwt.ValidTo - now)} left)"));
        checks.Add(new("ok", $"User id: {result.Claims!["uid"]}"));
        foreach (var field in result.NotPassed) checks.Add(new("warning", $"{field} is in the token but not passed to the rules"));

        var auth = new Dictionary<string, object?> { ["uid"] = result.Claims["uid"], ["token"] = result.Claims };
        return new TokenInspection(!expired, result.Provider, checks, auth, result.NotPassed);
    }

    /// <summary>Fetches a provider's discovery document: does the address work, does its issuer match, how many keys.</summary>
    public async Task<ProviderCheck> CheckProviderAsync(string issuer, string? authority = null, bool requireHttps = true, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out _)) return new ProviderCheck(false, null, 0, [], "That isn't a full address.");
        var root = (authority is { Length: > 0 } a ? a : issuer).TrimEnd('/');
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            var config = await OpenIdConnectConfigurationRetriever.GetAsync($"{root}/.well-known/openid-configuration",
                new HttpDocumentRetriever { RequireHttps = requireHttps }, timeout.Token);
            if (!TokenChecker.SameIssuer(issuer, config.Issuer))
                return new ProviderCheck(false, config.Issuer, config.SigningKeys.Count, [.. config.IdTokenSigningAlgValuesSupported],
                    $"The provider calls itself {config.Issuer}, not {issuer}: use that as the issuer.");
            return new ProviderCheck(true, config.Issuer, config.SigningKeys.Count, [.. config.IdTokenSigningAlgValuesSupported], null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            return new ProviderCheck(false, null, 0, [], $"Couldn't read {root}/.well-known/openid-configuration: {Root(ex).Message}");
        }
    }

    private static Exception Root(Exception ex) => ex.InnerException is { } inner ? Root(inner) : ex;

    private static string Ago(TimeSpan t) =>
        t.TotalDays >= 1 ? $"{(int)t.TotalDays} day{((int)t.TotalDays == 1 ? "" : "s")}"
        : t.TotalHours >= 1 ? $"{(int)t.TotalHours} hour{((int)t.TotalHours == 1 ? "" : "s")}"
        : $"{Math.Max(1, (int)t.TotalMinutes)} min";
}
