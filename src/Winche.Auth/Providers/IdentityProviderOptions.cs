using Microsoft.IdentityModel.Tokens;

namespace Winche.Auth.Providers;

/// <summary>
/// A sign-in provider whose ID tokens are exchanged for Winche tokens: Google, Apple, or any OpenID Connect provider
/// (Keycloak, Auth0, Entra ID, …). The app signs in with the provider itself and posts the ID token to
/// <c>/auth/v1/signIn/idp</c>; the user becomes (or already is) a Winche Auth user.
/// </summary>
public sealed class IdentityProviderOptions
{
    /// <summary>The provider's name: <c>google</c>, <c>apple</c>, or yours (<c>keycloak</c>). Also the token's <c>provider</c> claim.</summary>
    public string Name { get; internal set; } = "";
    /// <summary>google, apple or oidc.</summary>
    public string Kind { get; internal set; } = "oidc";
    /// <summary>A name for people ("Keycloak"); the name when not set.</summary>
    public string? DisplayName { get; set; }
    /// <summary>Its OpenID Connect address; its keys come from the discovery document there.</summary>
    public string Authority { get; set; } = "";
    /// <summary>The <c>iss</c> values its tokens may carry; the authority when empty.</summary>
    public IList<string> Issuers { get; set; } = [];
    /// <summary>The <c>aud</c> values its tokens may carry: your client ids (Google), bundle or service ids (Apple).</summary>
    public IList<string> Audiences { get; set; } = [];
    /// <summary>Use the provider's <c>sub</c> as the Winche uid (when it's a valid uid), so ids stay the same — e.g. moving from Keycloak.</summary>
    public bool UseSubjectAsUid { get; set; }
    /// <summary>Claims copied from its tokens into the user's custom claims at each sign-in (e.g. role, org).</summary>
    public IReadOnlyList<string> CopiedClaims { get; internal set; } = [];
    /// <summary>
    /// Every sign-in with this provider needs a second step: the provider's own (its token says so, see
    /// <see cref="SecondStepAcrValues"/>), or Winche's code for users who turned on two-step sign-in. Others are refused
    /// with SECOND_STEP_REQUIRED. Off: a second step is asked only of users who turned it on.
    /// </summary>
    public bool RequireSecondStep { get; set; }

    /// <summary>
    /// Signing in through this provider counts as a second step on its own (the provider checks one for everyone, e.g. a
    /// company's sign-in with its own two-step): users who turned on Winche's two-step aren't asked for its code too.
    /// </summary>
    public bool CountsAsSecondStep { get; set; }
    /// <summary>
    /// <c>acr</c> values in its ID tokens that mean the user passed a second step (Keycloak: the level you gave a flow
    /// with a one-time code, e.g. "2"). A standard <c>amr</c> claim (otp, mfa, hwk…) counts without this.
    /// </summary>
    public IList<string> SecondStepAcrValues { get; set; } = [];
    /// <summary>Keys to check its tokens with instead of fetching them (tests, offline setups).</summary>
    public IReadOnlyList<SecurityKey>? SigningKeys { get; set; }
    /// <summary>
    /// Accept unsigned ID tokens. For the Winche emulator and tests only: anyone can then sign in as anyone.
    /// </summary>
    public bool AllowUnsignedTokensForTesting { get; set; }

    /// <summary>The Keycloak sync, when on (<see cref="SyncFromKeycloak"/>).</summary>
    public KeycloakSyncOptions? KeycloakSync { get; internal set; }

    /// <summary>
    /// Keeps the users who sign in with this (Keycloak) provider in step with Keycloak, one way: disabled, enabled or
    /// deleted there (deleted: disabled here, and unlinked), their name, email and the copied claims. Winche only reads
    /// Keycloak, polling its saved events; turn on "Save events" and "Save admin events" in the realm.
    /// </summary>
    public IdentityProviderOptions SyncFromKeycloak(Action<KeycloakSyncOptions> configure)
    {
        var sync = new KeycloakSyncOptions();
        configure(sync);
        KeycloakSync = sync;
        return this;
    }

    /// <summary>Copies these claims from its tokens into the user's custom claims at each sign-in.</summary>
    public IdentityProviderOptions MapClaims(params string[] claims)
    {
        CopiedClaims = claims;
        return this;
    }

    internal IReadOnlyList<string> EffectiveIssuers => Issuers.Count > 0 ? [.. Issuers] : [Authority.TrimEnd('/')];

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Authority) && SigningKeys is null && !AllowUnsignedTokensForTesting)
            throw new InvalidOperationException($"Winche Auth provider '{Name}': set Authority.");
        if (Audiences.Count == 0)
            throw new InvalidOperationException($"Winche Auth provider '{Name}': set Audiences (your client ids for it).");
        if (Authority is { Length: > 0 } a && (!Uri.TryCreate(a, UriKind.Absolute, out var u) || u.Scheme is not ("https" or "http")))
            throw new InvalidOperationException($"Winche Auth provider '{Name}': the authority must be a full address, like https://accounts.example.com.");
        KeycloakSync?.Validate(this);
        if (CopiedClaims.FirstOrDefault(Tokens.TokenIssuer.Reserved.Contains) is { } reserved)
            throw new InvalidOperationException($"Winche Auth provider '{Name}': '{reserved}' can't be copied into custom claims.");
    }
}
