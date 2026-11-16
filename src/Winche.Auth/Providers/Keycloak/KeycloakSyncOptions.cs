namespace Winche.Auth.Providers;

/// <summary>
/// Keeps the Winche users linked to a Keycloak provider in step with Keycloak, one way: Winche reads Keycloak (users,
/// their roles, groups and attributes, and its saved events) and never writes to it. Set on the provider with
/// <see cref="IdentityProviderOptions.SyncFromKeycloak"/>.
/// </summary>
public sealed class KeycloakSyncOptions
{
    /// <summary>
    /// A confidential Keycloak client with a service account, used only to read: give its service account the
    /// realm-management roles <c>view-users</c> and <c>view-events</c>.
    /// </summary>
    public string ClientId { get; set; } = "";

    /// <summary>That client's secret.</summary>
    public string ClientSecret { get; set; } = "";

    /// <summary>Set from settings: the secret's name in the app's secret store (read when it's needed), instead of <see cref="ClientSecret"/>.</summary>
    internal string? ClientSecretName { get; set; }

    /// <summary>
    /// Where the server reaches Keycloak, when not at the provider's authority (e.g. <c>http://keycloak:8080</c> inside
    /// the network, when the public address sits behind a CDN). The realm is the authority's.
    /// </summary>
    public string? AdminServer { get; set; }

    public const string Disable = "disable", Delete = "delete";

    /// <summary>
    /// What becomes of a Winche user whose Keycloak account is deleted: <see cref="Disable"/> (the default) keeps them,
    /// disabled and unlinked, for an admin to decide; <see cref="Delete"/> deletes them here too, as when Keycloak is
    /// where accounts are kept, so a deletion there (a person leaving, their right to erasure) reaches the app's data
    /// through its <c>users.onDeleted</c> triggers and webhooks.
    /// </summary>
    public string WhenDeleted { get; set; } = Disable;

    /// <summary>How often Keycloak's events are read for changed users (default 10 seconds).</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>How often every linked user is compared with Keycloak, catching what events missed (default daily).</summary>
    public TimeSpan ReconcileInterval { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// The custom claims kept in step: the provider's copied claims when not set. Each is read from the Keycloak user:
    /// <c>realm_access</c> (<c>{"roles": […]}</c>, their realm roles), <c>groups</c> (group paths), anything else the user
    /// attribute of that name (one value, or a list). Leave out claims your tokens get from other mappers: they're only
    /// refreshed at sign-in.
    /// </summary>
    public IList<string>? Claims { get; set; }

    /// <summary>Keycloak user attributes kept as custom claims, by attribute name (see <see cref="MapAttribute"/>).</summary>
    public IDictionary<string, string> Attributes { get; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// Keeps the Keycloak user attribute <paramref name="attribute"/> as the custom claim <paramref name="claim"/> (the
    /// same name when not given): one value as a string, several as a list, none removes the claim. Read from Keycloak
    /// itself, at each sign-in and when it changes there, so the realm needs no token mapper for it. Keycloak keeps
    /// attributes it doesn't know only when the realm's user profile allows unmanaged attributes, or declares them.
    /// </summary>
    public KeycloakSyncOptions MapAttribute(string attribute, string? claim = null)
    {
        Attributes[attribute] = claim ?? attribute;
        return this;
    }

    /// <summary>Every custom claim the sync keeps in step.</summary>
    internal IReadOnlyList<string> ClaimNames(IdentityProviderOptions provider) =>
        [.. ((IEnumerable<string>?)Claims ?? provider.CopiedClaims).Concat(Attributes.Values).Distinct(StringComparer.Ordinal)];

    /// <summary>
    /// A secret (16+ characters) for <c>POST /auth/v1/providers/{name}/changed</c>, which reads Keycloak's events at
    /// once: point a Keycloak webhook plugin at it, sending the secret as a bearer token. Not set, the endpoint is off.
    /// </summary>
    public string? WebhookSecret { get; set; }

    /// <summary>Handles the requests to Keycloak (tests, proxies).</summary>
    public HttpMessageHandler? BackchannelHandler { get; set; }

    internal void Validate(IdentityProviderOptions provider)
    {
        var where = $"Winche Auth provider '{provider.Name}', Keycloak sync";
        if (string.IsNullOrWhiteSpace(ClientId) || (string.IsNullOrWhiteSpace(ClientSecret) && ClientSecretName is null))
            throw new InvalidOperationException($"{where}: set ClientId and ClientSecret (a read-only service account).");
        if (KeycloakRealm.From(provider.Authority, AdminServer) is null)
            throw new InvalidOperationException($"{where}: the authority must be a Keycloak realm, like https://id.example.com/realms/acme.");
        foreach (var (attribute, claim) in Attributes)
        {
            if (string.IsNullOrWhiteSpace(attribute) || string.IsNullOrWhiteSpace(claim))
                throw new InvalidOperationException($"{where}: an attribute and its claim need names.");
            if (Tokens.TokenIssuer.Reserved.Contains(claim) || claim is "realm_access" or "groups")
                throw new InvalidOperationException($"{where}: attribute '{attribute}' can't become the claim '{claim}', which is reserved.");
        }
        if (WebhookSecret is { Length: < 16 })
            throw new InvalidOperationException($"{where}: WebhookSecret must be at least 16 characters.");
        if (PollInterval <= TimeSpan.Zero || ReconcileInterval <= TimeSpan.Zero)
            throw new InvalidOperationException($"{where}: PollInterval and ReconcileInterval must be positive.");
    }
}

/// <summary>A Keycloak realm's admin and token addresses, from a provider's authority (<c>{server}/realms/{realm}</c>).</summary>
internal sealed record KeycloakRealm(string Server, string Realm)
{
    public string Admin => $"{Server}/admin/realms/{Uri.EscapeDataString(Realm)}";
    public string Token => $"{Server}/realms/{Uri.EscapeDataString(Realm)}/protocol/openid-connect/token";

    public static KeycloakRealm? From(string authority, string? adminServer)
    {
        var a = authority.TrimEnd('/');
        var at = a.LastIndexOf("/realms/", StringComparison.Ordinal);
        if (at < 0 || !Uri.TryCreate(a, UriKind.Absolute, out _)) return null;
        var realm = Uri.UnescapeDataString(a[(at + "/realms/".Length)..]);
        if (realm.Length == 0 || realm.Contains('/')) return null;
        return new KeycloakRealm((adminServer ?? a[..at]).TrimEnd('/'), realm);
    }
}
