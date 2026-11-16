using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Winche.Auth.Providers;

/// <summary>A Keycloak user as the sync sees them: what's kept in step on the Winche user.</summary>
internal sealed record KeycloakUserState(string Id, bool Enabled, string? Email, bool EmailVerified, string? Name,
    IReadOnlyDictionary<string, object?> Claims);

/// <summary>Reads a Keycloak realm through its admin REST API, as a service account. Never writes.</summary>
internal sealed class KeycloakReader : IDisposable
{
    private readonly KeycloakRealm _realm;
    private readonly KeycloakSyncOptions _options;
    private readonly HttpClient _http;
    private readonly IReadOnlyList<string> _claims;
    private readonly Dictionary<string, string> _attributeOf;   // claim → the attribute it's kept from
    private (string Token, DateTimeOffset Expires)? _token;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);

    /// <summary>Events read per request; an hour of them at most per poll.</summary>
    private const int Page = 100, MaxPages = 50;

    /// <summary>Keycloak's user events that change what's synced (self-service in its account console).</summary>
    private static readonly string[] UserEventTypes = ["UPDATE_PROFILE", "UPDATE_EMAIL", "VERIFY_EMAIL", "DELETE_ACCOUNT"];

    /// <summary>Its admin events about a user, their roles or their groups.</summary>
    private static readonly string[] AdminResourceTypes = ["USER", "REALM_ROLE_MAPPING", "CLIENT_ROLE_MAPPING", "GROUP_MEMBERSHIP"];

    /// <summary>The claims it reads, for applying a user.</summary>
    public IReadOnlyList<string> ClaimNames => _claims;

    private readonly Winche.Secrets.SecretStore? _secrets;

    public KeycloakReader(IdentityProviderOptions provider, Winche.Secrets.SecretStore? secrets = null)
    {
        _secrets = secrets;
        _options = provider.KeycloakSync!;
        _realm = KeycloakRealm.From(provider.Authority, _options.AdminServer)!;
        _http = _options.BackchannelHandler is { } h ? new HttpClient(h, disposeHandler: false) : new HttpClient();
        _http.Timeout = TimeSpan.FromSeconds(30);
        _claims = _options.ClaimNames(provider);
        _attributeOf = _options.Attributes.ToDictionary(a => a.Value, a => a.Key, StringComparer.Ordinal);
    }

    public void Dispose() => _http.Dispose();

    /// <summary>The user, or null when Keycloak has no user with that id (deleted).</summary>
    public async Task<KeycloakUserState?> UserAsync(string id, CancellationToken ct)
    {
        var user = await GetAsync($"users/{Uri.EscapeDataString(id)}", ct, notFoundIsNull: true);
        if (user is null) return null;
        var claims = new Dictionary<string, object?>(StringComparer.Ordinal);
        var attributes = user["attributes"] as JsonObject;
        foreach (var name in _claims)
        {
            switch (name)
            {
                case "realm_access":
                    var roles = await GetAsync($"users/{Uri.EscapeDataString(id)}/role-mappings/realm/composite", ct) as JsonArray ?? [];
                    claims[name] = new Dictionary<string, object?> { ["roles"] = roles.Select(r => (string?)r?["name"]).Order(StringComparer.Ordinal).Cast<object?>().ToList() };
                    break;
                case "groups":
                    var groups = await GetAsync($"users/{Uri.EscapeDataString(id)}/groups?briefRepresentation=true&max=1000", ct) as JsonArray ?? [];
                    claims[name] = groups.Select(g => (string?)g?["path"]).Order(StringComparer.Ordinal).Cast<object?>().ToList();
                    break;
                default:
                    if (attributes?[_attributeOf.GetValueOrDefault(name, name)] is JsonArray values && values.Count > 0)
                        claims[name] = values.Count == 1 ? (string?)values[0] : values.Select(v => (object?)(string?)v).ToList();
                    else claims[name] = null;   // not there: removed from the claims
                    break;
            }
        }
        var name2 = string.Join(' ', new[] { (string?)user["firstName"], (string?)user["lastName"] }.Where(s => !string.IsNullOrWhiteSpace(s))).Trim();
        return new KeycloakUserState(
            (string)user["id"]!, (bool?)user["enabled"] ?? true, (string?)user["email"], (bool?)user["emailVerified"] ?? false,
            name2.Length == 0 ? null : name2, claims);
    }

    /// <summary>
    /// The users whose events came after <paramref name="after"/> (Keycloak's milliseconds), and the newest event's
    /// time. Re-reads a little before it, since events can arrive slightly out of order; applying a user twice is harmless.
    /// Null for <c>Complete</c> when there were more than a poll reads: reconcile instead.
    /// </summary>
    public async Task<(IReadOnlySet<string> Users, long Newest, bool Complete)> ChangedSinceAsync(long after, CancellationToken ct)
    {
        var users = new HashSet<string>(StringComparer.Ordinal);
        var newest = after;
        var from = after - 5_000;
        var day = DateTimeOffset.FromUnixTimeMilliseconds(Math.Max(0, from)).UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var complete = true;

        var types = string.Join("", UserEventTypes.Select(t => $"&type={t}"));
        complete &= await ReadAsync($"events?dateFrom={day}{types}", from, e => (string?)e["userId"], users, n => newest = Math.Max(newest, n), ct);
        var resources = string.Join("", AdminResourceTypes.Select(t => $"&resourceTypes={t}"));
        complete &= await ReadAsync($"admin-events?dateFrom={day}{resources}", from, e =>
        {
            // users/{id}, users/{id}/role-mappings/…, users/{id}/groups/{group}
            var path = (string?)e["resourcePath"];
            return path is not null && path.StartsWith("users/", StringComparison.Ordinal) ? path["users/".Length..].Split('/')[0] : null;
        }, users, n => newest = Math.Max(newest, n), ct);
        return (users, newest, complete);
    }

    /// <summary>Reads events newest first until one is no newer than <paramref name="from"/>; false when it gave up first.</summary>
    private async Task<bool> ReadAsync(string query, long from, Func<JsonNode, string?> userOf, HashSet<string> users, Action<long> seen, CancellationToken ct)
    {
        for (var page = 0; page < MaxPages; page++)
        {
            var events = await GetAsync($"{query}&first={page * Page}&max={Page}", ct) as JsonArray ?? [];
            foreach (var e in events)
            {
                if (e is null) continue;
                var time = (long?)e["time"] ?? 0;
                if (time <= from) return true;
                seen(time);
                if (userOf(e) is { Length: > 0 } id) users.Add(id);
            }
            if (events.Count < Page) return true;
        }
        return false;
    }

    private async Task<JsonNode?> GetAsync(string path, CancellationToken ct, bool notFoundIsNull = false)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_realm.Admin}/{path}");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await TokenAsync(ct, force: attempt > 0));
            using var response = await _http.SendAsync(request, ct);
            if (response.StatusCode == HttpStatusCode.Unauthorized && attempt == 0) continue;   // a stale token: once more
            if (response.StatusCode == HttpStatusCode.NotFound && notFoundIsNull) return null;
            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"Keycloak answered {(int)response.StatusCode} to GET {path.Split('?')[0]}" +
                    (response.StatusCode == HttpStatusCode.Forbidden ? ": give the sync's service account view-users and view-events." : "."));
            return JsonNode.Parse(await response.Content.ReadAsStringAsync(ct));
        }
    }

    private async Task<string> TokenAsync(CancellationToken ct, bool force)
    {
        if (!force && _token is { } t && t.Expires > DateTimeOffset.UtcNow.AddSeconds(30)) return t.Token;
        await _tokenLock.WaitAsync(ct);
        try
        {
            if (!force && _token is { } again && again.Expires > DateTimeOffset.UtcNow.AddSeconds(30)) return again.Token;
            // Set in code, or (set in settings) kept in the app's secret store.
            var secret = !string.IsNullOrEmpty(_options.ClientSecret) ? _options.ClientSecret
                : _options.ClientSecretName is { } name && _secrets is not null ? await _secrets.GetAsync(name, ct) ?? "" : "";
            using var response = await _http.PostAsync(_realm.Token, new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials", ["client_id"] = _options.ClientId, ["client_secret"] = secret,
            }), ct);
            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"Keycloak refused the sync's client '{_options.ClientId}' ({(int)response.StatusCode}): check its id, secret and service account.");
            var json = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!;
            var token = (string)json["access_token"]!;
            _token = (token, DateTimeOffset.UtcNow.AddSeconds((int?)json["expires_in"] ?? 60));
            return token;
        }
        finally { _tokenLock.Release(); }
    }
}
