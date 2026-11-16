using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.Providers;

namespace Winche.Auth.Tests;

/// <summary>A Keycloak realm's admin API, in memory: users, their roles and groups, and its saved events.</summary>
internal sealed class FakeKeycloak : IAsyncDisposable
{
    public sealed class User
    {
        public required string Id;
        public bool Enabled = true;
        public string? Email, FirstName, LastName;
        public bool EmailVerified = true;
        public Dictionary<string, List<string>> Attributes = [];
        public List<string> Roles = ["default-roles-example"];
        public List<string> Groups = [];
    }

    public ConcurrentDictionary<string, User> Users { get; } = new();
    public ConcurrentQueue<(long Time, string Type, string UserId)> Events { get; } = new();
    public ConcurrentQueue<(long Time, string Resource, string Path)> AdminEvents { get; } = new();
    public ConcurrentQueue<string> Writes { get; } = new();   // anything but reading
    public int Reads;
    public bool Down;   // answers 503 to everything
    private readonly WebApplication _app;

    private FakeKeycloak(WebApplication app) => _app = app;
    public HttpMessageHandler Handler => _app.GetTestServer().CreateHandler();

    public static async Task<FakeKeycloak> StartAsync()
    {
        var b = WebApplication.CreateBuilder();
        b.WebHost.UseTestServer();
        b.Logging.ClearProviders();
        var app = b.Build();
        var kc = new FakeKeycloak(app);
        app.Use(async (http, next) =>
        {
            if (kc.Down) { http.Response.StatusCode = 503; return; }
            if (http.Request.Method != "GET" && !http.Request.Path.Value!.EndsWith("/token")) kc.Writes.Enqueue($"{http.Request.Method} {http.Request.Path}");
            else Interlocked.Increment(ref kc.Reads);
            await next();
        });
        app.MapPost("/realms/example/protocol/openid-connect/token", (HttpContext http) =>
            http.Request.Form["client_secret"] == "sync-secret" ? Results.Json(new { access_token = "admin-token", expires_in = 300 }) : Results.Unauthorized());
        var admin = app.MapGroup("/admin/realms/example").AddEndpointFilter(async (ctx, next) =>
            ctx.HttpContext.Request.Headers.Authorization == "Bearer admin-token" ? await next(ctx) : Results.Unauthorized());
        admin.MapGet("/users/{id}", (string id) => kc.Users.TryGetValue(id, out var u)
            ? Results.Json(new JsonObject
            {
                ["id"] = u.Id, ["enabled"] = u.Enabled, ["email"] = u.Email, ["emailVerified"] = u.EmailVerified,
                ["firstName"] = u.FirstName, ["lastName"] = u.LastName,
                ["attributes"] = new JsonObject(u.Attributes.Select(a => KeyValuePair.Create(a.Key, (JsonNode?)new JsonArray([.. a.Value.Select(v => (JsonNode?)v)])))),
            })
            : Results.NotFound());
        admin.MapGet("/users/{id}/role-mappings/realm/composite", (string id) => Results.Json(kc.Users[id].Roles.Select(r => new { name = r })));
        admin.MapGet("/users/{id}/groups", (string id) => Results.Json(kc.Users[id].Groups.Select(g => new { name = g.Split('/')[^1], path = g })));
        admin.MapGet("/events", (int first, int max) => Results.Json(kc.Events.OrderByDescending(e => e.Time).Skip(first).Take(max)
            .Select(e => new { time = e.Time, type = e.Type, userId = e.UserId })));
        admin.MapGet("/admin-events", (int first, int max) => Results.Json(kc.AdminEvents.OrderByDescending(e => e.Time).Skip(first).Take(max)
            .Select(e => new { time = e.Time, resourceType = e.Resource, resourcePath = e.Path, operationType = "UPDATE" })));
        await app.StartAsync();
        return kc;
    }

    private static long Now => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>An admin changes <paramref name="id"/> in Keycloak's admin console.</summary>
    public void AdminChanged(string id, string resource = "USER", string? path = null) => AdminEvents.Enqueue((Now, resource, path ?? $"users/{id}"));

    /// <summary>The user changes their own profile in Keycloak's account console.</summary>
    public void UserChanged(string id, string type = "UPDATE_PROFILE") => Events.Enqueue((Now, type, id));

    public ValueTask DisposeAsync() => _app.DisposeAsync();
}

[Collection("postgres")]
public class KeycloakSyncTests(PostgresFixture pg)
{
    private static readonly RsaSecurityKey Key = new(RSA.Create(2048)) { KeyId = "k1" };
    private const string Issuer = "https://idp.test/realms/example";

    private static string IdToken(string sub, string email) => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Issuer = Issuer, Audience = "app", Expires = DateTime.UtcNow.AddMinutes(5),
        Claims = new Dictionary<string, object> { ["sub"] = sub, ["email"] = email, ["email_verified"] = true, ["name"] = "Ann Keycloak", ["role"] = "nurse" },
        SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.RsaSha256),
    });

    private async Task<TestApp> Start(FakeKeycloak kc, Action<KeycloakSyncOptions>? more = null, string? db = null) =>
        await TestApp.StartAsync(db ?? await pg.NewDatabaseAsync(), auth: o => o.OpenIdConnect("keycloak", k =>
        {
            k.Authority = Issuer;
            k.Audiences = ["app"];
            k.SigningKeys = [Key];
            k.MapClaims("role", "realm_access");
            k.SyncFromKeycloak(s =>
            {
                s.ClientId = "winche-sync";
                s.ClientSecret = "sync-secret";
                s.PollInterval = TimeSpan.FromMilliseconds(200);
                s.WebhookSecret = "a-webhook-secret-for-tests";
                s.BackchannelHandler = kc.Handler;
                more?.Invoke(s);
            });
        }));

    [Fact]
    public async Task Attributes_become_claims_from_the_first_token_and_follow_changes()
    {
        await using var kc = await FakeKeycloak.StartAsync();
        await using var app = await Start(kc, s => s.MapAttribute("department", "dept").MapAttribute("wards"));
        kc.Users["kc-ann"] = new FakeKeycloak.User { Id = "kc-ann", Email = "ann@example.com", Attributes = { ["department"] = ["icu"], ["wards"] = ["w1", "w2"] } };
        var ann = await SignIn(app, kc);   // the ID token has neither: no mapper in Keycloak

        var claims = await app.WhoAmI(ann.AccessToken);
        Assert.Equal("icu", claims.GetProperty("dept").GetString());
        Assert.Equal(["w1", "w2"], claims.GetProperty("wards").EnumerateArray().Select(w => w.GetString()));

        kc.Users["kc-ann"].Attributes["department"] = ["theatres"];
        kc.Users["kc-ann"].Attributes.Remove("wards");
        kc.AdminChanged("kc-ann");
        await Until(async () => (await User(app, ann.Uid)).CustomClaims.GetValueOrDefault("dept")?.ToString() == "theatres");
        Assert.False((await User(app, ann.Uid)).CustomClaims.ContainsKey("wards"));
    }

    [Fact]
    public async Task Keycloak_not_answering_doesnt_stop_a_sign_in()
    {
        await using var kc = await FakeKeycloak.StartAsync();
        await using var app = await Start(kc, s => s.MapAttribute("department", "dept"));
        kc.Down = true;
        var ann = await SignIn(app, kc);
        Assert.False((await app.WhoAmI(ann.AccessToken)).TryGetProperty("dept", out _));
        kc.Users["kc-ann"].Attributes["department"] = ["icu"];
        kc.Down = false;   // back: the daily comparison (or the next event) catches up
        kc.AdminChanged("kc-ann");
        await Until(async () => (await User(app, ann.Uid)).CustomClaims.ContainsKey("dept"));
    }

    private static async Task<Session> SignIn(TestApp app, FakeKeycloak kc, string id = "kc-ann", string email = "ann@example.com")
    {
        kc.Users.TryAdd(id, new FakeKeycloak.User { Id = id, Email = email, FirstName = "Ann", LastName = "Keycloak", Attributes = { ["role"] = ["nurse"] } });
        return await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "keycloak", idToken = IdToken(id, email) }));
    }

    private static async Task Until(Func<Task<bool>> done)
    {
        for (var i = 0; i < 200; i++) { if (await done()) return; await Task.Delay(25); }
        Assert.True(await done());
    }

    private static Task<WincheUserInfo> User(TestApp app, string uid) => app.Scoped(async a => (await a.GetUserAsync(uid))!);

    [Fact]
    public async Task Disabling_in_Keycloak_disables_here_and_ends_sessions_and_enabling_brings_them_back()
    {
        await using var kc = await FakeKeycloak.StartAsync();
        await using var app = await Start(kc);
        var ann = await SignIn(app, kc);

        kc.Users["kc-ann"].Enabled = false;
        kc.AdminChanged("kc-ann");
        await Until(async () => (await User(app, ann.Uid)).Disabled);
        Assert.Equal((401, "INVALID_REFRESH_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/token", new { refreshToken = ann.RefreshToken })));

        kc.Users["kc-ann"].Enabled = true;
        kc.AdminChanged("kc-ann");
        await Until(async () => !(await User(app, ann.Uid)).Disabled);
        Assert.Empty(kc.Writes);   // only ever read
    }

    [Fact]
    public async Task A_user_an_admin_disabled_here_isnt_enabled_by_Keycloak()
    {
        await using var kc = await FakeKeycloak.StartAsync();
        await using var app = await Start(kc);
        var ann = await SignIn(app, kc);
        await app.Scoped(a => a.SetDisabledAsync(ann.Uid, true));
        kc.Users["kc-ann"].FirstName = "Annie";
        kc.UserChanged("kc-ann");
        await Until(async () => (await User(app, ann.Uid)).DisplayName == "Annie Keycloak");
        Assert.True((await User(app, ann.Uid)).Disabled);
    }

    [Fact]
    public async Task Name_email_roles_and_attributes_follow_Keycloak()
    {
        await using var kc = await FakeKeycloak.StartAsync();
        await using var app = await Start(kc);
        var ann = await SignIn(app, kc);
        var u = kc.Users["kc-ann"];
        u.Email = "ann.k@example.com";
        u.LastName = "Smith";
        u.Attributes["role"] = ["doctor"];
        u.Roles = ["default-roles-example", "clinician"];
        kc.AdminChanged("kc-ann");
        await Until(async () => (await User(app, ann.Uid)).Email == "ann.k@example.com");
        var user = await User(app, ann.Uid);
        Assert.Equal("Ann Smith", user.DisplayName);
        Assert.Equal("doctor", user.CustomClaims["role"]?.ToString());
        Assert.Contains("clinician", System.Text.Json.JsonSerializer.Serialize(user.CustomClaims["realm_access"]));

        // An attribute removed there: the claim goes too.
        u.Attributes.Remove("role");
        kc.AdminChanged("kc-ann", "REALM_ROLE_MAPPING", "users/kc-ann/role-mappings/realm");
        await Until(async () => !(await User(app, ann.Uid)).CustomClaims.ContainsKey("role"));
    }

    [Fact]
    public async Task Deleted_in_Keycloak_is_disabled_and_unlinked_here_not_deleted()
    {
        await using var kc = await FakeKeycloak.StartAsync();
        await using var app = await Start(kc);
        var ann = await SignIn(app, kc);
        kc.Users.TryRemove("kc-ann", out _);
        kc.AdminChanged("kc-ann");
        await Until(async () => (await User(app, ann.Uid)).Disabled);
        var user = await User(app, ann.Uid);
        Assert.DoesNotContain("keycloak", user.Providers);
        Assert.Equal("ann@example.com", user.Email);
    }

    [Fact]
    public async Task With_when_deleted_delete_someone_deleted_in_Keycloak_is_deleted_here_too_with_a_deleted_event()
    {
        await using var kc = await FakeKeycloak.StartAsync();
        var db = await pg.NewDatabaseAsync();
        await using var app = await Start(kc, s => s.WhenDeleted = KeycloakSyncOptions.Delete, db);
        var ann = await SignIn(app, kc);
        kc.Users.TryRemove("kc-ann", out _);
        kc.AdminChanged("kc-ann");
        await Until(async () => await app.Scoped(a => a.GetUserAsync(ann.Uid)) is null);
        await using var conn = new Npgsql.NpgsqlConnection(db);
        await conn.OpenAsync();
        await using var cmd = new Npgsql.NpgsqlCommand("SELECT count(*) FROM auth_user_events WHERE type = 'deleted' AND path = @u", conn);
        cmd.Parameters.AddWithValue("u", ann.Uid);
        Assert.Equal(1L, (long)(await cmd.ExecuteScalarAsync())!);   // what users.onDeleted triggers and webhooks get
    }

    [Fact]
    public async Task What_events_missed_the_daily_comparison_catches()
    {
        await using var kc = await FakeKeycloak.StartAsync();
        var db = await pg.NewDatabaseAsync();
        await using (var first = await Start(kc, db: db))
            await SignIn(first, kc);
        kc.Users["kc-ann"].Enabled = false;   // no event: e.g. Keycloak's events were off, or expired
        await using var app = await Start(kc, s => s.ReconcileInterval = TimeSpan.FromMinutes(1), db);
        var uid = (await app.Scoped(a => a.ListUsersAsync())).Users.Single().Uid;
        // Marked as compared long ago: the next run compares everyone.
        await using (var conn = new Npgsql.NpgsqlConnection(db))
        {
            await conn.OpenAsync();
            await new Npgsql.NpgsqlCommand("UPDATE auth_provider_sync SET reconciled_at = now() - interval '1 hour'", conn).ExecuteNonQueryAsync();
        }
        await Until(async () => (await User(app, uid)).Disabled);
    }

    [Fact]
    public async Task The_webhook_reads_Keycloak_at_once_and_needs_its_secret()
    {
        await using var kc = await FakeKeycloak.StartAsync();
        await using var app = await Start(kc, s => s.PollInterval = TimeSpan.FromHours(1));
        var ann = await SignIn(app, kc);
        await Until(() => app.Service<ProviderSyncs>().StatusAsync().ContinueWith(t => t.Result.Single().LastRunAt is not null));
        await Task.Delay(300);   // the first run is over and waiting an hour

        kc.Users["kc-ann"].Enabled = false;
        kc.AdminChanged("kc-ann");
        using (var wrong = new HttpRequestMessage(HttpMethod.Post, "/auth/v1/providers/keycloak/changed") { Headers = { { "Authorization", "Bearer guess" } } })
            Assert.Equal(HttpStatusCode.NotFound, (await app.Client.SendAsync(wrong)).StatusCode);
        await Task.Delay(500);
        Assert.False((await User(app, ann.Uid)).Disabled);

        using var hook = new HttpRequestMessage(HttpMethod.Post, "/auth/v1/providers/keycloak/changed")
        {
            Headers = { { "Authorization", "Bearer a-webhook-secret-for-tests" } },
            Content = new StringContent("{\"type\":\"admin.USER-UPDATE\"}"),
        };
        Assert.Equal(HttpStatusCode.Accepted, (await app.Client.SendAsync(hook)).StatusCode);
        await Until(async () => (await User(app, ann.Uid)).Disabled);
    }

    [Fact]
    public async Task A_wrong_secret_shows_in_the_status_and_health()
    {
        await using var kc = await FakeKeycloak.StartAsync();
        await using var app = await Start(kc, s => s.ClientSecret = "wrong");
        await Until(() => app.Service<ProviderSyncs>().StatusAsync().ContinueWith(t => t.Result.Single().LastError is not null));
        Assert.Contains("winche-sync", (await app.Service<ProviderSyncs>().StatusAsync()).Single().LastError);
    }
}
