using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Winche.Auth.Tests;

[Collection("postgres")]
public class ProviderTests(PostgresFixture pg)
{
    private static readonly RsaSecurityKey GoogleKey = new(RSA.Create(2048)) { KeyId = "g1" };
    private static readonly RsaSecurityKey KeycloakKey = new(RSA.Create(2048)) { KeyId = "k1" };
    private const string KeycloakIssuer = "https://idp.test/realms/example";

    private static string Google(string sub, string? email = "ann@gmail.com", bool verified = true, string aud = "app.apps.googleusercontent.com",
        string? nonce = null, DateTime? expires = null, SecurityKey? key = null)
    {
        var claims = new Dictionary<string, object> { ["sub"] = sub, ["name"] = "Ann Google", ["picture"] = "https://lh3.example.com/ann.png" };
        if (email is not null) { claims["email"] = email; claims["email_verified"] = verified; }
        if (nonce is not null) claims["nonce"] = nonce;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://accounts.google.com", Audience = aud, Claims = claims,
            IssuedAt = (expires ?? DateTime.UtcNow.AddMinutes(5)).AddMinutes(-10), NotBefore = (expires ?? DateTime.UtcNow.AddMinutes(5)).AddMinutes(-10),
            Expires = expires ?? DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(key ?? GoogleKey, SecurityAlgorithms.RsaSha256),
        });
    }

    private static string Keycloak(string sub, string? role) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = KeycloakIssuer, Audience = "clinic-app", Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = role is null
                ? new Dictionary<string, object> { ["sub"] = sub, ["email"] = "kc@example.com", ["email_verified"] = true }
                : new Dictionary<string, object> { ["sub"] = sub, ["email"] = "kc@example.com", ["email_verified"] = true, ["role"] = role },
            SigningCredentials = new SigningCredentials(KeycloakKey, SecurityAlgorithms.RsaSha256),
        });

    private Task<TestApp> Start(Action<WincheAuthOptions>? more = null) => pg.NewDatabaseAsync().ContinueWith(db => TestApp.StartAsync(db.Result, auth: o =>
    {
        o.Google(g => { g.Audiences = ["app.apps.googleusercontent.com"]; g.SigningKeys = [GoogleKey]; });
        o.OpenIdConnect("keycloak", k =>
        {
            k.Authority = KeycloakIssuer;
            k.Audiences = ["clinic-app"];
            k.SigningKeys = [KeycloakKey];
            k.UseSubjectAsUid = true;
            k.DisplayName = "Example Health Keycloak";
            k.MapClaims("role");
        });
        more?.Invoke(o);
    })).Unwrap();

    private static object Idp(string provider, string idToken, string? nonce = null) => new { provider, idToken, nonce };

    [Fact]
    public async Task Google_sign_in_makes_the_user_once_and_signs_them_in_after()
    {
        await using var app = await Start();
        var s = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("google", Google("g-123"))));
        var user = s.Body.GetProperty("user");
        Assert.Equal("ann@gmail.com", user.GetProperty("email").GetString());
        Assert.True(user.GetProperty("emailVerified").GetBoolean());
        Assert.Equal("Ann Google", user.GetProperty("displayName").GetString());
        Assert.Equal(["google"], user.GetProperty("providers").EnumerateArray().Select(p => p.GetString()));
        Assert.Equal("google", (await app.WhoAmI(s.AccessToken)).GetProperty("provider").GetString());

        var again = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("google", Google("g-123"))));
        Assert.Equal(s.Uid, again.Uid);
        Assert.Equal(1, (await app.Scoped(a => a.ListUsersAsync())).Total);

        var providers = await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/auth/v1/providers", null));
        Assert.Equal(["google", "keycloak"], providers.GetProperty("providers").EnumerateArray().Select(p => p.GetProperty("name").GetString()));
    }

    [Fact]
    public async Task Bad_tokens_are_refused()
    {
        await using var app = await Start();
        async Task<(int, string)> Try(string token, string? nonce = null) => await TestApp.Error(await app.PostAsync("/auth/v1/signIn/idp", Idp("google", token, nonce)));
        Assert.Equal((401, "INVALID_ID_TOKEN"), await Try(Google("g-1", aud: "someone-else")));
        Assert.Equal((401, "INVALID_ID_TOKEN"), await Try(Google("g-1", expires: DateTime.UtcNow.AddMinutes(-10))));
        Assert.Equal((401, "INVALID_ID_TOKEN"), await Try(Google("g-1", key: new RsaSecurityKey(RSA.Create(2048)) { KeyId = "g1" })));
        Assert.Equal((401, "INVALID_ID_TOKEN"), await Try(Google("g-1", nonce: "abc"), nonce: "xyz"));
        Assert.Equal((401, "INVALID_ID_TOKEN"), await Try("not-a-token"));
        Assert.Equal((401, "INVALID_ID_TOKEN"), await Try(Unsigned("https://accounts.google.com", "app.apps.googleusercontent.com", "g-1")));   // not allowed here
        Assert.Equal((400, "SIGN_IN_METHOD_NOT_ENABLED"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/idp", Idp("facebook", Google("g-1")))));

        // A matching nonce: as sent (Google) or its SHA-256 (Apple).
        await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("google", Google("g-1", nonce: "abc"), "abc")));
        var hashed = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("raw-nonce")));
        await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("google", Google("g-1", nonce: hashed), "raw-nonce")));
    }

    [Fact]
    public async Task An_existing_email_account_must_link_the_provider_itself()
    {
        await using var app = await Start();
        var ann = await app.SignUpAsync("ann@gmail.com");
        Assert.Equal((409, "ACCOUNT_EXISTS_WITH_OTHER_METHOD"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/idp", Idp("google", Google("g-123")))));
        // An address the provider hasn't verified doesn't count: a separate account, without the address.
        var other = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("google", Google("g-999", verified: false))));
        Assert.NotEqual(ann.Uid, other.Uid);
        Assert.Equal(System.Text.Json.JsonValueKind.Null, other.Body.GetProperty("user").GetProperty("email").ValueKind);

        var linked = await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", Idp("google", Google("g-123")), ann.AccessToken));
        Assert.Equal(["password", "google"], linked.Body.GetProperty("user").GetProperty("providers").EnumerateArray().Select(p => p.GetString()));
        Assert.Equal(ann.Uid, (await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("google", Google("g-123"))))).Uid);

        // That Google account belongs to Ann now; and Ann can't link a second one.
        Assert.Equal((409, "CREDENTIAL_ALREADY_IN_USE"), await TestApp.Error(await app.PostAsync("/auth/v1/link/idp", Idp("google", Google("g-123")), other.AccessToken)));
        Assert.Equal((409, "PROVIDER_ALREADY_LINKED"), await TestApp.Error(await app.PostAsync("/auth/v1/link/idp", Idp("google", Google("g-555", email: null)), ann.AccessToken)));

        // Unlinking: fine while a password remains; not the last way in.
        var after = await TestApp.Json(await app.PostAsync("/auth/v1/unlink", new { provider = "google" }, ann.AccessToken));
        Assert.Equal(["password"], after.GetProperty("providers").EnumerateArray().Select(p => p.GetString()));
        Assert.Equal((400, "LAST_SIGN_IN_METHOD"), await TestApp.Error(await app.PostAsync("/auth/v1/unlink", new { provider = "google" }, other.AccessToken)));
    }

    [Fact]
    public async Task A_guest_keeps_their_uid_when_they_link_Google()
    {
        await using var app = await Start();
        var guest = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/anonymous"));
        var linked = await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", Idp("google", Google("g-7", email: "guest@gmail.com")), guest.AccessToken));
        Assert.Equal(guest.Uid, linked.Uid);
        var user = linked.Body.GetProperty("user");
        Assert.False(user.GetProperty("isAnonymous").GetBoolean());
        Assert.Equal("guest@gmail.com", user.GetProperty("email").GetString());
        Assert.Equal(guest.Uid, (await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("google", Google("g-7", email: "guest@gmail.com"))))).Uid);
    }

    [Fact]
    public async Task Keycloak_users_keep_their_ids_and_roles_follow_each_sign_in()
    {
        await using var app = await Start();
        var s = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("keycloak", Keycloak("6f1c2a9e-1b2c-4d5e-8f90-123456789abc", "clinician"))));
        Assert.Equal("6f1c2a9e-1b2c-4d5e-8f90-123456789abc", s.Uid);   // existing users/{uid} documents still match
        var claims = await app.WhoAmI(s.AccessToken);
        Assert.Equal("clinician", claims.GetProperty("role").GetString());
        Assert.Equal("keycloak", claims.GetProperty("provider").GetString());

        var promoted = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("keycloak", Keycloak("6f1c2a9e-1b2c-4d5e-8f90-123456789abc", "admin"))));
        Assert.Equal("admin", (await app.WhoAmI(promoted.AccessToken)).GetProperty("role").GetString());
        var demoted = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("keycloak", Keycloak("6f1c2a9e-1b2c-4d5e-8f90-123456789abc", null))));
        Assert.False((await app.WhoAmI(demoted.AccessToken)).TryGetProperty("role", out _));
    }

    [Fact]
    public async Task Unsigned_tokens_only_where_allowed_for_testing()
    {
        await using var app = await Start(o => o.Apple(a => { a.Audiences = ["com.example.app"]; a.AllowUnsignedTokensForTesting = true; }));
        var s = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("apple", Unsigned("https://appleid.apple.com", "com.example.app", "apple-1", "a@privaterelay.appleid.com", "true"))));
        Assert.Equal("a@privaterelay.appleid.com", s.Body.GetProperty("user").GetProperty("email").GetString());
        Assert.True(s.Body.GetProperty("user").GetProperty("emailVerified").GetBoolean());   // Apple's "true" string
        Assert.Equal((401, "INVALID_ID_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/idp", Idp("apple", Unsigned("https://appleid.apple.com", "someone-else", "apple-1")))));
    }

    private static string KeycloakSession(string sub, string sid) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = KeycloakIssuer, Audience = "clinic-app", Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = new Dictionary<string, object> { ["sub"] = sub, ["sid"] = sid, ["email"] = "kc@example.com", ["email_verified"] = true },
            SigningCredentials = new SigningCredentials(KeycloakKey, SecurityAlgorithms.RsaSha256),
        });

    private static string LogoutToken(string? sid, string? sub, SecurityKey? key = null, bool withNonce = false)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("n"),
            ["events"] = new Dictionary<string, object> { ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>() },
        };
        if (sid is not null) claims["sid"] = sid;
        if (sub is not null) claims["sub"] = sub;
        if (withNonce) claims["nonce"] = "n";
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = KeycloakIssuer, Audience = "clinic-app", IssuedAt = DateTime.UtcNow, Claims = claims,
            SigningCredentials = new SigningCredentials(key ?? KeycloakKey, SecurityAlgorithms.RsaSha256),
        });
    }

    private async Task<HttpResponseMessage> BackChannelAsync(TestApp app, string token) =>
        await app.Client.PostAsync("/auth/v1/providers/keycloak/backchannel-logout",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["logout_token"] = token }));

    [Fact]
    public async Task A_providers_back_channel_logout_ends_the_session_it_names_or_every_session_of_the_person_it_names()
    {
        await using var app = await Start();
        var a = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("keycloak", KeycloakSession("kc-1", "sid-a"))));
        var b = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", Idp("keycloak", KeycloakSession("kc-1", "sid-b"))));

        // Not a logout token, a forged one, or one with a nonce: refused, nothing ends.
        Assert.Equal(400, (int)(await BackChannelAsync(app, "x")).StatusCode);
        Assert.Equal(400, (int)(await BackChannelAsync(app, LogoutToken("sid-a", null, new RsaSecurityKey(RSA.Create(2048)) { KeyId = "k1" }))).StatusCode);
        Assert.Equal(400, (int)(await BackChannelAsync(app, LogoutToken("sid-a", null, withNonce: true))).StatusCode);

        // Its session: that one ends, the other carries on.
        Assert.Equal(200, (int)(await BackChannelAsync(app, LogoutToken("sid-a", "kc-1"))).StatusCode);
        Assert.Equal((401, "INVALID_REFRESH_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/token", new { refreshToken = a.RefreshToken })));
        var b2 = await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = b.RefreshToken }));

        // The person (no sid): every session of theirs from the provider ends.
        Assert.Equal(200, (int)(await BackChannelAsync(app, LogoutToken(null, "kc-1"))).StatusCode);
        Assert.Equal((401, "INVALID_REFRESH_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/token", new { refreshToken = b2.RefreshToken })));
        // Someone who never signed in here: nothing to end, still fine.
        Assert.Equal(200, (int)(await BackChannelAsync(app, LogoutToken(null, "kc-nobody"))).StatusCode);
    }

    private static string Unsigned(string iss, string aud, string sub, string? email = null, string? verified = null)
    {
        var payload = new Dictionary<string, object> { ["iss"] = iss, ["aud"] = aud, ["sub"] = sub, ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() };
        if (email is not null) payload["email"] = email;
        if (verified is not null) payload["email_verified"] = verified;
        return $"{Base64UrlEncoder.Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}")}.{Base64UrlEncoder.Encode(System.Text.Json.JsonSerializer.Serialize(payload))}.";
    }
}
