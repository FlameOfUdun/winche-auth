using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.AspNetCore;
using Winche.Database.AspNetCore.DependencyInjection;
using Winche.Database.AspNetCore.Rest.DependencyInjection;
using Winche.Database.DependencyInjection;

namespace Winche.Auth.Tests;

[Collection("postgres")]
public class TrustedIssuerTests(PostgresFixture pg)
{
    private const string KeycloakIssuer = "https://idp.test/realms/example";
    private static readonly RsaSecurityKey Keycloak = new(RSA.Create(2048)) { KeyId = "kc1" };

    private static string KeycloakToken(string sub, string audience = "clinic-api", string issuer = KeycloakIssuer, SecurityKey? key = null) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = new Dictionary<string, object> { ["sub"] = sub, ["role"] = "clinician", ["email"] = "kc@example.com", ["session_state"] = "secret-ish" },
            SigningCredentials = new SigningCredentials(key ?? Keycloak, SecurityAlgorithms.RsaSha256),
        });

    private static void TrustKeycloak(WincheTokenOptions t) => t.TrustIssuer("keycloak", i =>
    {
        i.Issuer = KeycloakIssuer;
        i.SigningKeys = [Keycloak];
        i.Audience = "clinic-api";
        i.MapClaims("role");
    });

    [Fact]
    public async Task Tokens_from_a_trusted_issuer_are_accepted_as_they_are()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), trust: TrustKeycloak);
        var claims = await app.WhoAmI(KeycloakToken("kc-123"));
        Assert.Equal("kc-123", claims.GetProperty("uid").GetString());
        Assert.Equal("keycloak", claims.GetProperty("issuer").GetString());
        Assert.Equal("clinician", claims.GetProperty("role").GetString());
        Assert.Equal("kc@example.com", claims.GetProperty("email").GetString());
        Assert.False(claims.TryGetProperty("session_state", out _));   // not in MapClaims

        // Winche's own tokens work beside them.
        var s = await app.SignUpAsync("ann@example.com");
        Assert.Equal("winche", (await app.WhoAmI(s.AccessToken)).GetProperty("issuer").GetString());

        // Wrong audience, unknown issuer, or a forged signature: signed out.
        Assert.True((await app.WhoAmI(KeycloakToken("kc-123", audience: "other"))).TryGetProperty("signedOut", out _));
        Assert.True((await app.WhoAmI(KeycloakToken("kc-123", issuer: "https://evil.test"))).TryGetProperty("signedOut", out _));
        Assert.True((await app.WhoAmI(KeycloakToken("kc-123", key: new RsaSecurityKey(RSA.Create(2048)) { KeyId = "kc1" }))).TryGetProperty("signedOut", out _));
        // A token claiming Winche's issuer but signed by someone else.
        Assert.True((await app.WhoAmI(KeycloakToken("kc-123", issuer: TestApp.Issuer, audience: TestApp.Issuer))).TryGetProperty("signedOut", out _));

        // Their users aren't Winche Auth users.
        Assert.Equal(401, (int)(await app.SendAsync(HttpMethod.Get, "/auth/v1/me", KeycloakToken("kc-123"))).StatusCode);
    }

    [Fact]
    public async Task Claims_are_found_when_the_app_has_its_own_default_scheme()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), trust: TrustKeycloak,
            services: s => s.AddAuthentication(o => o.DefaultScheme = "AppCookie").AddCookie("AppCookie"));
        var ann = await app.SignUpAsync("ann@example.com");
        Assert.Equal(ann.Uid, (await app.WhoAmI(ann.AccessToken)).GetProperty("uid").GetString());
        Assert.Equal("kc-1", (await app.WhoAmI(KeycloakToken("kc-1"))).GetProperty("uid").GetString());
        Assert.True((await app.WhoAmI(null)).TryGetProperty("signedOut", out _));
    }

    [Fact]
    public async Task External_issuers_alone_need_no_Winche_Auth()
    {
        await using var app = await TestApp.StartAsync(null, trust: TrustKeycloak, trustWinche: false);
        Assert.Equal("kc-9", (await app.WhoAmI(KeycloakToken("kc-9"))).GetProperty("uid").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await app.PostAsync("/auth/v1/signIn", new { })).StatusCode);
    }

    [Fact]
    public async Task Database_rules_see_the_uid_from_either_issuer()
    {
        var db = await pg.NewDatabaseAsync();
        await using var app = await TestApp.StartAsync(db, trust: TrustKeycloak,
            services: s => s.AddWincheDatabase(o =>
            {
                o.ConnectionString = db;
                o.MapClaims(WincheClaims.From);
                o.UseRulesText("""
                    match users/{uid} {
                      allow read, write: if request.auth.uid == uid;
                    }
                    match staff/{doc} {
                      allow read: if request.auth.token.role == 'clinician' && request.auth.token.issuer == 'keycloak';
                    }
                    """);
            }),
            map: app =>
            {
                app.InitializeWincheDatabaseAsync().GetAwaiter().GetResult();
                app.MapWincheDatabaseRestApi();
            });

        var ann = await app.SignUpAsync("ann@example.com");
        Assert.Equal(HttpStatusCode.OK, (await Put(app, $"users/{ann.Uid}", ann.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Put(app, "users/someone-else", ann.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Put(app, $"users/{ann.Uid}", null)).StatusCode);

        var kc = KeycloakToken("kc-123");
        Assert.Equal(HttpStatusCode.OK, (await Put(app, "users/kc-123", kc)).StatusCode);
        Assert.NotEqual(HttpStatusCode.Forbidden, (await Get(app, "staff/rota", kc)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Get(app, "staff/rota", ann.AccessToken)).StatusCode);
    }

    private static string DocPath(string path) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(path));

    private static async Task<HttpResponseMessage> Put(TestApp app, string path, string? bearer)
    {
        using var req = new HttpRequestMessage(HttpMethod.Put, $"/documents/v1/{DocPath(path)}")
        {
            Content = JsonContent.Create(new { fields = new { name = new { stringValue = "x" } } }),
        };
        if (bearer is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await app.Client.SendAsync(req);
    }

    private static async Task<HttpResponseMessage> Get(TestApp app, string path, string? bearer)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"/documents/v1/{DocPath(path)}");
        if (bearer is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await app.Client.SendAsync(req);
    }
}
