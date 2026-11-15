using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.AspNetCore;
using Winche.Core;

namespace Winche.Auth.Tests;

/// <summary>A tiny OpenID Connect provider on a real port: discovery and keys, like Keycloak serves them.</summary>
public sealed class FakeOidcProvider : IAsyncDisposable
{
    private readonly WebApplication _app;
    public RsaSecurityKey Key { get; } = new(RSA.Create(2048)) { KeyId = "OqSi2" };
    public string Issuer { get; }

    private FakeOidcProvider(WebApplication app, string issuer) { _app = app; Issuer = issuer; }

    public static async Task<FakeOidcProvider> StartAsync()
    {
        var b = WebApplication.CreateBuilder();
        b.WebHost.UseUrls("http://127.0.0.1:0");
        b.Logging.ClearProviders();
        var app = b.Build();
        FakeOidcProvider? self = null;
        app.MapGet("/realms/clinic/.well-known/openid-configuration", () => Results.Json(new Dictionary<string, object>
        {
            ["issuer"] = self!.Issuer, ["jwks_uri"] = self.Issuer + "/protocol/openid-connect/certs",
            ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
        }));
        app.MapGet("/realms/clinic/protocol/openid-connect/certs", () =>
        {
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(self!.Key.Rsa.ExportParameters(false)) { KeyId = self.Key.KeyId });
            return Results.Json(new { keys = new[] { new { kty = jwk.Kty, kid = jwk.Kid, use = "sig", alg = "RS256", n = jwk.N, e = jwk.E } } });
        });
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        self = new FakeOidcProvider(app, address.TrimEnd('/') + "/realms/clinic");
        return self;
    }

    public string Token(string sub, string audience = "clinic-api", DateTime? expires = null, string[]? roles = null) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer, Audience = audience,
            IssuedAt = (expires ?? DateTime.UtcNow.AddMinutes(5)).AddMinutes(-10), NotBefore = (expires ?? DateTime.UtcNow.AddMinutes(5)).AddMinutes(-10),
            Expires = expires ?? DateTime.UtcNow.AddMinutes(5),
            Claims = new Dictionary<string, object>
            {
                ["sub"] = sub, ["email"] = "dr.costa@example.com", ["given_name"] = "Ana", ["family_name"] = "Costa",
                ["realm_access"] = new Dictionary<string, object> { ["roles"] = roles ?? ["clinician", "trainer"] },
                ["org"] = "st-marys", ["groups"] = new[] { "/clinicians" },
            },
            SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.RsaSha256),
        });

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}

[Collection("postgres")]
public class ProviderSettingsTests(PostgresFixture pg)
{
    private static JsonNode Settings(FakeOidcProvider idp, params ClaimMapping[] claims) => System.Text.Json.JsonSerializer.SerializeToNode(new IdentityProvidersSettings
    {
        TrustWincheAuth = true,
        Providers = [new TrustedProviderSettings
        {
            Name = "keycloak", DisplayName = "Example Health Keycloak", Kind = "keycloak", Issuer = idp.Issuer, Audiences = ["clinic-api"],
            RequireHttps = false, Claims = [.. claims],
        }],
    }, SettingsArea.Json)!;

    private async Task<TestApp> Start(string db) => await TestApp.StartAsync(db,
        services: s => s.AddWincheConfig(o => o.ConnectionString = db),
        trust: t => t.UseSettings());

    [Fact]
    public async Task Providers_saved_in_settings_apply_without_a_restart()
    {
        await using var idp = await FakeOidcProvider.StartAsync();
        var db = await pg.NewDatabaseAsync();
        await using var app = await Start(db);
        var token = idp.Token("6f1c2a9e-1b2c-4d5e-8f90-123456789abc");
        Assert.True((await app.WhoAmI(token)).TryGetProperty("signedOut", out _));   // not trusted yet

        var store = app.Service<SettingsStore>();
        await store.SaveAsync(WincheAuthDefaults.SettingsArea, Settings(idp, new ClaimMapping("realm_access.roles", "roles"),
            new ClaimMapping("given_name + family_name", "name"), new ClaimMapping("org", "org")), "admin@example.com", "Trust Keycloak");

        var claims = await app.WhoAmI(token);
        Assert.Equal("6f1c2a9e-1b2c-4d5e-8f90-123456789abc", claims.GetProperty("uid").GetString());
        Assert.Equal("keycloak", claims.GetProperty("issuer").GetString());
        Assert.Equal(["clinician", "trainer"], claims.GetProperty("roles").EnumerateArray().Select(r => r.GetString()));
        Assert.Equal("Ana Costa", claims.GetProperty("name").GetString());
        Assert.Equal("dr.costa@example.com", claims.GetProperty("email").GetString());   // always passed
        Assert.False(claims.TryGetProperty("groups", out _));   // not mapped
        Assert.False(claims.TryGetProperty("realm_access", out _));

        // Winche Auth's own tokens still work beside them (the code trusted them; the settings kept it).
        var ann = await app.SignUpAsync("ann@example.com");
        Assert.Equal("winche", (await app.WhoAmI(ann.AccessToken)).GetProperty("issuer").GetString());

        // Reset to the code's values: Keycloak is no longer trusted.
        await store.ResetAsync(WincheAuthDefaults.SettingsArea, "admin@example.com", "Undo");
        Assert.True((await app.WhoAmI(token)).TryGetProperty("signedOut", out _));
    }

    [Fact]
    public async Task Bad_provider_settings_are_refused()
    {
        var db = await pg.NewDatabaseAsync();
        await using var app = await Start(db);
        var bad = System.Text.Json.JsonSerializer.SerializeToNode(new IdentityProvidersSettings
        {
            Providers =
            [
                new TrustedProviderSettings { Name = "Key Cloak", Issuer = "not a url", Audiences = [] },
                new TrustedProviderSettings { Name = "ok", Issuer = "http://insecure.example.com", Audiences = ["a"], Claims = [new("x", "uid"), new("y", "role"), new("z", "role")] },
            ],
        }, SettingsArea.Json)!;
        var ex = await Assert.ThrowsAsync<SettingsValidationException>(() => app.Service<SettingsStore>().SaveAsync(WincheAuthDefaults.SettingsArea, bad, null, null));
        Assert.Contains(ex.Errors, e => e.Contains("lower-case"));
        Assert.Contains(ex.Errors, e => e.Contains("full address"));
        Assert.Contains(ex.Errors, e => e.Contains("audience"));
        Assert.Contains(ex.Errors, e => e.Contains("https"));
        Assert.Contains(ex.Errors, e => e.Contains("'uid' can't be a name"));
        Assert.Contains(ex.Errors, e => e.Contains("'role' is set twice"));
    }

    [Fact]
    public async Task The_token_test_shows_the_checks_and_what_the_rules_see_for_a_draft()
    {
        await using var idp = await FakeOidcProvider.StartAsync();
        var db = await pg.NewDatabaseAsync();
        await using var app = await Start(db);
        var inspector = app.Service<WincheTokenInspector>();
        var draft = Settings(idp, new ClaimMapping("realm_access.roles", "roles")).Deserialize<IdentityProvidersSettings>(SettingsArea.Json)!;

        var ok = await inspector.InspectAsync("Bearer " + idp.Token("u-1"), draft);
        Assert.True(ok.WouldSignIn);
        Assert.Equal("keycloak", ok.Provider);
        Assert.Equal("ok", ok.Checks[0].Outcome);
        Assert.Contains("Example Health Keycloak (key OqSi2)", ok.Checks[0].Text);
        Assert.Contains(ok.Checks, c => c.Outcome == "warning" && c.Text.StartsWith("groups is in the token"));
        Assert.Contains(ok.Checks, c => c.Outcome == "warning" && c.Text.StartsWith("org is in the token"));
        Assert.Equal("u-1", ok.Auth!["uid"]);
        var token = (IReadOnlyDictionary<string, object?>)ok.Auth["token"]!;
        Assert.Equal(new List<object?> { "clinician", "trainer" }, token["roles"]);

        // Expired: still mapped, but marked as unable to sign in.
        var old = await inspector.InspectAsync(idp.Token("u-1", expires: DateTime.UtcNow.AddHours(-3)), draft);
        Assert.False(old.WouldSignIn);
        Assert.Contains(old.Checks, c => c.Outcome == "error" && c.Text.StartsWith("Expired 3 hours ago"));
        Assert.NotNull(old.Auth);

        // Wrong audience, untrusted issuer, garbage.
        Assert.Contains("another app", (await inspector.InspectAsync(idp.Token("u-1", audience: "other"), draft)).Checks[0].Text);
        Assert.Contains("aren't trusted", (await inspector.InspectAsync(idp.Token("u-1"))).Checks[0].Text);   // not in the saved settings
        Assert.Contains("three parts", (await inspector.InspectAsync("hello")).Checks[0].Text);
    }

    [Fact]
    public async Task Checking_a_providers_address()
    {
        await using var idp = await FakeOidcProvider.StartAsync();
        await using var app = await Start(await pg.NewDatabaseAsync());
        var inspector = app.Service<WincheTokenInspector>();
        var found = await inspector.CheckProviderAsync(idp.Issuer, requireHttps: false);
        Assert.True(found.Found, found.Error);
        Assert.Equal((1, "RS256"), (found.Keys, found.Algorithms.Single()));
        var mismatch = await inspector.CheckProviderAsync(idp.Issuer + "-typo", idp.Issuer, requireHttps: false);
        Assert.False(mismatch.Found);
        Assert.Contains("calls itself", mismatch.Error);
        var nowhere = await inspector.CheckProviderAsync("http://127.0.0.1:1/realms/x", requireHttps: false);
        Assert.False(nowhere.Found);
        Assert.Contains("Couldn't read", nowhere.Error);
        Assert.False((await inspector.CheckProviderAsync(idp.Issuer)).Found);   // https required by default
    }
}
