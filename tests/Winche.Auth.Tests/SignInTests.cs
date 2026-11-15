using System.Net;
using Microsoft.Extensions.Time.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Winche.Auth.Tests;

[Collection("postgres")]
public class SignInTests(PostgresFixture pg)
{
    [Fact]
    public async Task Sign_up_and_sign_in_give_tokens_the_rules_can_read()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var s = await app.SignUpAsync("ann@example.com");
        Assert.Equal(28, s.Uid.Length);
        Assert.Equal(900, s.Body.GetProperty("expiresIn").GetInt32());

        var me = await app.WhoAmI(s.AccessToken);
        Assert.Equal(s.Uid, me.GetProperty("uid").GetString());
        Assert.Equal(s.Uid, me.GetProperty("sub").GetString());
        Assert.Equal("winche", me.GetProperty("issuer").GetString());
        Assert.Equal("password", me.GetProperty("provider").GetString());
        Assert.Equal("ann@example.com", me.GetProperty("email").GetString());
        Assert.False(me.GetProperty("email_verified").GetBoolean());
        Assert.True((await app.WhoAmI(null)).GetProperty("signedOut").GetBoolean());
        Assert.True((await app.WhoAmI("not.a.token")).GetProperty("signedOut").GetBoolean());

        var profile = await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/auth/v1/me", s.AccessToken));
        Assert.Equal(["password"], profile.GetProperty("providers").EnumerateArray().Select(p => p.GetString()));
        Assert.Equal(401, (int)(await app.SendAsync(HttpMethod.Get, "/auth/v1/me", null)).StatusCode);

        var signedIn = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ANN@example.com", password = "correct horse battery" }));
        Assert.Equal(s.Uid, signedIn.Uid);

        Assert.Equal((409, "EMAIL_EXISTS"), await TestApp.Error(await app.PostAsync("/auth/v1/signUp", new { email = "Ann@Example.com", password = "another long one" })));
        Assert.Equal((400, "WEAK_PASSWORD"), await TestApp.Error(await app.PostAsync("/auth/v1/signUp", new { email = "bob@example.com", password = "short" })));
        Assert.Equal((400, "INVALID_EMAIL"), await TestApp.Error(await app.PostAsync("/auth/v1/signUp", new { email = "bob", password = "correct horse battery" })));
        // A wrong password and an unknown email look the same.
        Assert.Equal((401, "INVALID_CREDENTIALS"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "wrong password!" })));
        Assert.Equal((401, "INVALID_CREDENTIALS"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "nobody@example.com", password = "wrong password!" })));
    }

    [Fact]
    public async Task Repeated_failures_lock_the_account()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), auth: o => o.MaxFailedSignIns = 3);
        await app.SignUpAsync("ann@example.com");
        for (var i = 0; i < 2; i++)
            Assert.Equal("INVALID_CREDENTIALS", (await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "wrong password!" }))).Code);
        Assert.Equal((429, "LOCKED_OUT"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "wrong password!" })));
        Assert.Equal((429, "LOCKED_OUT"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" })));
    }

    [Fact]
    public async Task Refresh_replaces_the_token_and_a_reused_one_ends_the_session()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddSingleton<TimeProvider>(clock));
        var s = await app.SignUpAsync("ann@example.com");

        var r2 = await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = s.RefreshToken }));
        Assert.NotEqual(s.RefreshToken, r2.RefreshToken);
        Assert.Equal(s.Uid, (await app.WhoAmI(r2.AccessToken)).GetProperty("uid").GetString());

        // The old one again within seconds (two refreshes racing): refused, the session lives on.
        Assert.Equal((401, "INVALID_REFRESH_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/token", new { refreshToken = s.RefreshToken })));
        var r3 = await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = r2.RefreshToken }));

        // Later: someone copied it. The whole session ends.
        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(401, (int)(await app.PostAsync("/auth/v1/token", new { refreshToken = r2.RefreshToken })).StatusCode);
        Assert.Equal((401, "INVALID_REFRESH_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/token", new { refreshToken = r3.RefreshToken })));

        // Signing out ends a session; garbage is refused.
        var other = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
        Assert.Equal(HttpStatusCode.NoContent, (await app.PostAsync("/auth/v1/signOut", new { refreshToken = other.RefreshToken })).StatusCode);
        Assert.Equal(401, (int)(await app.PostAsync("/auth/v1/token", new { refreshToken = other.RefreshToken })).StatusCode);
        Assert.Equal(401, (int)(await app.PostAsync("/auth/v1/token", new { refreshToken = "nonsense" })).StatusCode);
    }

    [Fact]
    public async Task Anonymous_users_upgrade_to_a_password_and_keep_their_uid()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var guest = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/anonymous"));
        var claims = await app.WhoAmI(guest.AccessToken);
        Assert.True(claims.GetProperty("anonymous").GetBoolean());
        Assert.Equal("anonymous", claims.GetProperty("provider").GetString());
        Assert.False(claims.TryGetProperty("email", out _));

        var linked = await app.SessionAsync(await app.PostAsync("/auth/v1/link/password", new { email = "guest@example.com", password = "correct horse battery" }, guest.AccessToken));
        Assert.Equal(guest.Uid, linked.Uid);
        Assert.False(linked.Body.GetProperty("user").GetProperty("isAnonymous").GetBoolean());
        Assert.Equal("guest@example.com", (await app.WhoAmI(linked.AccessToken)).GetProperty("email").GetString());
        Assert.Equal(guest.Uid, (await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "guest@example.com", password = "correct horse battery" }))).Uid);
        Assert.Equal((400, "NOT_ANONYMOUS"), await TestApp.Error(await app.PostAsync("/auth/v1/link/password", new { email = "x@example.com", password = "correct horse battery" }, linked.AccessToken)));
    }

    [Fact]
    public async Task Sign_in_methods_that_arent_on_are_refused()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), methods: false);
        Assert.Equal((400, "SIGN_IN_METHOD_NOT_ENABLED"), await TestApp.Error(await app.PostAsync("/auth/v1/signUp", new { email = "ann@example.com", password = "correct horse battery" })));
        Assert.Equal((400, "SIGN_IN_METHOD_NOT_ENABLED"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" })));
        Assert.Equal((400, "SIGN_IN_METHOD_NOT_ENABLED"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/anonymous")));

        // Users made by your code can still be signed in through it.
        var uid = (await app.Scoped(a => a.CreateUserAsync("ann@example.com", null, "Ann"))).Uid;
        var tokens = await app.Scoped(a => a.SignInAsUserAsync(uid, AuthRequestInfo.Server));
        var claims = await app.WhoAmI(tokens.AccessToken);
        Assert.Equal("custom", claims.GetProperty("provider").GetString());
        Assert.Equal("Ann", claims.GetProperty("name").GetString());
    }

    [Fact]
    public async Task Changing_the_password_ends_other_sessions()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var phone = await app.SignUpAsync("ann@example.com");
        var laptop = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));

        Assert.Equal((401, "INVALID_CREDENTIALS"), await TestApp.Error(await app.PostAsync("/auth/v1/me/password", new { currentPassword = "nope nope nope", newPassword = "a brand new password" }, laptop.AccessToken)));
        var renewed = await app.SessionAsync(await app.PostAsync("/auth/v1/me/password", new { currentPassword = "correct horse battery", newPassword = "a brand new password" }, laptop.AccessToken));

        Assert.Equal(401, (int)(await app.PostAsync("/auth/v1/token", new { refreshToken = phone.RefreshToken })).StatusCode);
        Assert.Equal(401, (int)(await app.PostAsync("/auth/v1/token", new { refreshToken = laptop.RefreshToken })).StatusCode);
        await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = renewed.RefreshToken }));
        Assert.Equal(401, (int)(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" })).StatusCode);
        await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "a brand new password" }));
    }

    [Fact]
    public async Task Tokens_are_ES256_with_a_published_key_that_rotates()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var s = await app.SignUpAsync("ann@example.com");
        var jwt = new JsonWebToken(s.AccessToken);
        Assert.Equal("ES256", jwt.Alg);
        Assert.Equal(TestApp.Issuer, jwt.Issuer);
        Assert.Equal([TestApp.Issuer], jwt.Audiences);

        var jwks = await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/.well-known/jwks.json", null));
        Assert.Contains(jwt.Kid, jwks.GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()));
        Assert.False(jwks.GetProperty("keys")[0].TryGetProperty("d", out _));   // public parts only
        var discovery = await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/.well-known/openid-configuration", null));
        Assert.Equal("https://api.test/.well-known/jwks.json", discovery.GetProperty("jwks_uri").GetString());

        await app.Service<Winche.Auth.Tokens.SigningKeyStore>().RotateAsync();
        var after = await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = s.RefreshToken }));
        Assert.NotEqual(jwt.Kid, new JsonWebToken(after.AccessToken).Kid);
        Assert.Equal(s.Uid, (await app.WhoAmI(s.AccessToken)).GetProperty("uid").GetString());   // the retired key still checks
        var keys = await app.Service<Winche.Auth.Tokens.SigningKeyStore>().ListAsync();
        Assert.Equal(2, keys.Count);
        Assert.Null(keys[0].RetiredAt);
        Assert.NotNull(keys[1].RetiredAt);
    }

    [Fact]
    public async Task It_shares_a_database_with_other_Identity_tables()
    {
        var db = await pg.NewDatabaseAsync();
        await using (var conn = new Npgsql.NpgsqlConnection(db))
        {
            await conn.OpenAsync();
            // What the Winche console's own Identity tables create.
            await using var cmd = new Npgsql.NpgsqlCommand("""
                CREATE TABLE "AspNetUsers" ("NormalizedUserName" text, "NormalizedEmail" text);
                CREATE UNIQUE INDEX "UserNameIndex" ON "AspNetUsers" ("NormalizedUserName");
                CREATE INDEX "EmailIndex" ON "AspNetUsers" ("NormalizedEmail");
                CREATE TABLE "__EFMigrationsHistory" ("MigrationId" varchar(150) PRIMARY KEY, "ProductVersion" varchar(32) NOT NULL);
                """, conn);
            await cmd.ExecuteNonQueryAsync();
        }
        // …and the app's other Identity setup doesn't change Winche Auth's rules.
        await using var app = await TestApp.StartAsync(db, auth: o => o.MaxFailedSignIns = 2, services: s => s.PostConfigure<Microsoft.AspNetCore.Identity.IdentityOptions>(o =>
        {
            o.Password.RequiredLength = 30;
            o.Password.RequireDigit = true;
            o.User.RequireUniqueEmail = true;
            o.Lockout.MaxFailedAccessAttempts = 99;
        }));
        await app.SignUpAsync("ann@example.com", "ten chars!");
        await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/anonymous"));
        await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "wrong password" });
        Assert.Equal((429, "LOCKED_OUT"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "wrong password" })));
    }

    [Fact]
    public async Task Signing_keys_can_be_encrypted_at_rest()
    {
        var db = await pg.NewDatabaseAsync();
        const string secret = "a-very-long-key-encryption-secret-123456";
        await using (var app = await TestApp.StartAsync(db, auth: o => o.KeyEncryptionSecret = secret))
        {
            var s = await app.SignUpAsync("ann@example.com");
            Assert.Equal(s.Uid, (await app.WhoAmI(s.AccessToken)).GetProperty("uid").GetString());
        }
        await using var conn = new Npgsql.NpgsqlConnection(db);
        await conn.OpenAsync();
        await using var cmd = new Npgsql.NpgsqlCommand("SELECT bool_and(\"Encrypted\") FROM auth_signing_keys", conn);
        Assert.True((bool)(await cmd.ExecuteScalarAsync())!);

        // Same secret, another instance: the keys load.
        await using var again = await TestApp.StartAsync(db, auth: o => o.KeyEncryptionSecret = secret);
        await again.SessionAsync(await again.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
    }

    [Fact]
    public async Task Without_their_own_secret_signing_keys_are_encrypted_with_the_master_key()
    {
        var db = await pg.NewDatabaseAsync();
        var keys = new Winche.Core.WincheKeys(new string('m', 40));
        await using (var app = await TestApp.StartAsync(db, services: s => s.AddSingleton(keys), auth: o => o.KeyEncryptionSecret = null))
            await app.SignUpAsync("ann@example.com");
        await using var conn = new Npgsql.NpgsqlConnection(db);
        await conn.OpenAsync();
        await using var cmd = new Npgsql.NpgsqlCommand("SELECT bool_and(\"Encrypted\") FROM auth_signing_keys", conn);
        Assert.True((bool)(await cmd.ExecuteScalarAsync())!);
        await using var again = await TestApp.StartAsync(db, services: s => s.AddSingleton(keys), auth: o => o.KeyEncryptionSecret = null);
        await again.SessionAsync(await again.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
    }

    [Fact]
    public async Task After_a_master_key_change_signing_keys_are_read_with_the_previous_one_and_re_encrypted()
    {
        var db = await pg.NewDatabaseAsync();
        string oldKey = new('o', 40), newKey = new('n', 40);
        await using (var app = await TestApp.StartAsync(db, services: s => s.AddSingleton(new Winche.Core.WincheKeys(oldKey)), auth: o => o.KeyEncryptionSecret = null))
            await app.SignUpAsync("ann@example.com");
        async Task<byte[]> Stored()
        {
            await using var conn = new Npgsql.NpgsqlConnection(db);
            await conn.OpenAsync();
            await using var cmd = new Npgsql.NpgsqlCommand("SELECT \"PrivateKey\" FROM auth_signing_keys ORDER BY \"Kid\" LIMIT 1", conn);
            return (byte[])(await cmd.ExecuteScalarAsync())!;
        }
        var before = await Stored();

        // The new key alone can't start; with the old one as previous it starts, and the key moves to the new one.
        await Assert.ThrowsAnyAsync<Exception>(() => TestApp.StartAsync(db, services: s => s.AddSingleton(new Winche.Core.WincheKeys(newKey)), auth: o => o.KeyEncryptionSecret = null));
        await using (var rotating = await TestApp.StartAsync(db, services: s => s.AddSingleton(new Winche.Core.WincheKeys(newKey, [oldKey])), auth: o => o.KeyEncryptionSecret = null))
            await rotating.SessionAsync(await rotating.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
        Assert.NotEqual(before, await Stored());
        await using var after = await TestApp.StartAsync(db, services: s => s.AddSingleton(new Winche.Core.WincheKeys(newKey)), auth: o => o.KeyEncryptionSecret = null);
        await after.SessionAsync(await after.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
    }

    [Fact]
    public async Task Set_up_on_demand_auth_makes_its_tables_and_signing_key_only_when_its_setup_runs()
    {
        var db = await pg.NewDatabaseAsync();
        await using var app = await TestApp.StartAsync(db, services: s => Winche.Core.WincheProductSetupExtensions.AddWincheProductSetupOnDemand(s));
        async Task<bool> Has(string table)
        {
            await using var conn = new Npgsql.NpgsqlConnection(db);
            await conn.OpenAsync();
            await using var cmd = new Npgsql.NpgsqlCommand($"SELECT to_regclass('public.{table}') IS NOT NULL", conn);
            return (bool)(await cmd.ExecuteScalarAsync())!;
        }
        await Task.Delay(200);
        Assert.False(await Has("auth_users"));

        var setup = app.App.Services.GetServices<Winche.Core.IWincheProductSetup>().Single(x => x.Product == Winche.Core.WincheProductNames.Authentication);
        Assert.Equal(3, setup.Steps.Count);
        await Winche.Core.WincheProductSetupExtensions.RunAllAsync(setup);
        Assert.True(await Has("auth_users"));
        app.App.Services.GetRequiredService<Winche.Core.WincheProductReadiness>().MarkReady(Winche.Core.WincheProductNames.Authentication);
        await app.SignUpAsync("ann@example.com");
    }

    private sealed class Sink : IWincheChangeSink
    {
        public List<WincheChange> Changes { get; } = [];
        public Task OnChangesAsync(IReadOnlyList<WincheChange> changes, CancellationToken ct)
        {
            lock (Changes) Changes.AddRange(changes);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task User_events_reach_every_change_sink_and_auth_offers_its_action()
    {
        var sink = new Sink();
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddSingleton<IWincheChangeSink>(sink));
        var session = await app.SignUpAsync("ann@example.com");
        for (var i = 0; i < 200; i++) { lock (sink.Changes) if (sink.Changes.Any(c => c.Type == "created")) break; await Task.Delay(25); }   // delivered after the commit
        var created = Assert.Single(sink.Changes, c => c.Type == "created");
        Assert.Equal(("auth", session.Uid, "ann@example.com"), (created.Source, created.Variables["uid"], created.Variables["email"]));
        Assert.Contains(app.App.Services.GetServices<WincheChangeSource>(), s => s.Name == "auth");
    }
}
