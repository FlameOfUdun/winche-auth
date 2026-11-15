using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.Email;
using Winche.Auth.Mfa;
using Winche.Auth.AspNetCore;

namespace Winche.Auth.Tests;

/// <summary>Each account-takeover and bypass path the step-1 review found, end to end.</summary>
[Collection("postgres")]
public class SecurityTests(PostgresFixture pg)
{
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.UtcNow);
    private const string Password = "correct horse battery";

    private async Task<(TestApp App, Outbox Outbox)> Start(Action<WincheAuthOptions>? more = null, string? db = null)
    {
        var outbox = new Outbox();
        var app = await TestApp.StartAsync(db ?? await pg.NewDatabaseAsync(), services: s =>
        {
            s.AddSingleton<IAuthEmailSender>(outbox);
            s.AddSingleton<TimeProvider>(_clock);
        }, auth: o =>
        {
            o.Email(e => { e.SendInBackground = false; e.AppName = "Test"; });
            o.EmailLink(l => l.LinkUrl = "myapp://finish");
            o.Mfa(m => m.RecoveryCodes = 2);
            more?.Invoke(o);
        });
        return (app, outbox);
    }

    private string Totp(string secret) => Mfa.Totp.Code(Mfa.Totp.FromBase32(secret), Mfa.Totp.Step(_clock.GetUtcNow()));

    private async Task<string> EnrollAsync(TestApp app, Session s)
    {
        var start = await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/start", null, s.AccessToken));
        var secret = start.GetProperty("secret").GetString()!;
        await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/confirm", new { code = Totp(secret) }, s.AccessToken));
        _clock.Advance(TimeSpan.FromSeconds(30));
        return secret;
    }

    [Fact]
    public async Task Signing_up_with_someone_elses_email_first_gives_nothing_once_they_prove_it()
    {
        var (app, outbox) = await Start();
        await using var _ = app;
        var mallory = await app.SignUpAsync("victim@example.com");   // not verified: Mallory can't read that inbox

        await app.PostAsync("/auth/v1/sendSignInLink", new { email = "victim@example.com" });
        var victim = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/link", new { code = Outbox.Code(outbox.Last("victim@example.com")) }));
        Assert.Equal(mallory.Uid, victim.Uid);   // the address's account, now the owner's

        Assert.Equal((401, "INVALID_CREDENTIALS"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "victim@example.com", password = Password })));
        Assert.Equal((401, "INVALID_REFRESH_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/token", new { refreshToken = mallory.RefreshToken })));
    }

    [Fact]
    public async Task Signing_in_again_doesnt_reset_wrong_second_step_codes()
    {
        var (app, _) = await Start();
        await using var __ = app;
        await EnrollAsync(app, await app.SignUpAsync("ann@example.com"));

        (int, string) last = default;
        for (var round = 0; round < 6 && last.Item2 != "LOCKED_OUT"; round++)
        {
            var first = await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = Password });
            if ((int)first.StatusCode == 429) { last = (429, "LOCKED_OUT"); break; }
            var mfaToken = System.Text.Json.JsonDocument.Parse(await first.Content.ReadAsStringAsync()).RootElement
                .GetProperty("error").GetProperty("details").GetProperty("mfaToken").GetString();
            last = await TestApp.Error(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken, code = "000000" }));
        }
        Assert.Equal((429, "LOCKED_OUT"), last);   // 5 wrong codes, however many fresh sign-ins between them
    }

    [Fact]
    public async Task Sensitive_changes_need_a_recent_sign_in_except_a_guests_upgrade()
    {
        var (app, _) = await Start();
        await using var __ = app;
        var ann = await app.SignUpAsync("ann@example.com");
        var guest = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/anonymous"));
        _clock.Advance(TimeSpan.FromMinutes(10));   // the access tokens still work; the sign-ins aren't recent

        Assert.Equal((400, "REQUIRES_RECENT_SIGN_IN"), await TestApp.Error(await app.PostAsync("/auth/v1/me/email", new { newEmail = "x@example.com" }, ann.AccessToken)));
        Assert.Equal((400, "REQUIRES_RECENT_SIGN_IN"), await TestApp.Error(await app.SendAsync(HttpMethod.Delete, "/auth/v1/me", ann.AccessToken)));
        Assert.Equal((400, "REQUIRES_RECENT_SIGN_IN"), await TestApp.Error(await app.PostAsync("/auth/v1/me/mfa/totp/start", null, ann.AccessToken)));
        await TestApp.Json(await app.PostAsync("/auth/v1/link/password", new { email = "guest@example.com", password = Password }, guest.AccessToken));

        var fresh = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = Password }));
        Assert.Equal(HttpStatusCode.NoContent, (await app.SendAsync(HttpMethod.Delete, "/auth/v1/me", fresh.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task Undoing_an_email_change_takes_back_the_account_from_whoever_changed_it()
    {
        var (app, outbox) = await Start();
        await using var _ = app;
        var ann = await app.SignUpAsync("ann@example.com");
        // Someone with Ann's session moves the account to their address and sets a password.
        await app.PostAsync("/auth/v1/me/email", new { newEmail = "mallory@example.com" }, ann.AccessToken);
        await TestApp.Json(await app.PostAsync("/auth/v1/action/apply", new { code = Outbox.Code(outbox.Last("mallory@example.com")) }));
        Assert.Equal((401, "INVALID_REFRESH_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/token", new { refreshToken = ann.RefreshToken })));   // the change ended every session
        await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "mallory@example.com" });
        await TestApp.Json(await app.PostAsync("/auth/v1/resetPassword", new { code = Outbox.Code(outbox.Last("mallory@example.com")), newPassword = "mallory's own password" }));

        // Ann undoes it from her inbox: her address is back, and Mallory's password goes with the change.
        await TestApp.Json(await app.PostAsync("/auth/v1/action/apply", new { code = Outbox.Code(outbox.Last("ann@example.com")) }));
        Assert.Equal((401, "INVALID_CREDENTIALS"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "mallory's own password" })));
    }

    [Fact]
    public async Task A_guest_upgrade_waits_for_a_verified_email_when_the_app_asks_for_one()
    {
        var (app, outbox) = await Start(o => o.EmailPassword(e => e.RequireVerifiedEmail = true));
        await using var _ = app;
        var guest = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/anonymous"));
        Assert.Equal((403, "EMAIL_NOT_VERIFIED"),
            await TestApp.Error(await app.PostAsync("/auth/v1/link/password", new { email = "ann@example.com", password = Password }, guest.AccessToken)));
        Assert.Equal(1, outbox.Count("ann@example.com"));   // the verify link
    }

    [Fact]
    public async Task Turning_on_two_step_ends_every_other_session()
    {
        var (app, _) = await Start();
        await using var __ = app;
        var here = await app.SignUpAsync("ann@example.com");
        var elsewhere = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = Password }));
        await EnrollAsync(app, here);

        Assert.Equal((401, "INVALID_REFRESH_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/token", new { refreshToken = elsewhere.RefreshToken })));
        await TestApp.Json(await app.PostAsync("/auth/v1/token", new { refreshToken = here.RefreshToken }));   // this one goes on
    }

    [Fact]
    public async Task An_enrolled_second_step_is_still_asked_for_after_the_app_turns_two_step_off()
    {
        var db = await pg.NewDatabaseAsync();
        var (app, _) = await Start(db: db);
        await EnrollAsync(app, await app.SignUpAsync("ann@example.com"));
        await app.DisposeAsync();

        var (without, _) = await Start(o => o.MfaSettings = null, db);
        await using var __ = without;
        Assert.Equal((401, "MFA_REQUIRED"), await TestApp.Error(await without.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = Password })));
    }

    [Fact]
    public async Task Attempts_are_counted_across_servers_and_addresses_without_case()
    {
        var db = await pg.NewDatabaseAsync();
        var (one, outbox) = await Start(db: db);
        await using var _ = one;
        var (two, twoOutbox) = await Start(db: db);
        await using var ___ = two;
        // 20 sign-ins a minute per address: 15 on each server is too many together.
        var refused = 0;
        for (var i = 0; i < 15; i++)
            foreach (var app in new[] { one, two })
                if ((int)(await app.PostAsync("/auth/v1/signIn", new { email = "nobody@example.com", password = "x" })).StatusCode == 429) refused++;
        Assert.Equal(10, refused);

        foreach (var spelling in new[] { "Bob@example.com", "bOb@example.com", "boB@example.com", "BOB@example.com", "bob@EXAMPLE.com", "Bob@Example.com", "bob@example.COM" })
            await two.PostAsync("/auth/v1/sendSignInLink", new { email = spelling });
        Assert.Equal(5, twoOutbox.Sent.Count(m => m.To.Equals("bob@example.com", StringComparison.OrdinalIgnoreCase)));   // one inbox, one allowance
    }

    [Fact]
    public async Task An_access_token_in_the_address_is_only_taken_for_websockets()
    {
        var (app, _) = await Start();
        await using var __ = app;
        var ann = await app.SignUpAsync("ann@example.com");
        Assert.True((await app.WhoAmI(null)).TryGetProperty("signedOut", out _));
        var viaQuery = await TestApp.Json(await app.SendAsync(HttpMethod.Get, $"/whoami?access_token={ann.AccessToken}", null));
        Assert.True(viaQuery.TryGetProperty("signedOut", out _));
    }

    private static readonly RsaSecurityKey Keycloak = new(RSA.Create(2048)) { KeyId = "kc1" };

    [Fact]
    public async Task An_outside_token_cant_carry_claims_only_Winche_sets()
    {
        var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), trust: t => t.TrustIssuer("keycloak", i =>
        {
            i.Issuer = "https://idp.test/realms/x";
            i.SigningKeys = [Keycloak];
            i.Audience = "api";   // no mapping: everything else passes
        }));
        await using var keycloakApp = app;
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://idp.test/realms/x", Audience = "api", Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = new Dictionary<string, object> { ["sub"] = "kc-1", ["mfa"] = true, ["provider"] = "password", ["anonymous"] = false, ["role"] = "nurse" },
            SigningCredentials = new SigningCredentials(Keycloak, SecurityAlgorithms.RsaSha256),
        });
        var claims = await app.WhoAmI(token);
        Assert.Equal(("kc-1", "keycloak", "nurse"), (claims.GetProperty("uid").GetString(), claims.GetProperty("issuer").GetString(), claims.GetProperty("role").GetString()));
        Assert.False(claims.TryGetProperty("mfa", out _));
        Assert.False(claims.TryGetProperty("provider", out _));
        Assert.Throws<ArgumentException>(() => new WincheTokenOptions().TrustIssuer("other", i => { i.Issuer = "x"; i.SigningKeys = [Keycloak]; i.Audience = "a"; i.Map("role", "uid"); }));
    }
}
