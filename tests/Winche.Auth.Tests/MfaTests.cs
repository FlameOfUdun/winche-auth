using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.Mfa;

namespace Winche.Auth.Tests;

[Collection("postgres")]
public class MfaTests(PostgresFixture pg)
{
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.UtcNow);

    private async Task<TestApp> Start(Action<WincheAuthOptions>? more = null) =>
        await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddSingleton<TimeProvider>(_clock), auth: o =>
        {
            o.Mfa(m => m.RecoveryCodes = 4);
            o.Google(g => { g.Audiences = ["app"]; g.AllowUnsignedTokensForTesting = true; });
            more?.Invoke(o);
        });

    private string Code(string secret) => Totp.Code(Totp.FromBase32(secret), Totp.Step(_clock.GetUtcNow()));

    /// <summary>The next 30-second step: a new code (each code works once).</summary>
    private void NextStep() => _clock.Advance(TimeSpan.FromSeconds(30));

    private async Task<(Session Session, string Secret, string[] Recovery)> Enrolled(TestApp app, string email = "ann@example.com")
    {
        var s = await app.SignUpAsync(email);
        var start = await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/start", null, s.AccessToken));
        var secret = start.GetProperty("secret").GetString()!;
        var done = await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/confirm", new { code = Code(secret) }, s.AccessToken));
        return (s, secret, [.. done.GetProperty("recoveryCodes").EnumerateArray().Select(c => c.GetString()!)]);
    }

    private static async Task<string> MfaToken(HttpResponseMessage resp)
    {
        var text = await resp.Content.ReadAsStringAsync();
        Assert.Equal(401, (int)resp.StatusCode);
        var error = JsonDocument.Parse(text).RootElement.GetProperty("error");
        Assert.Equal(("unauthenticated", "MFA_REQUIRED"), (error.GetProperty("code").GetString(), error.GetProperty("reason").GetString()));
        var details = error.GetProperty("details");
        Assert.Equal(["totp", "recovery"], details.GetProperty("factors").EnumerateArray().Select(f => f.GetString()));
        return details.GetProperty("mfaToken").GetString()!;
    }

    private Task<HttpResponseMessage> SignIn(TestApp app) =>
        app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" });

    [Fact]
    public async Task Adding_an_authenticator_app()
    {
        await using var app = await Start();
        var s = await app.SignUpAsync("ann@example.com");
        var start = await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/start", null, s.AccessToken));
        var secret = start.GetProperty("secret").GetString()!;
        Assert.Equal(32, secret.Length);
        Assert.Equal($"otpauth://totp/api.test:ann%40example.com?secret={secret}&issuer=api.test&algorithm=SHA1&digits=6&period=30",
            start.GetProperty("otpauthUri").GetString());

        Assert.Equal((401, "INVALID_MFA_CODE"), await TestApp.Error(await app.PostAsync("/auth/v1/me/mfa/totp/confirm", new { code = "000000" }, s.AccessToken)));
        var done = await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/confirm", new { code = Code(secret) }, s.AccessToken));
        Assert.Equal(4, done.GetProperty("recoveryCodes").GetArrayLength());
        var status = await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/auth/v1/me/mfa", s.AccessToken));
        Assert.Equal((true, 4), (status.GetProperty("enabled").GetBoolean(), status.GetProperty("recoveryCodesLeft").GetInt32()));
        Assert.True((await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/auth/v1/me", s.AccessToken))).GetProperty("mfaEnabled").GetBoolean());
        Assert.Equal((400, "MFA_ALREADY_ENABLED"), await TestApp.Error(await app.PostAsync("/auth/v1/me/mfa/totp/start", null, s.AccessToken)));
    }

    [Fact]
    public async Task Sign_in_then_asks_for_a_code_that_works_once()
    {
        await using var app = await Start();
        var (_, secret, recovery) = await Enrolled(app);

        var mfaToken = await MfaToken(await SignIn(app));
        Assert.Equal((401, "INVALID_MFA_CODE"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken, code = "123456" })));
        NextStep();
        var code = Code(secret);
        var s = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken, code }));
        Assert.True((await app.WhoAmI(s.AccessToken)).GetProperty("mfa").GetBoolean());
        var refreshed = await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = s.RefreshToken }));
        Assert.True((await app.WhoAmI(refreshed.AccessToken)).GetProperty("mfa").GetBoolean());   // the session keeps it
        Assert.Equal(400, (int)(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken, code })).StatusCode);   // the pending sign-in is done

        // The same code can't be replayed on another sign-in.
        var again = await MfaToken(await SignIn(app));
        Assert.Equal((401, "INVALID_MFA_CODE"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken = again, code })));
        // A recovery code works, once (spaces, dashes and case don't matter).
        await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken = again, code = recovery[0].ToUpperInvariant().Replace("-", " ") }));
        var third = await MfaToken(await SignIn(app));
        Assert.Equal((401, "INVALID_MFA_CODE"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken = third, code = recovery[0] })));
        Assert.Equal(3, (await app.Scoped(async a => await a.GetMfaStatusAsync(s.Uid))).RecoveryCodesLeft);

        // A password sign-in without the second step has no "mfa" claim.
        var plain = await app.Scoped(a => a.SignInAsUserAsync(s.Uid, AuthRequestInfo.Server));
        Assert.False((await app.WhoAmI(plain.AccessToken)).TryGetProperty("mfa", out _));
    }

    [Fact]
    public async Task Wrong_codes_lock_the_account()
    {
        await using var app = await Start(o => o.MaxFailedSignIns = 3);
        var (_, secret, _) = await Enrolled(app);
        var mfaToken = await MfaToken(await SignIn(app));
        for (var i = 0; i < 2; i++)
            Assert.Equal("INVALID_MFA_CODE", (await TestApp.Error(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken, code = "111111" }))).Item2);
        Assert.Equal((429, "LOCKED_OUT"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken, code = "111111" })));
        NextStep();
        Assert.Equal(400, (int)(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken, code = Code(secret) })).StatusCode);   // start over
    }

    [Fact]
    public async Task Turning_it_off_and_new_recovery_codes()
    {
        await using var app = await Start();
        var (s, secret, recovery) = await Enrolled(app);
        NextStep();
        var fresh = await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/recoveryCodes", new { code = Code(secret) }, s.AccessToken));
        Assert.Equal(4, fresh.GetProperty("recoveryCodes").GetArrayLength());
        var mfaToken = await MfaToken(await SignIn(app));
        Assert.Equal((401, "INVALID_MFA_CODE"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken, code = recovery[1] })));   // old codes are gone

        Assert.Equal((401, "INVALID_MFA_CODE"), await TestApp.Error(await app.PostAsync("/auth/v1/me/mfa/disable", new { code = "000000" }, s.AccessToken)));
        await app.PostAsync("/auth/v1/me/mfa/disable", new { code = fresh.GetProperty("recoveryCodes")[0].GetString() }, s.AccessToken);
        await app.SessionAsync(await SignIn(app));   // no second step now

        // An admin can turn it off for someone who lost their phone.
        var bob = await Enrolled(app, "bob@example.com");
        await app.Scoped(a => a.ResetMfaAsync(bob.Session.Uid));
        await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "bob@example.com", password = "correct horse battery" }));
    }

    [Fact]
    public async Task Provider_sign_in_asks_too()
    {
        await using var app = await Start();
        var b64 = (object o) => Base64UrlEncoder.Encode(JsonSerializer.Serialize(o));
        var idToken = $"{b64(new { alg = "none" })}.{b64(new { iss = "https://accounts.google.com", aud = "app", sub = "g-1", email = "ann@example.com", email_verified = true, exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() })}.";
        var (s, secret, _) = await Enrolled(app);
        NextStep();
        await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", new { provider = "google", idToken }, s.AccessToken));
        var mfaToken = await MfaToken(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken }));
        var done = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/mfa", new { mfaToken, code = Code(secret) }));
        Assert.Equal("google", (await app.WhoAmI(done.AccessToken)).GetProperty("provider").GetString());
    }

    private static string IdToken(string iss, string aud, string sub, object? amr = null, string? acr = null)
    {
        var b64 = (object o) => Base64UrlEncoder.Encode(JsonSerializer.Serialize(o));
        var payload = new Dictionary<string, object> { ["iss"] = iss, ["aud"] = aud, ["sub"] = sub, ["email"] = $"{sub}@example.com", ["email_verified"] = true,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() };
        if (amr is not null) payload["amr"] = amr;
        if (acr is not null) payload["acr"] = acr;
        return $"{b64(new { alg = "none" })}.{b64(payload)}.";
    }

    [Fact]
    public async Task A_provider_that_checked_a_second_step_counts_so_the_user_isnt_asked_twice()
    {
        await using var app = await Start();
        var (s, _, _) = await Enrolled(app);
        NextStep();
        await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", new { provider = "google", idToken = IdToken("https://accounts.google.com", "app", "g-1") }, s.AccessToken));

        // Google says it asked for a one-time code: no Winche code, and the session counts as two-step.
        var done = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp",
            new { provider = "google", idToken = IdToken("https://accounts.google.com", "app", "g-1", amr: new[] { "pwd", "otp" }) }));
        Assert.True((await app.WhoAmI(done.AccessToken)).GetProperty("mfa").GetBoolean());
        // Without it, Winche's code is still asked for: a linked provider is no way around the user's two-step.
        await MfaToken(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken = IdToken("https://accounts.google.com", "app", "g-1", amr: "pwd") }));
    }

    [Fact]
    public async Task A_provider_trusted_as_a_second_step_signs_in_users_with_two_step_on_without_winches_code()
    {
        await using var app = await Start(o => o.OpenIdConnect("staff", k =>
        {
            k.Authority = "https://id.example.com/realms/staff"; k.Audiences = ["app"]; k.AllowUnsignedTokensForTesting = true;
            k.CountsAsSecondStep = true;   // the company's sign-in asks everyone for its own second step
        }));
        var (s, _, _) = await Enrolled(app);
        NextStep();
        await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", new { provider = "staff", idToken = IdToken("https://id.example.com/realms/staff", "app", "kc-1") }, s.AccessToken));
        var done = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "staff", idToken = IdToken("https://id.example.com/realms/staff", "app", "kc-1") }));
        Assert.True((await app.WhoAmI(done.AccessToken)).GetProperty("mfa").GetBoolean());
    }

    [Fact]
    public async Task A_provider_that_requires_a_second_step_refuses_sign_ins_without_one()
    {
        await using var app = await Start(o => o.OpenIdConnect("keycloak", k =>
        {
            k.Authority = "https://id.example.com/realms/staff"; k.Audiences = ["app"]; k.AllowUnsignedTokensForTesting = true;
            k.RequireSecondStep = true; k.SecondStepAcrValues = ["2"];
        }));
        const string iss = "https://id.example.com/realms/staff";
        Assert.Equal((401, "SECOND_STEP_REQUIRED"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "keycloak", idToken = IdToken(iss, "app", "kc-1", acr: "1") })));
        var s = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "keycloak", idToken = IdToken(iss, "app", "kc-1", acr: "2") }));
        Assert.True((await app.WhoAmI(s.AccessToken)).GetProperty("mfa").GetBoolean());
        // Optional providers: a sign-in without a second step is fine, and has no "mfa" claim.
        await using var open = await Start();
        var plain = await open.SessionAsync(await open.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken = IdToken("https://accounts.google.com", "app", "g-2") }));
        Assert.False((await open.WhoAmI(plain.AccessToken)).TryGetProperty("mfa", out _));
    }

    [Fact]
    public async Task Off_unless_turned_on()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var s = await app.SignUpAsync("ann@example.com");
        Assert.Equal((400, "SIGN_IN_METHOD_NOT_ENABLED"), await TestApp.Error(await app.PostAsync("/auth/v1/me/mfa/totp/start", null, s.AccessToken)));
    }

    [Fact]
    public void Totp_matches_the_RFC_6238_test_vectors()
    {
        // RFC 6238 appendix B, SHA-1 key "12345678901234567890": 8-digit codes; our 6 digits are their last six.
        var key = "12345678901234567890"u8.ToArray();
        Assert.Equal("287082", Totp.Code(key, 59 / 30));
        Assert.Equal("081804", Totp.Code(key, 1111111109 / 30));
        Assert.Equal("005924", Totp.Code(key, 1234567890 / 30));
        Assert.Equal(key, Totp.FromBase32(Totp.Base32(key)));
    }

    [Fact]
    public async Task Starting_again_before_confirming_keeps_the_same_key()
    {
        await using var app = await Start();
        var s = await app.SignUpAsync("ann@example.com");
        var first = (await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/start", null, s.AccessToken))).GetProperty("secret").GetString();
        var again = (await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/start", null, s.AccessToken))).GetProperty("secret").GetString();
        Assert.Equal(first, again);   // a reload of the set-up page: the app already scanned still works
        await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/confirm", new { code = Code(first!) }, s.AccessToken));
    }
}
