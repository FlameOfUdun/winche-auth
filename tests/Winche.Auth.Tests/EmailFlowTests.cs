using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Winche.Auth.Email;
using Winche.Auth.Mfa;

namespace Winche.Auth.Tests;

public sealed class Outbox : IAuthEmailSender
{
    public List<AuthEmailMessage> Sent { get; } = [];
    public bool Down;   // the mail server refusing everything
    public Task SendAsync(AuthEmailMessage message, CancellationToken ct)
    {
        if (Down) throw new InvalidOperationException("The mail server is down.");
        lock (Sent) Sent.Add(message);
        return Task.CompletedTask;
    }
    public AuthEmailMessage Last(string to) { lock (Sent) return Sent.Last(m => m.To == to); }
    public int Count(string to) { lock (Sent) return Sent.Count(m => m.To == to); }
    public static string Code(AuthEmailMessage m) => Regex.Match(m.Link!, "code=([A-Za-z0-9_-]+)").Groups[1].Value;
}

[Collection("postgres")]
public class EmailFlowTests(PostgresFixture pg)
{
    private async Task<(TestApp App, Outbox Outbox)> Start(Action<WincheAuthOptions>? more = null)
    {
        var outbox = new Outbox();
        var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddSingleton<IAuthEmailSender>(outbox), auth: o =>
        {
            o.Email(e => { e.SendInBackground = false; e.AppName = "Test & App"; });
            o.EmailLink(l => l.LinkUrl = "myapp://finish");
            more?.Invoke(o);
        });
        return (app, outbox);
    }

    private static Task<HttpResponseMessage> Apply(TestApp app, string code) => app.PostAsync("/auth/v1/action/apply", new { code });

    [Fact]
    public async Task Sign_up_sends_a_verify_link_that_verifies_once()
    {
        var (app, outbox) = await Start();
        await using var _ = app;
        var s = await app.SignUpAsync("ann@example.com");
        var mail = outbox.Last("ann@example.com");
        Assert.Equal("verifyEmail", mail.Kind);
        Assert.Equal("Verify your email for Test & App", mail.Subject);
        Assert.StartsWith("https://api.test/auth/v1/action#mode=verifyEmail&code=", mail.Link);   // after '#': never in a server log
        Assert.Contains(mail.Link!, mail.Text);
        Assert.Contains("Hello,", mail.Text);   // no display name, no stray space
        Assert.Contains("Test &amp; App", mail.Html);
        Assert.Contains(">Verify email</a>", mail.Html);

        var check = await TestApp.Json(await app.PostAsync("/auth/v1/action/check", new { code = Outbox.Code(mail) }));
        Assert.Equal(("verifyEmail", "ann@example.com"), (check.GetProperty("mode").GetString(), check.GetProperty("email").GetString()));
        await TestApp.Json(await Apply(app, Outbox.Code(mail)));
        Assert.Equal((400, "INVALID_CODE"), await TestApp.Error(await Apply(app, Outbox.Code(mail))));
        var next = await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = s.RefreshToken }));
        Assert.True((await app.WhoAmI(next.AccessToken)).GetProperty("email_verified").GetBoolean());

        // Already verified: asking again sends nothing.
        var before = outbox.Count("ann@example.com");
        Assert.Equal(HttpStatusCode.NoContent, (await app.PostAsync("/auth/v1/sendVerification", null, next.AccessToken)).StatusCode);
        Assert.Equal(before, outbox.Count("ann@example.com"));
    }

    [Fact]
    public async Task Password_reset_by_email()
    {
        var (app, outbox) = await Start();
        await using var _ = app;
        var s = await app.SignUpAsync("ann@example.com");
        // Whoever signed up with the address (never proved) set a name and photo.
        await app.Scoped(a => a.UpdateProfileAsync(s.Uid, "Not Ann", null));
        await app.Scoped(a => a.SetPhotoAsync(s.Uid, PhotoTests.Png));
        Assert.Equal(HttpStatusCode.NoContent, (await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "nobody@example.com" })).StatusCode);
        Assert.Equal(0, outbox.Count("nobody@example.com"));   // same answer, nothing sent

        Assert.Equal(HttpStatusCode.NoContent, (await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ANN@example.com" })).StatusCode);
        var code = Outbox.Code(outbox.Last("ann@example.com"));
        Assert.Equal((400, "WEAK_PASSWORD"), await TestApp.Error(await app.PostAsync("/auth/v1/resetPassword", new { code, newPassword = "short" })));
        await TestApp.Json(await app.PostAsync("/auth/v1/resetPassword", new { code, newPassword = "a brand new password" }));
        Assert.Equal((400, "INVALID_CODE"), await TestApp.Error(await app.PostAsync("/auth/v1/resetPassword", new { code, newPassword = "another new password" })));

        Assert.Equal(401, (int)(await app.PostAsync("/auth/v1/token", new { refreshToken = s.RefreshToken })).StatusCode);   // sessions ended
        // The address's owner proved it: the name and photo the other person set are gone too.
        var owned = (await app.Scoped(a => a.GetUserAsync(s.Uid)))!;
        Assert.Equal((null, null, null), (owned.DisplayName, owned.PhotoUrl, owned.PhotoSource));
        // The other person's access token (its session ended) can't put them back.
        Assert.Equal(401, (await TestApp.Error(await app.SendAsync(HttpMethod.Patch, "/auth/v1/me", s.AccessToken, new { displayName = "Not Ann" }))).Item1);
        // …nor turn on two-step sign-in with their own authenticator, nor delete the account.
        Assert.Equal(401, (await TestApp.Error(await app.PostAsync("/auth/v1/me/mfa/totp/confirm", new { code = "123456" }, s.AccessToken))).Item1);
        Assert.Equal(401, (await TestApp.Error(await app.SendAsync(HttpMethod.Delete, "/auth/v1/me", s.AccessToken))).Item1);
        Assert.NotNull(await app.Scoped(a => a.GetUserAsync(s.Uid)));
        await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "a brand new password" }));
    }

    [Fact]
    public async Task A_new_link_replaces_the_old_and_an_address_gets_a_few_an_hour()
    {
        var (app, outbox) = await Start(o => o.EmailSending!.MaxPerAddressPerHour = 3);
        await using var _ = app;
        await app.SignUpAsync("ann@example.com");   // 1: verify
        await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ann@example.com" });   // 2
        var first = Outbox.Code(outbox.Last("ann@example.com"));
        await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ann@example.com" });   // 3
        var second = Outbox.Code(outbox.Last("ann@example.com"));
        await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ann@example.com" });   // 4: dropped
        Assert.Equal(3, outbox.Count("ann@example.com"));
        Assert.Equal((400, "INVALID_CODE"), await TestApp.Error(await app.PostAsync("/auth/v1/resetPassword", new { code = first, newPassword = "a brand new password" })));
        await TestApp.Json(await app.PostAsync("/auth/v1/resetPassword", new { code = second, newPassword = "a brand new password" }));
    }

    [Fact]
    public async Task Email_link_sign_in_makes_the_account_on_first_use()
    {
        var (app, outbox) = await Start();
        await using var _ = app;
        Assert.Equal(HttpStatusCode.NoContent, (await app.PostAsync("/auth/v1/sendSignInLink", new { email = "new@example.com" })).StatusCode);
        var mail = outbox.Last("new@example.com");
        Assert.StartsWith("myapp://finish?mode=signIn&code=", mail.Link);
        var s = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/link", new { code = Outbox.Code(mail) }));
        var claims = await app.WhoAmI(s.AccessToken);
        Assert.Equal("emailLink", claims.GetProperty("provider").GetString());
        Assert.True(claims.GetProperty("email_verified").GetBoolean());
        Assert.Equal((400, "INVALID_CODE"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/link", new { code = Outbox.Code(mail) })));

        // The same address again: the same user.
        await app.PostAsync("/auth/v1/sendSignInLink", new { email = "new@example.com" });
        Assert.Equal(s.Uid, (await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/link", new { code = Outbox.Code(outbox.Last("new@example.com")) }))).Uid);
        // A reset code isn't a sign-in code.
        await app.PostAsync("/auth/v1/signUp", new { email = "bob@example.com", password = "correct horse battery" });
        await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "bob@example.com" });
        Assert.Equal((400, "INVALID_CODE"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/link", new { code = Outbox.Code(outbox.Last("bob@example.com")) })));
    }

    [Fact]
    public async Task Changing_the_email_needs_the_new_address_and_the_old_one_can_undo_it()
    {
        var (app, outbox) = await Start(o => o.Mfa());
        await using var _ = app;
        var s = await app.SignUpAsync("ann@example.com");
        // Two-step sign-in on (whoever has the account could have set it): the undo takes it away with the rest.
        var totp = await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/start", null, s.AccessToken));
        var secret = totp.GetProperty("secret").GetString()!;
        await TestApp.Json(await app.PostAsync("/auth/v1/me/mfa/totp/confirm", new { code = Totp.Code(Totp.FromBase32(secret), Totp.Step(DateTimeOffset.UtcNow)) }, s.AccessToken));
        Assert.True((await app.Scoped(a => a.GetMfaStatusAsync(s.Uid))).Enabled);
        Assert.Equal(HttpStatusCode.Accepted, (await app.PostAsync("/auth/v1/me/email", new { newEmail = "ann.new@example.com" }, s.AccessToken)).StatusCode);
        var confirm = outbox.Last("ann.new@example.com");
        Assert.Equal("verifyEmail", confirm.Kind);
        Assert.Contains("mode=verifyAndChangeEmail", confirm.Link);
        Assert.Equal("ann@example.com", (await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/auth/v1/me", s.AccessToken))).GetProperty("email").GetString());

        await TestApp.Json(await Apply(app, Outbox.Code(confirm)));
        Assert.Equal("ann.new@example.com", (await app.Scoped(a => a.GetUserAsync(s.Uid)))!.Email);
        // The account was never verified: proving an address claims it, and its sessions end (tokens included).
        Assert.Equal(401, (int)(await app.SendAsync(HttpMethod.Get, "/auth/v1/me", s.AccessToken)).StatusCode);
        var notice = outbox.Last("ann@example.com");
        Assert.Equal("emailChanged", notice.Kind);
        Assert.Contains("from ann@example.com to ann.new@example.com", notice.Text);
        Assert.Contains("mode=recoverEmail", notice.Link);

        await TestApp.Json(await Apply(app, Outbox.Code(notice)));
        var me = await app.Scoped(a => a.GetUserAsync(s.Uid));
        Assert.Equal("ann@example.com", me!.Email);
        Assert.Equal(401, (int)(await app.PostAsync("/auth/v1/token", new { refreshToken = s.RefreshToken })).StatusCode);   // signed out everywhere
        var mfa = await app.Scoped(a => a.GetMfaStatusAsync(s.Uid));
        Assert.Equal((false, 0), (mfa.Enabled, mfa.RecoveryCodesLeft));   // two-step off, its recovery codes gone
    }

    [Fact]
    public async Task A_verified_email_can_be_required()
    {
        var (app, outbox) = await Start(o => o.EmailPasswordSignIn!.RequireVerifiedEmail = true);
        await using var _ = app;
        Assert.Equal((403, "EMAIL_NOT_VERIFIED"), await TestApp.Error(await app.PostAsync("/auth/v1/signUp", new { email = "ann@example.com", password = "correct horse battery" })));
        Assert.Equal((403, "EMAIL_NOT_VERIFIED"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" })));
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("ann@example.com"))));
        await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
    }

    [Fact]
    public async Task The_built_in_page_shows_a_button_and_only_the_button_uses_the_link()
    {
        var (app, outbox) = await Start();
        await using var _ = app;
        await app.SignUpAsync("ann@example.com");
        var link = new Uri(outbox.Last("ann@example.com").Link!);

        // The link opens a page that reads the code from after '#' and posts it (a browser would run its script).
        var opener = await app.Client.GetAsync(link.PathAndQuery);
        Assert.Equal("/auth/v1/action", link.PathAndQuery);
        var openerHtml = await opener.Content.ReadAsStringAsync();
        Assert.Contains("location.hash", openerHtml);
        Assert.Contains("script-src 'nonce-", opener.Headers.GetValues("Content-Security-Policy").Single());
        var code = Outbox.Code(outbox.Last("ann@example.com"));
        var page = await app.Client.PostAsync("/auth/v1/action", new FormUrlEncodedContent(new Dictionary<string, string> { ["open"] = "1", ["code"] = code }));
        var html = await page.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("Verify my email", html);
        Assert.Contains("Test &amp; App", html);
        Assert.Equal("no-referrer", page.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("default-src 'none'", page.Headers.GetValues("Content-Security-Policy").Single());
        // Opening the link again (a mail scanner) doesn't use it up.
        await app.Client.PostAsync("/auth/v1/action", new FormUrlEncodedContent(new Dictionary<string, string> { ["open"] = "1", ["code"] = code }));
        var done = await app.Client.PostAsync("/auth/v1/action", new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = code }));
        Assert.Contains("Your email is verified", await done.Content.ReadAsStringAsync());
        Assert.Contains("This link doesn", await (await app.Client.PostAsync("/auth/v1/action",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["open"] = "1", ["code"] = code }))).Content.ReadAsStringAsync());

        await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ann@example.com" });
        var reset = Outbox.Code(outbox.Last("ann@example.com"));
        var form = await (await app.Client.GetAsync($"/auth/v1/action?mode=resetPassword&code={reset}")).Content.ReadAsStringAsync();
        Assert.Contains("type=\"password\"", form);
        var weak = await app.Client.PostAsync("/auth/v1/action", new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = reset, ["password"] = "short" }));
        Assert.Contains("at least 10 characters", await weak.Content.ReadAsStringAsync());
        var ok = await app.Client.PostAsync("/auth/v1/action", new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = reset, ["password"] = "a brand new password" }));
        Assert.Contains("Your password is changed", await ok.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Templates_can_be_changed_and_reset()
    {
        var (app, outbox) = await Start();
        await using var _ = app;
        var bad = await Assert.ThrowsAsync<AuthException>(() => app.Scoped(async a => { await a.SaveEmailTemplateAsync("resetPassword", "Reset", "No link here", "admin@x"); return 0; }));
        Assert.Contains("%LINK%", bad.Message);
        await app.Scoped(async a => { await a.SaveEmailTemplateAsync("resetPassword", "Your %APP_NAME% reset", "Hi %EMAIL%,\n\n%LINK%", "admin@x"); return 0; });
        var templates = await app.Scoped(a => a.GetEmailTemplatesAsync());
        var reset = templates.Single(t => t.Kind == "resetPassword");
        Assert.True(reset.IsCustom);
        Assert.Equal("admin@x", reset.UpdatedBy);
        Assert.Equal("1 hour", reset.LinkLifetime);

        await app.SignUpAsync("ann@example.com");
        await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ann@example.com" });
        Assert.Equal("Your Test & App reset", outbox.Last("ann@example.com").Subject);
        Assert.StartsWith("Hi ann@example.com,", outbox.Last("ann@example.com").Text);

        await app.Scoped(async a => { await a.SendTestEmailAsync("resetPassword", "admin@example.com"); return 0; });
        Assert.Equal("[Test] Your Test & App reset", outbox.Last("admin@example.com").Subject);

        await app.Scoped(async a => { await a.ResetEmailTemplateAsync("resetPassword"); return 0; });
        Assert.False((await app.Scoped(a => a.GetEmailTemplatesAsync())).Single(t => t.Kind == "resetPassword").IsCustom);
    }

    [Fact]
    public async Task Without_email_set_up_the_flows_say_so()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        Assert.Equal((400, "EMAIL_NOT_SET_UP"), await TestApp.Error(await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ann@example.com" })));
        await app.SignUpAsync("ann@example.com");   // no verify email, no error
    }

    [Fact]
    public async Task Claiming_an_account_cancels_codes_whoever_made_it_asked_for()
    {
        var (app, outbox) = await Start();
        await using var _ = app;
        // Someone signs up with Ann's address and asks to move the account to theirs: the code comes to them.
        var s = await app.SignUpAsync("ann@example.com");
        Assert.Equal(HttpStatusCode.Accepted, (await app.PostAsync("/auth/v1/me/email", new { newEmail = "evil@example.com" }, s.AccessToken)).StatusCode);
        var theirs = Outbox.Code(outbox.Last("evil@example.com"));
        // Ann claims it by resetting the password from her inbox…
        await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ann@example.com" });
        await TestApp.Json(await app.PostAsync("/auth/v1/resetPassword", new { code = Outbox.Code(outbox.Last("ann@example.com")), newPassword = "a brand new password" }));
        // …and their code no longer takes it away.
        Assert.Equal((400, "INVALID_CODE"), await TestApp.Error(await Apply(app, theirs)));
        Assert.Equal("ann@example.com", (await app.Scoped(a => a.GetUserAsync(s.Uid)))!.Email);
    }

    [Fact]
    public async Task Undoing_an_email_change_removes_providers_linked_since()
    {
        var (app, outbox) = await Start(o => o.Google(g => { g.Audiences = ["app"]; g.AllowUnsignedTokensForTesting = true; }));
        await using var _ = app;
        var s = await app.SignUpAsync("ann@example.com");
        await app.PostAsync("/auth/v1/me/email", new { newEmail = "evil@example.com" }, s.AccessToken);
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("evil@example.com"))));
        var undo = Outbox.Code(outbox.Last("ann@example.com"));
        // Whoever now has the account signs in and links their own Google account.
        await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "evil@example.com" });
        await TestApp.Json(await app.PostAsync("/auth/v1/resetPassword", new { code = Outbox.Code(outbox.Last("evil@example.com")), newPassword = "a brand new password" }));
        var evil = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "evil@example.com", password = "a brand new password" }));
        var google = GoogleToken("g-1");
        await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", new { provider = "google", idToken = google }, evil.AccessToken));
        // Ann undoes the change: their Google account no longer signs in to hers.
        await TestApp.Json(await Apply(app, undo));
        Assert.Equal("ann@example.com", (await app.Scoped(a => a.GetUserAsync(s.Uid)))!.Email);
        Assert.NotEqual(s.Uid, (await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken = google }))).Uid);
    }

    [Fact]
    public async Task Undoing_an_email_change_keeps_the_providers_the_owner_had()
    {
        var (app, outbox) = await Start(o => o.Google(g => { g.Audiences = ["app"]; g.AllowUnsignedTokensForTesting = true; }));
        await using var _ = app;
        // Ann signs in with Google only (her address verified by it).
        var ann = GoogleToken("ann");
        var s = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken = ann }));
        await app.PostAsync("/auth/v1/me/email", new { newEmail = "evil@example.com" }, s.AccessToken);
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("evil@example.com"))));
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("ann@example.com"))));
        // Her Google account still signs her in.
        Assert.Equal(s.Uid, (await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken = ann }))).Uid);
    }

    [Fact]
    public async Task Linking_a_provider_emails_the_owner_a_link_that_removes_it_and_signs_everyone_out()
    {
        var (app, outbox) = await Start(o => o.Google(g => { g.Audiences = ["app"]; g.AllowUnsignedTokensForTesting = true; }));
        await using var _ = app;
        var s = await app.SignUpAsync("ann@example.com");
        await app.PostAsync("/auth/v1/sendVerification", null, s.AccessToken);
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("ann@example.com"))));
        var session = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
        // Someone with her session links their own Google: Ann is told, with a link that removes it.
        var theirs = GoogleToken("intruder");
        await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", new { provider = "google", idToken = theirs }, session.AccessToken));
        var notice = outbox.Last("ann@example.com");
        Assert.Equal("providerLinked", notice.Kind);
        Assert.Contains("Google", notice.Text);
        // Even with her inbox flooded since, the link works.
        for (var n = 0; n < 6; n++) await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ann@example.com" });
        Assert.Equal("unlinkProvider", (await TestApp.Json(await app.PostAsync("/auth/v1/action/check", new { code = Outbox.Code(notice) }))).GetProperty("mode").GetString());
        await TestApp.Json(await Apply(app, Outbox.Code(notice)));
        Assert.NotEqual(s.Uid, (await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken = theirs }))).Uid);
        Assert.Equal(401, (int)(await app.SendAsync(HttpMethod.Get, "/auth/v1/me", session.AccessToken)).StatusCode);
        Assert.Equal((400, "INVALID_CODE"), await TestApp.Error(await Apply(app, Outbox.Code(notice))));
    }

    [Fact]
    public async Task Removing_the_last_way_to_sign_in_from_the_email_still_removes_it_and_says_what_next()
    {
        var (app, outbox) = await Start(o =>
        {
            o.Google(g => { g.Audiences = ["app"]; g.AllowUnsignedTokensForTesting = true; });
            o.Apple(a => { a.Audiences = ["com.example.app"]; a.AllowUnsignedTokensForTesting = true; });
            o.EmailLinkSignIn = null;   // here, a password reset is the way back
        });
        await using var _ = app;
        // Ann signs in with Google (no password). Someone with her session links their Apple account and removes her Google.
        var ann = GoogleToken("ann");
        var s = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken = ann }));
        var b64 = (object o) => Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(System.Text.Json.JsonSerializer.Serialize(o));
        var apple = $"{b64(new { alg = "none" })}.{b64(new Dictionary<string, object> { ["iss"] = "https://appleid.apple.com", ["aud"] = "com.example.app", ["sub"] = "intruder-apple", ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() })}.";
        await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", new { provider = "apple", idToken = apple }, s.AccessToken));
        await TestApp.Json(await app.PostAsync("/auth/v1/unlink", new { provider = "google" }, s.AccessToken));
        var notice = outbox.Last("ann@example.com");
        Assert.Equal("providerLinked", notice.Kind);

        // The link still takes the intruder's Apple away, though it's now the only way in, and says how Ann gets back.
        var applied = await TestApp.Json(await Apply(app, Outbox.Code(notice)));
        Assert.Equal("resetPassword", applied.GetProperty("next").GetString());
        Assert.Empty((await app.Scoped(a => a.GetUserAsync(s.Uid)))!.Providers.Where(p => p != "password"));
        Assert.Equal("resetPassword", outbox.Last("ann@example.com").Kind);   // the reset link is in her inbox
    }

    [Fact]
    public async Task When_the_reset_can_not_be_sent_the_removal_still_stands_and_says_so()
    {
        var (app, outbox) = await Start(o =>
        {
            o.Google(g => { g.Audiences = ["app"]; g.AllowUnsignedTokensForTesting = true; });
            o.Apple(a => { a.Audiences = ["com.example.app"]; a.AllowUnsignedTokensForTesting = true; });
            o.EmailLinkSignIn = null;
        });
        await using var _ = app;
        var s = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken = GoogleToken("ann") }));
        var b64 = (object o) => Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(System.Text.Json.JsonSerializer.Serialize(o));
        var apple = $"{b64(new { alg = "none" })}.{b64(new Dictionary<string, object> { ["iss"] = "https://appleid.apple.com", ["aud"] = "com.example.app", ["sub"] = "intruder-apple", ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() })}.";
        await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", new { provider = "apple", idToken = apple }, s.AccessToken));
        await TestApp.Json(await app.PostAsync("/auth/v1/unlink", new { provider = "google" }, s.AccessToken));
        var notice = outbox.Last("ann@example.com");

        outbox.Down = true;   // the mail server refuses the reset
        var applied = await TestApp.Json(await Apply(app, Outbox.Code(notice)));
        Assert.Equal("resetNotSent", applied.GetProperty("next").GetString());
        Assert.Empty((await app.Scoped(a => a.GetUserAsync(s.Uid)))!.Providers.Where(p => p != "password"));   // removed all the same
    }

    [Fact]
    public async Task Linking_and_unlinking_over_and_over_never_uses_up_the_owners_emails()
    {
        var (app, outbox) = await Start(o => o.Google(g => { g.Audiences = ["app"]; g.AllowUnsignedTokensForTesting = true; }));
        await using var _ = app;
        var s = await app.SignUpAsync("ann@example.com");
        for (var n = 0; n < 6; n++)
        {
            await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", new { provider = "google", idToken = GoogleToken($"g-{n}") }, s.AccessToken));
            await TestApp.Json(await app.PostAsync("/auth/v1/unlink", new { provider = "google" }, s.AccessToken));
        }
        await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ann@example.com" });
        Assert.Equal("resetPassword", outbox.Last("ann@example.com").Kind);
    }

    [Fact]
    public async Task A_notice_that_cant_be_sent_never_leaves_a_link_half_made()
    {
        var (app, outbox) = await Start(o => o.Google(g => { g.Audiences = ["app"]; g.AllowUnsignedTokensForTesting = true; }));
        await using var _ = app;
        var s = await app.SignUpAsync("ann@example.com");
        outbox.Down = true;
        var r = await app.PostAsync("/auth/v1/link/idp", new { provider = "google", idToken = GoogleToken("g-1") }, s.AccessToken);
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());   // linked; the notice's failure is logged
        Assert.Equal(s.Uid, (await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken = GoogleToken("g-1") }))).Uid);
    }

    [Fact]
    public async Task Undoing_an_email_change_cancels_every_other_code_whoever_changed_it_kept()
    {
        var (app, outbox) = await Start();
        await using var _ = app;
        var s = await app.SignUpAsync("ann@example.com");
        await app.PostAsync("/auth/v1/sendVerification", null, s.AccessToken);
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("ann@example.com"))));
        var session = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
        // Someone with her session asks for two changes, and makes one.
        await app.PostAsync("/auth/v1/me/email", new { newEmail = "evil1@example.com" }, session.AccessToken);
        await app.PostAsync("/auth/v1/me/email", new { newEmail = "evil2@example.com" }, session.AccessToken);
        var spare = Outbox.Code(outbox.Last("evil2@example.com"));
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("evil1@example.com"))));
        // Ann undoes it: the spare code no longer takes the address again.
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("ann@example.com"))));
        Assert.Equal((400, "INVALID_CODE"), await TestApp.Error(await Apply(app, spare)));
        Assert.Equal("ann@example.com", (await app.Scoped(a => a.GetUserAsync(s.Uid)))!.Email);
    }

    [Fact]
    public async Task Undoing_an_email_change_keeps_the_owners_remove_it_links()
    {
        var (app, outbox) = await Start(o => o.Google(g => { g.Audiences = ["app"]; g.AllowUnsignedTokensForTesting = true; }));
        await using var _ = app;
        var s = await app.SignUpAsync("ann@example.com");
        await app.PostAsync("/auth/v1/sendVerification", null, s.AccessToken);
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("ann@example.com"))));
        var session = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
        // Their Google is linked first (Ann is told), then the address changed and undone.
        var theirs = GoogleToken("intruder");
        await app.SessionAsync(await app.PostAsync("/auth/v1/link/idp", new { provider = "google", idToken = theirs }, session.AccessToken));
        var notice = Outbox.Code(outbox.Last("ann@example.com"));
        await app.PostAsync("/auth/v1/me/email", new { newEmail = "evil@example.com" }, session.AccessToken);
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("evil@example.com"))));
        await TestApp.Json(await Apply(app, Outbox.Code(outbox.Last("ann@example.com"))));
        // The notice still removes it.
        await TestApp.Json(await Apply(app, notice));
        Assert.NotEqual(s.Uid, (await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/idp", new { provider = "google", idToken = theirs }))).Uid);
    }

    private static string GoogleToken(string sub)
    {
        var b64 = (object o) => Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(System.Text.Json.JsonSerializer.Serialize(o));
        var payload = new Dictionary<string, object> { ["iss"] = "https://accounts.google.com", ["aud"] = "app", ["sub"] = sub, ["email"] = $"{sub}@example.com",
            ["email_verified"] = true, ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() };
        return $"{b64(new { alg = "none" })}.{b64(payload)}.";
    }
}
