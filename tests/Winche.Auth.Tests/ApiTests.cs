using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Time.Testing;
using Winche.Auth.AspNetCore;
using Winche.Auth.Email;

namespace Winche.Auth.Tests;

/// <summary>What the app's own server can do: custom tokens, links it sends itself, passwords, paging; and how it's watched.</summary>
[Collection("postgres")]
public class ApiTests(PostgresFixture pg)
{
    private const string Password = "correct horse battery";

    [Fact]
    public async Task A_custom_token_signs_in_as_its_uid_and_is_nothing_else()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddSingleton<TimeProvider>(clock));
        var token = await app.Scoped(a => a.CreateCustomTokenAsync("ext-42"));

        var first = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/custom", new { token }));
        Assert.Equal("ext-42", first.Uid);   // made on first use
        var claims = await app.WhoAmI(first.AccessToken);
        Assert.Equal("custom", claims.GetProperty("provider").GetString());
        Assert.Equal("ext-42", (await app.SessionAsync(await app.PostAsync("/auth/v1/signIn/custom", new { token }))).Uid);

        Assert.True((await app.WhoAmI(token)).TryGetProperty("signedOut", out _));   // not an access token
        Assert.Equal((401, "INVALID_CUSTOM_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/custom", new { token = first.AccessToken })));
        clock.Advance(TimeSpan.FromMinutes(61));
        Assert.Equal((401, "INVALID_CUSTOM_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/custom", new { token })));
        await Assert.ThrowsAsync<AuthException>(() => app.Scoped(a => a.CreateCustomTokenAsync("ext-42", TimeSpan.FromHours(2))));
    }

    [Fact]
    public async Task The_app_can_make_links_to_send_itself_and_set_anyones_password()
    {
        var outbox = new Outbox();
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddSingleton<IAuthEmailSender>(outbox),
            auth: o => { o.Email(e => { e.SendInBackground = false; e.AppName = "Test"; e.SendVerificationOnSignUp = false; }); o.EmailLink(l => l.LinkUrl = "myapp://finish"); });
        var ann = await app.SignUpAsync("ann@example.com");

        var link = await app.Scoped(a => a.CreateEmailLinkAsync(AuthEmailKinds.ResetPassword, "ann@example.com"));
        Assert.Empty(outbox.Sent);   // nothing emailed: the app sends it
        var code = WincheAuthCode(link);
        await TestApp.Json(await app.PostAsync("/auth/v1/resetPassword", new { code, newPassword = "a brand new password" }));
        await TestApp.Json(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "a brand new password" }));
        Assert.StartsWith("myapp://finish?mode=signIn&code=", await app.Scoped(a => a.CreateEmailLinkAsync(AuthEmailKinds.SignIn, "new@example.com")));
        var missing = await Assert.ThrowsAsync<AuthException>(() => app.Scoped(a => a.CreateEmailLinkAsync(AuthEmailKinds.VerifyEmail, "nobody@example.com")));
        Assert.Equal((WincheErrorCode.NotFound, "USER_NOT_FOUND"), (missing.Error.Kind, missing.Error.Reason));

        // An account made without a password gets one; every session ends.
        var bob = await app.Scoped(a => a.CreateUserAsync("bob@example.com", null));
        await app.Scoped(a => a.SetPasswordAsync(bob.Uid, Password));
        await TestApp.Json(await app.PostAsync("/auth/v1/signIn", new { email = "bob@example.com", password = Password }));
        await app.Scoped(a => a.SetPasswordAsync(ann.Uid, "the console chose this"));
        Assert.Equal((401, "INVALID_REFRESH_TOKEN"), await TestApp.Error(await app.PostAsync("/auth/v1/token", new { refreshToken = ann.RefreshToken })));
    }

    private static string WincheAuthCode(string link) => System.Text.RegularExpressions.Regex.Match(link, "code=([A-Za-z0-9_-]+)").Groups[1].Value;

    [Fact]
    public async Task Every_user_a_page_at_a_time_keeping_its_place_as_users_come_and_go()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddSingleton<TimeProvider>(clock));
        var made = new List<string>();
        for (var i = 0; i < 5; i++)
        {
            made.Add((await app.Scoped(a => a.CreateUserAsync($"u{i}@example.com", null))).Uid);
            clock.Advance(TimeSpan.FromSeconds(1));
        }
        var first = await app.Scoped(a => a.ListUsersPageAsync(null, 2));
        await app.Scoped(a => a.CreateUserAsync("newest@example.com", null));   // added meanwhile: before the first page, not repeated
        await app.Scoped(async a => { await a.DeleteUserAsync(first.Users[0].Uid); return true; });
        var second = await app.Scoped(a => a.ListUsersPageAsync(first.NextPageToken, 2));
        var third = await app.Scoped(a => a.ListUsersPageAsync(second.NextPageToken, 2));
        Assert.Null(third.NextPageToken);
        Assert.Equal(Enumerable.Reverse(made), first.Users.Concat(second.Users).Concat(third.Users).Select(u => u.Uid));
        await Assert.ThrowsAsync<AuthException>(() => app.Scoped(a => a.ListUsersPageAsync("not-a-token", 2)));
    }

    private sealed class Recorder : IWincheAuthObserver
    {
        public ConcurrentQueue<string> Seen { get; } = new();
        public Task OnUserEventAsync(WincheAuthUserEvent e, CancellationToken ct) { Seen.Enqueue(e.Type); return Task.CompletedTask; }
    }

    [Fact]
    public async Task Changes_to_a_user_are_updated_events_and_auth_reports_metrics_and_health()
    {
        var recorder = new Recorder();
        var counted = new ConcurrentBag<string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (i, l) => { if (i.Meter.Name == Winche.Auth.Logging.AuthEvents.MeterName) l.EnableMeasurementEvents(i); };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
            counted.Add(string.Join(" ", tags.ToArray().Select(t => t.Value))));
        listener.Start();

        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s =>
        {
            s.AddSingleton<IWincheAuthObserver>(recorder);
            s.AddHealthChecks().AddWincheAuth();
        });
        var ann = await app.SignUpAsync("ann@example.com");
        await app.Scoped(a => a.UpdateProfileAsync(ann.Uid, "Ann", null));
        await app.Scoped(a => a.SetEmailVerifiedAsync(ann.Uid, true));
        for (var i = 0; i < 200 && recorder.Seen.Count < 4; i++) await Task.Delay(25);
        Assert.Equal(["created", "signedIn", "updated", "updated"], recorder.Seen);
        Assert.Contains("auth.signUp ok", counted);

        var health = await app.Service<HealthCheckService>().CheckHealthAsync();
        Assert.Equal(HealthStatus.Healthy, health.Status);
    }

    [Fact]
    public async Task An_admin_sets_an_accounts_email_at_once_ending_its_sessions()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var ann = await app.SignUpAsync("ann@example.com");
        await app.SignUpAsync("bob@example.com");
        var user = await app.Scoped(a => a.SetEmailAsync(ann.Uid, "Ann.New@example.com"));
        Assert.Equal(("ann.new@example.com", true), (user.Email?.ToLowerInvariant(), user.EmailVerified));
        await Assert.ThrowsAsync<AuthException>(() => app.Scoped(a => a.RefreshAsync(ann.RefreshToken, AuthRequestInfo.Server)));
        var taken = await Assert.ThrowsAsync<AuthException>(() => app.Scoped(a => a.SetEmailAsync(ann.Uid, "bob@example.com")));
        Assert.Equal(AuthErrorCodes.EmailExists, taken.Code);
    }

}
