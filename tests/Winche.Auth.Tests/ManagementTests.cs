using System.Net;

namespace Winche.Auth.Tests;

[Collection("postgres")]
public class ManagementTests(PostgresFixture pg)
{
    [Fact]
    public async Task Custom_claims_reach_the_next_token()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var s = await app.SignUpAsync("ann@example.com");
        await app.Scoped(a => a.SetCustomClaimsAsync(s.Uid, new Dictionary<string, object?>
        {
            ["role"] = "clinician", ["level"] = 3, ["orgs"] = new[] { "st-marys", "example" },
        }));
        var next = await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = s.RefreshToken }));
        var claims = await app.WhoAmI(next.AccessToken);
        Assert.Equal("clinician", claims.GetProperty("role").GetString());
        Assert.Equal(3, claims.GetProperty("level").GetInt32());
        Assert.Equal(["st-marys", "example"], claims.GetProperty("orgs").EnumerateArray().Select(o => o.GetString()));
        Assert.Equal("clinician", next.Body.GetProperty("user").GetProperty("customClaims").GetProperty("role").GetString());

        var reserved = await Assert.ThrowsAsync<AuthException>(() => app.Scoped(a => a.SetCustomClaimsAsync(s.Uid, new Dictionary<string, object?> { ["uid"] = "someone-else" })));
        Assert.Equal("INVALID_CLAIMS", reserved.Code);
        var big = await Assert.ThrowsAsync<AuthException>(() => app.Scoped(a => a.SetCustomClaimsAsync(s.Uid, new Dictionary<string, object?> { ["x"] = new string('a', 2000) })));
        Assert.Equal("INVALID_CLAIMS", big.Code);

        await app.Scoped(a => a.SetCustomClaimsAsync(s.Uid, null));
        var cleared = await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = next.RefreshToken }));
        Assert.False((await app.WhoAmI(cleared.AccessToken)).TryGetProperty("role", out _));
    }

    [Fact]
    public async Task Disabling_a_user_ends_their_sessions_and_stops_sign_in()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var s = await app.SignUpAsync("ann@example.com");
        await app.Scoped(a => a.SetDisabledAsync(s.Uid, true));
        Assert.Equal(401, (int)(await app.PostAsync("/auth/v1/token", new { refreshToken = s.RefreshToken })).StatusCode);
        // Only someone with the right password learns it's disabled.
        Assert.Equal((401, "INVALID_CREDENTIALS"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "wrong password!" })));
        Assert.Equal((403, "USER_DISABLED"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" })));

        await app.Scoped(a => a.SetDisabledAsync(s.Uid, false));
        await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
    }

    [Fact]
    public async Task Users_are_listed_searched_and_deleted_with_their_sessions()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var ann = await app.SignUpAsync("ann@example.com");
        await app.SignUpAsync("bob@example.com");
        await app.PostAsync("/auth/v1/signIn/anonymous");

        var all = await app.Scoped(a => a.ListUsersAsync());
        Assert.Equal(3, all.Total);
        Assert.True(all.Users[0].IsAnonymous);   // newest first
        var found = await app.Scoped(a => a.ListUsersAsync("ANN@"));
        Assert.Equal(ann.Uid, Assert.Single(found.Users).Uid);
        Assert.Equal(ann.Uid, Assert.Single((await app.Scoped(a => a.ListUsersAsync(ann.Uid))).Users).Uid);
        Assert.Empty((await app.Scoped(a => a.ListUsersAsync("100%_"))).Users);

        var sessions = await app.Scoped(a => a.ListSessionsAsync(ann.Uid));
        Assert.Equal("password", Assert.Single(sessions).Provider);

        Assert.Equal(HttpStatusCode.NoContent, (await app.SendAsync(HttpMethod.Delete, "/auth/v1/me", ann.AccessToken)).StatusCode);
        Assert.Null(await app.Scoped(a => a.GetUserAsync(ann.Uid)));
        Assert.Equal(401, (int)(await app.PostAsync("/auth/v1/token", new { refreshToken = ann.RefreshToken })).StatusCode);
        Assert.Equal(2, (await app.Scoped(a => a.ListUsersAsync())).Total);
    }

    [Fact]
    public async Task Your_code_can_refuse_and_follow_sign_ups()
    {
        var created = new List<string>();
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), auth: o =>
        {
            o.Events.BeforeCreate = (attempt, _) => attempt.Email is { } e && !e.EndsWith("@example.com")
                ? throw new AuthDeniedException("Only example.com addresses can sign up.") : Task.CompletedTask;
            o.Events.AfterCreate = (user, _) => { lock (created) created.Add(user.Uid); return Task.CompletedTask; };
            o.Events.BeforeSignIn = (user, _, _) => user.Email == "blocked@example.com"
                ? throw new AuthDeniedException("Not today.") : Task.CompletedTask;
        });
        Assert.Equal((403, "DENIED"), await TestApp.Error(await app.PostAsync("/auth/v1/signUp", new { email = "eve@evil.test", password = "correct horse battery" })));
        var ann = await app.SignUpAsync("ann@example.com");
        Assert.Equal([ann.Uid], created);
        await app.SignUpAsync("blocked@example.com");
        Assert.Equal((403, "DENIED"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn", new { email = "blocked@example.com", password = "correct horse battery" })));
    }

    [Fact]
    public async Task Profile_updates()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var s = await app.SignUpAsync("ann@example.com");
        var user = await TestApp.Json(await app.SendAsync(HttpMethod.Patch, "/auth/v1/me", s.AccessToken, new { displayName = "  Ann K  ", photoUrl = "https://cdn.example.com/ann.png" }));
        Assert.Equal("Ann K", user.GetProperty("displayName").GetString());
        Assert.Equal((400, "INVALID_ARGUMENT"), await TestApp.Error(await app.SendAsync(HttpMethod.Patch, "/auth/v1/me", s.AccessToken, new { photoUrl = "javascript:alert(1)" })));
        var next = await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = s.RefreshToken }));
        Assert.Equal("Ann K", (await app.WhoAmI(next.AccessToken)).GetProperty("name").GetString());
    }
}
