using Microsoft.Extensions.DependencyInjection;

namespace Winche.Auth.Tests;

/// <summary>user: for the database's expand: a uid to a public profile.</summary>
[Collection("postgres")]
public class UserReferenceResolverTests(PostgresFixture pg)
{
    [Fact]
    public async Task A_uid_resolves_to_a_public_profile_for_the_signed_in_and_in_full_for_the_app()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), auth: o => o.PublicProfileClaims.Add("role"));
        var ann = await app.SignUpAsync("ann@example.com");
        await app.Scoped(a => a.UpdateProfileAsync(ann.Uid, "Ann Lee", "https://example.com/ann.png"));
        await app.Scoped(a => a.SetCustomClaimsAsync(ann.Uid, new Dictionary<string, object?> { ["role"] = "nurse", ["salary"] = 100 }));
        var resolver = app.App.Services.GetServices<IWincheReferenceResolver>().Single(r => r.Kind == "user");
        Assert.Equal("auth_user_events_events", resolver.ChangeChannel);

        var bob = new ReferenceCaller(new Dictionary<string, object?> { ["uid"] = "bob" }, false);
        var seen = (await resolver.ResolveAsync([ann.Uid, "nobody"], bob, default)).Single();
        Assert.Equal(ann.Uid, seen.Key);
        Assert.Equal(("Ann Lee", "https://example.com/ann.png", "nurse"),
            ((string?)seen.Value["displayName"], (string?)seen.Value["photoUrl"], (string?)seen.Value["role"]));
        Assert.False(seen.Value.ContainsKey("email"));
        Assert.False(seen.Value.ContainsKey("salary"));

        Assert.Empty(await resolver.ResolveAsync([ann.Uid], new ReferenceCaller(null, false), default));   // signed out
        var own = await resolver.ResolveAsync([ann.Uid], new ReferenceCaller(new Dictionary<string, object?> { ["uid"] = ann.Uid }, false), default);
        Assert.Equal("ann@example.com", (string?)own[ann.Uid]["email"]);   // their own account
        var server = await resolver.ResolveAsync([ann.Uid], ReferenceCaller.Server, default);
        Assert.Equal("ann@example.com", (string?)server[ann.Uid]["email"]);
    }
}
