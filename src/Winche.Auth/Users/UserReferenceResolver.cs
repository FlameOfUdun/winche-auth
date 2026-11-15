using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Winche.Core.Feeds;

namespace Winche.Auth.Users;

/// <summary>
/// <c>user:</c> for the database's <c>expand</c>: a document field holding a uid comes back with that user's public
/// profile, <c>{uid, displayName, photoUrl}</c> plus the custom claims named in
/// <see cref="WincheAuthOptions.PublicProfileClaims"/>. A signed-in caller sees that much of anyone (their own account in
/// full); signed-out callers see nothing; the app's own code sees everything (<see cref="WincheUserInfo"/>).
/// </summary>
internal sealed class UserReferenceResolver(IServiceProvider services, WincheAuthOptions options) : IWincheReferenceResolver
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public string Kind => "user";

    /// <summary>User events: a profile change refreshes live subscriptions that expand users.</summary>
    public string? ChangeChannel => WincheEventFeed.Channel(AuthUserEvents.Table);

    public async Task<IReadOnlyDictionary<string, JsonObject>> ResolveAsync(IReadOnlyList<string> keys, ReferenceCaller caller, CancellationToken ct)
    {
        var found = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        if (!caller.Trusted && caller.Uid is null) return found;   // signed out: no profiles
        await using var scope = services.CreateAsyncScope();
        var auth = scope.ServiceProvider.GetRequiredService<IWincheAuth>();
        foreach (var uid in keys.Where(k => k.Length is > 0 and <= 64).Distinct())
        {
            if (await auth.GetUserAsync(uid, ct) is not { } user) continue;
            found[uid] = caller.Trusted || caller.Uid == uid ? JsonSerializer.SerializeToNode(user, Json)!.AsObject() : Public(user);
        }
        return found;
    }

    private JsonObject Public(WincheUserInfo user)
    {
        var profile = new JsonObject { ["uid"] = user.Uid, ["displayName"] = user.DisplayName, ["photoUrl"] = user.PhotoUrl };
        foreach (var claim in options.PublicProfileClaims)
            if (user.CustomClaims.TryGetValue(claim, out var value)) profile[claim] = JsonSerializer.SerializeToNode(value, Json);
        return profile;
    }
}
