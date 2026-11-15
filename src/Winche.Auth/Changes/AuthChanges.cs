using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Winche.Auth;

/// <summary>Winche Auth's changes, for webhooks and functions.</summary>
internal static class AuthChanges
{
    /// <summary>User events, as hooks and functions see them.</summary>
    public static readonly WincheChangeSource Source = new("auth", "Users", WincheAuthUserEvent.All, HasPaths: false, Variables: ["uid", "email", "provider"]);

    /// <summary>Publishes user events to the app's change sinks.</summary>
    public static void Add(IServiceCollection services)
    {
        services.AddSingleton<IWincheAuthObserver, ChangePublisher>();
        services.AddSingleton(Source);
    }
}

/// <summary>Turns user events into <see cref="WincheChange"/>s for every sink (queued right after the change is saved).</summary>
internal sealed class ChangePublisher(IEnumerable<IWincheChangeSink> sinks) : IWincheAuthObserver
{
    public string Name => "changes";   // the app's webhooks and function triggers

    internal bool HasSinks => sinks.Any();

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public Task OnUserEventAsync(WincheAuthUserEvent e, CancellationToken ct)
    {
        var vars = new Dictionary<string, string> { ["uid"] = e.Uid, ["email"] = e.User.Email ?? "", ["provider"] = e.Provider ?? "" };
        return WincheChanges.PublishAsync(sinks,
            new WincheChange("auth", e.Type, null, e.At, JsonSerializer.SerializeToNode(e.User, Json) as JsonObject, null, vars), ct);
    }
}
