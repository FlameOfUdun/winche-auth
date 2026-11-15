namespace Winche.Auth;

/// <summary>Something that happened to a user, for <see cref="IWincheAuthObserver"/>s.</summary>
/// <param name="Type">created, updated, deleted, disabled, enabled, claimsChanged or signedIn.</param>
/// <param name="User">The user as they are now (as they were, for deleted).</param>
/// <param name="Provider">For signedIn: how (password, google, emailLink, …).</param>
public sealed record WincheAuthUserEvent(string Type, string Uid, WincheUserInfo User, string? Provider, DateTimeOffset At)
{
    public const string Created = "created";
    public const string Deleted = "deleted";
    public const string Disabled = "disabled";
    public const string Enabled = "enabled";
    public const string ClaimsChanged = "claimsChanged";
    public const string SignedIn = "signedIn";

    /// <summary>The profile, email, its verification, the password or the sign-in methods changed.</summary>
    public const string Updated = "updated";

    public static readonly IReadOnlyList<string> All = [Created, Updated, Deleted, Disabled, Enabled, ClaimsChanged, SignedIn];
}

/// <summary>
/// Told about user changes after they're committed (register any number in DI). Unlike <c>o.Events</c> it can't stop
/// them. Each observer is a durable consumer of Winche Auth's event feed (<c>auth_user_events</c>, Winche.Core's
/// feeds): events reach it in the order they were committed, at least once, on one server at a time, even after a
/// restart. One that throws is retried (holding that observer back, not the others) until it has failed for
/// <see cref="WincheAuthEventOptions.DeadLetterAfter"/>; then the event is a dead letter, shown in the console with
/// the other feeds' and retried or discarded from there. An observer added later starts from then.
/// Winche Auth itself publishes these to the app's change sinks (webhooks, function triggers).
/// </summary>
public interface IWincheAuthObserver
{
    /// <summary>The observer's name, which keeps its place in the feed: change it and it starts again from then.</summary>
    string Name => GetType().FullName ?? GetType().Name;

    /// <summary>Handles one event. <see cref="WincheUserInfo.CustomClaims"/> values arrive as <c>JsonElement</c>s.</summary>
    Task OnUserEventAsync(WincheAuthUserEvent e, CancellationToken ct);
}

/// <summary>How user events reach <see cref="IWincheAuthObserver"/>s.</summary>
public sealed class WincheAuthEventOptions
{
    /// <summary>Events handed to an observer at a time, at most (default 100).</summary>
    public int BatchSize { get; set; } = 100;

    /// <summary>How long an observer may fail on an event before it's set aside as a dead letter (default one hour).</summary>
    public TimeSpan DeadLetterAfter { get; set; } = TimeSpan.FromHours(1);

    /// <summary>How long events are kept once every observer has them (default seven days).</summary>
    public TimeSpan Retention { get; set; } = TimeSpan.FromDays(7);

    /// <summary>How often other servers' events are looked for if a notification is missed (default 5 seconds).</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(5);
}
