using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Winche.Core;
using Winche.Core.Feeds;

namespace Winche.Auth;

/// <summary>
/// Winche Auth's user events (feed <c>auth</c>, table <c>auth_user_events</c>): written in the transaction that makes
/// the change, delivered to each <see cref="IWincheAuthObserver"/> as a durable consumer. How the observers are doing,
/// and their dead letters, for the console and health checks.
/// </summary>
public sealed class AuthUserEvents : IWincheFeedConsumers
{
    internal const string Name = "auth";
    internal const string Table = "auth_user_events";
    internal const string DataSourceKey = "winche-auth";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly WincheFeed<FeedEvent> _feed;

    internal NpgsqlDataSource Db { get; }
    internal WincheAuthEventOptions Options { get; }

    /// <summary>The observers by consumer name (two of one name get <c>#2</c>, <c>#3</c>, …).</summary>
    internal IReadOnlyDictionary<string, IWincheAuthObserver> Observers { get; }

    /// <summary>Raised after this server commits an event, so delivery needn't wait for the notification.</summary>
    internal event Action? Committed;

    internal AuthUserEvents([FromKeyedServices(DataSourceKey)] NpgsqlDataSource db, IEnumerable<IWincheAuthObserver> observers, WincheAuthOptions options)
    {
        Db = db;
        Options = options.UserEvents;
        _feed = WincheEventFeed.Open(db, Name, Table);
        var named = new Dictionary<string, IWincheAuthObserver>(StringComparer.Ordinal);
        // Publishing to the app's change sinks is an observer only when there are some.
        foreach (var o in observers.Where(o => o is not ChangePublisher { HasSinks: false }))
        {
            var name = o.Name;
            for (var n = 2; named.ContainsKey(name); n++) name = $"{o.Name}#{n}";
            named[name] = o;
        }
        Observers = named;
    }

    internal static readonly string[] Schema = [WincheEventFeed.TableSql(Table)];

    /// <summary>Creates the tables, and starts keeping events for every observer that has no position yet.</summary>
    internal async Task StartAsync(CancellationToken ct)
    {
        await WincheFeedTables.EnsureAsync(Db, ct);
        await WincheSchema.EnsureAsync(Db, "auth-events", Schema, ct);
        foreach (var name in Observers.Keys)
            if (await _feed.GetPositionAsync(name, ct) is null)
                await _feed.SavePositionAsync(name, await _feed.GetHeadAsync(ct), ct);
    }

    /// <summary>Writes an event in the caller's transaction.</summary>
    internal static Task AppendAsync(NpgsqlConnection conn, NpgsqlTransaction tx, string type, WincheUserInfo user, string? provider, CancellationToken ct) =>
        WincheEventFeed.AppendAsync(conn, tx, Table, type, user.Uid,
            new JsonObject { ["user"] = JsonSerializer.SerializeToNode(user, Json), ["provider"] = provider }, ct);

    internal void OnCommitted() => Committed?.Invoke();

    internal WincheFeed<FeedEvent> Feed => _feed;

    /// <summary>Hands <paramref name="events"/> to <paramref name="observer"/> in order; says which one failed, if one does.</summary>
    internal static async Task DeliverAsync(IWincheAuthObserver observer, IReadOnlyList<FeedEvent> events, CancellationToken ct)
    {
        for (var i = 0; i < events.Count; i++)
        {
            var e = events[i];
            try
            {
                var user = e.Data?["user"].Deserialize<WincheUserInfo>(Json)
                    ?? throw new InvalidDataException($"Auth event #{e.Seq} has no user.");
                await observer.OnUserEventAsync(new WincheAuthUserEvent(e.Type, e.Path, user, (string?)e.Data?["provider"], e.At), ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { throw new FeedDeliveryException(i, ex); }
        }
    }

    /// <summary>Each observer's consumer: position, lag, failure, dead letters.</summary>
    public Task<IReadOnlyList<FeedConsumerStatus>> ConsumersAsync(CancellationToken ct = default) => _feed.GetStatusAsync([.. Observers.Keys], ct);

    /// <summary>The events observers gave up on, oldest first.</summary>
    public Task<IReadOnlyList<FeedDeadLetter>> DeadLettersAsync(string? consumer = null, int limit = 100, CancellationToken ct = default) =>
        _feed.GetDeadLettersAsync(consumer, null, limit, ct);

    /// <summary>Delivers an observer's dead letters again; those that fail again are kept.</summary>
    public Task<FeedReplayResult> RetryAsync(string consumer, CancellationToken ct = default) =>
        Observers.TryGetValue(consumer, out var observer)
            ? _feed.ReplayDeadLettersAsync(consumer, (e, t) => DeliverAsync(observer, [e], t), ct)
            : Task.FromResult(new FeedReplayResult(0, 0));

    /// <summary>Drops one dead letter without delivering it.</summary>
    public async Task<bool> DiscardAsync(long id, CancellationToken ct = default) => await _feed.DeleteDeadLettersAsync(id, ct: ct) > 0;

    string IWincheFeedConsumers.Feed => Name;
}

/// <summary>Runs each observer's consumer of the auth feed (one server at a time per observer), and prunes the feed.</summary>
internal sealed class AuthEventService(AuthUserEvents events, ILogger<AuthEventService>? logger = null) : BackgroundService
{
    private readonly ILogger _logger = logger ?? (ILogger)NullLogger.Instance;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (events.Observers.Count == 0) return;
        var options = events.Options;
        var runners = events.Observers.Select(o => new WincheFeedRunner<FeedEvent>(events.Feed, o.Key, (batch, ct) => AuthUserEvents.DeliverAsync(o.Value, batch, ct),
            new WincheFeedOptions { BatchSize = options.BatchSize, DeadLetterAfter = options.DeadLetterAfter }, _logger)).ToList();
        await using var wake = new WincheFeedWake(events.Db, WincheEventFeed.Channel(AuthUserEvents.Table), options.PollInterval, _logger);
        events.Committed += wake.Wake;
        try
        {
            await Task.WhenAll(runners.Select(r => r.RunAsync(wake.WaitAsync, stoppingToken)).Append(PruneAsync(stoppingToken)));
        }
        finally { events.Committed -= wake.Wake; }
    }

    private async Task PruneAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var now = DateTimeOffset.UtcNow;
                var retention = events.Options.Retention;
                // Kept while an observer still needs them, up to four times the retention.
                await events.Feed.PruneAsync(now - retention, now - 4 * retention, [.. events.Observers.Keys], ct);
                await Task.Delay(TimeSpan.FromMinutes(10), ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Pruning Winche Auth's user events failed.");
                try { await Task.Delay(TimeSpan.FromMinutes(1), ct); } catch (OperationCanceledException) { break; }
            }
        }
    }
}
