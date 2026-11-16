using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Winche.Auth.Tokens;

namespace Winche.Auth.Tests;

/// <summary>User events that survive failures, accounts made whole or not at all, and signing keys rotated safely.</summary>
[Collection("postgres")]
public class ReliabilityTests(PostgresFixture pg)
{
    private const string Password = "correct horse battery";

    private sealed class Flaky : IWincheAuthObserver
    {
        public int FailuresLeft;
        public ConcurrentQueue<string> Seen { get; } = new();
        public Task OnUserEventAsync(WincheAuthUserEvent e, CancellationToken ct)
        {
            if (Interlocked.Decrement(ref FailuresLeft) >= 0) throw new InvalidOperationException("down for now");
            Seen.Enqueue($"{e.Type} {e.User.Email}");
            return Task.CompletedTask;
        }
    }

    private static async Task Until(Func<bool> done)
    {
        for (var i = 0; i < 300 && !done(); i++) await Task.Delay(25);
        Assert.True(done());
    }

    [Fact]
    public async Task An_observer_that_fails_gets_the_event_again_in_order_and_others_dont_wait()
    {
        var flaky = new Flaky { FailuresLeft = 2 };
        var fine = new Flaky();
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s =>
        {
            s.AddSingleton<IWincheAuthObserver>(flaky);
            s.AddSingleton<IWincheAuthObserver>(fine);
        });
        await app.SignUpAsync("ann@example.com");
        await app.SignUpAsync("bob@example.com");
        await Until(() => fine.Seen.Count == 4);
        await Until(() => flaky.Seen.Count == 4);
        Assert.Equal(["created ann@example.com", "signedIn ann@example.com", "created bob@example.com", "signedIn bob@example.com"], flaky.Seen);
    }

    [Fact]
    public async Task An_event_an_observer_gives_up_on_is_a_dead_letter_that_can_be_retried()
    {
        var flaky = new Flaky { FailuresLeft = int.MaxValue };
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddSingleton<IWincheAuthObserver>(flaky),
            auth: o => o.UserEvents.DeadLetterAfter = TimeSpan.Zero);
        await app.SignUpAsync("ann@example.com");
        var events = app.Service<AuthUserEvents>();
        var name = typeof(Flaky).FullName!;
        await Until(() => events.DeadLettersAsync(name).Result.Count == 2);
        Assert.Contains(await events.ConsumersAsync(), c => c.Name == name && c.DeadLetters == 2);

        flaky.FailuresLeft = 0;
        Assert.Equal(2, (await events.RetryAsync(name)).Replayed);
        Assert.Equal(["created ann@example.com", "signedIn ann@example.com"], flaky.Seen);
        Assert.Empty(await events.DeadLettersAsync(name));
    }

    [Fact]
    public async Task An_observer_added_later_starts_from_then_and_misses_nothing_while_no_server_runs_it()
    {
        var db = await pg.NewDatabaseAsync();
        await using (var before = await TestApp.StartAsync(db))
            await before.SignUpAsync("ann@example.com");   // before the observer existed

        var first = new Flaky();
        await using (var app = await TestApp.StartAsync(db, services: s => s.AddSingleton<IWincheAuthObserver>(first)))
        {
            await app.SignUpAsync("bob@example.com");
            await Until(() => first.Seen.Count == 2);
        }
        await using (var without = await TestApp.StartAsync(db))
            await without.SignUpAsync("carol@example.com");   // no server runs the observer now

        var back = new Flaky();
        await using var again = await TestApp.StartAsync(db, services: s => s.AddSingleton<IWincheAuthObserver>(back));
        await Until(() => back.Seen.Count == 2);
        Assert.Equal(["created bob@example.com", "signedIn bob@example.com"], first.Seen);
        Assert.Equal(["created carol@example.com", "signedIn carol@example.com"], back.Seen);
    }

    [Fact]
    public async Task A_sign_up_that_fails_halfway_leaves_no_account_and_no_event()
    {
        var seen = new Flaky();
        var refuse = true;
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddSingleton<IWincheAuthObserver>(seen),
            auth: o => o.Events.AfterCreate = (_, _) => refuse ? throw new InvalidOperationException("the app's own step failed") : Task.CompletedTask);
        await Assert.ThrowsAsync<InvalidOperationException>(() => app.PostAsync("/auth/v1/signUp", new { email = "ann@example.com", password = Password }));

        refuse = false;
        await app.SignUpAsync("ann@example.com");   // not EMAIL_EXISTS: the first never happened
        await Until(() => seen.Seen.Count == 2);
        await Task.Delay(300);
        Assert.Equal(["created ann@example.com", "signedIn ann@example.com"], seen.Seen);
    }

    private static string KidOf(string token) => new JsonWebToken(token).Kid;

    private static async Task<string[]> Published(TestApp app) =>
        [.. (await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/.well-known/jwks.json", null))).GetProperty("keys").EnumerateArray()
            .Select(k => k.GetProperty("kid").GetString()!)];

    [Fact]
    public async Task The_next_key_is_published_a_day_before_it_signs()
    {
        // A time finer than PostgreSQL keeps (it stores microseconds), as the system clock often gives.
        var start = DateTimeOffset.UtcNow;
        var clock = new FakeTimeProvider(start.AddTicks(7 - start.Ticks % TimeSpan.TicksPerMicrosecond));
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddSingleton<TimeProvider>(clock),
            auth: o => { o.KeyRotationInterval = TimeSpan.FromDays(10); o.AccessTokenLifetime = TimeSpan.FromDays(30); });
        var ann = await app.SignUpAsync("ann@example.com");
        var first = KidOf(ann.AccessToken);

        clock.Advance(TimeSpan.FromDays(9.5));   // the next key is due within a day: published, not signing
        var mid = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = Password }));
        Assert.Equal(first, KidOf(mid.AccessToken));
        var published = await Published(app);
        Assert.Equal(2, published.Length);
        var next = published.Single(k => k != first);

        clock.Advance(TimeSpan.FromDays(1));   // a day on: it signs; the old one still checks what it signed
        var later = await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = Password }));
        Assert.Equal(next, KidOf(later.AccessToken));
        Assert.Equal(ann.Uid, (await app.WhoAmI(mid.AccessToken)).GetProperty("uid").GetString());
    }

    [Fact]
    public async Task Servers_rotating_at_once_make_one_key_and_a_forced_rotation_signs_at_once()
    {
        var db = await pg.NewDatabaseAsync();
        await using var one = await TestApp.StartAsync(db);
        await using var two = await TestApp.StartAsync(db);
        var keysOne = one.Service<SigningKeyStore>();
        var keysTwo = two.Service<SigningKeyStore>();
        Assert.Single(await keysOne.ListAsync());   // both started; one key

        await keysOne.RotateAsync();
        var ann = await two.SignUpAsync("ann@example.com");   // two learns of it on its next look
        var listed = await keysTwo.ListAsync();
        Assert.Equal(2, listed.Count);
        Assert.Equal(listed[0].Kid, KidOf((await one.SessionAsync(await one.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = Password }))).AccessToken));
        Assert.NotNull(listed[1].RetiredAt);
        Assert.Equal(ann.Uid, (await one.WhoAmI(ann.AccessToken)).GetProperty("uid").GetString());
    }

    [Fact]
    public async Task Without_a_secret_or_a_master_key_it_wont_start()
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => TestApp.StartAsync(pg.NewDatabaseAsync().Result, auth: o => o.KeyEncryptionSecret = null));
        Assert.Contains("KeyEncryptionSecret", ex.ToString());
    }
}
