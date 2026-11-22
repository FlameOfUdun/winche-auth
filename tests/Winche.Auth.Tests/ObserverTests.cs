using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Winche.Auth.Tests;

/// <summary>IWincheAuthObserver: told about user changes after they commit, in order; a failing one holds back only itself.</summary>
[Collection("postgres")]
public class ObserverTests(PostgresFixture pg)
{
    private sealed class Recorder : IWincheAuthObserver
    {
        public ConcurrentQueue<string> Seen { get; } = new();
        public Task OnUserEventAsync(WincheAuthUserEvent e, CancellationToken ct)
        {
            Seen.Enqueue($"{e.Type} {e.User.Email ?? e.Uid}{(e.Provider is null ? "" : $" via {e.Provider}")}");
            return Task.CompletedTask;
        }
    }

    private sealed class Broken : IWincheAuthObserver
    {
        public Task OnUserEventAsync(WincheAuthUserEvent e, CancellationToken ct) => throw new InvalidOperationException("observer down");
    }

    [Fact]
    public async Task Observers_hear_creates_sign_ins_and_admin_changes()
    {
        var recorder = new Recorder();
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s =>
        {
            s.AddSingleton<IWincheAuthObserver>(new Broken());
            s.AddSingleton<IWincheAuthObserver>(recorder);
        });
        var ann = await app.SignUpAsync("ann@example.com");
        await TestApp.Json(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
        await app.Scoped(a => a.SetDisabledAsync(ann.Uid, true));
        await app.Scoped(a => a.SetCustomClaimsAsync(ann.Uid, new Dictionary<string, object?> { ["role"] = "editor" }));
        await app.Scoped(async a => { await a.DeleteUserAsync(ann.Uid); return true; });
        // Delivered after the commit: wait for the last one.
        for (var i = 0; i < 200 && recorder.Seen.Count < 6; i++) await Task.Delay(25);
        Assert.Equal([
            "created ann@example.com", "signedIn ann@example.com via password", "signedIn ann@example.com via password",
            "disabled ann@example.com", "claimsChanged ann@example.com", "deleted ann@example.com",
        ], recorder.Seen);
    }
}
