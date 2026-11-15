using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Winche.Auth.Logging;

namespace Winche.Auth.Tests;

[Collection("postgres")]
public class AuthEventsTests(PostgresFixture pg)
{
    private sealed class Capture : ILoggerProvider, ILogger
    {
        public List<(LogLevel Level, string Message, Dictionary<string, object?> Values)> Entries { get; } = [];
        public ILogger CreateLogger(string category) => category == AuthEvents.Category ? this : Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        public void Dispose() { }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? ex, Func<TState, Exception?, string> format)
        {
            lock (Entries) Entries.Add((level, format(state, ex), state is IEnumerable<KeyValuePair<string, object?>> kv ? kv.ToDictionary(k => k.Key, k => k.Value) : []));
        }
    }

    [Fact]
    public async Task Sign_ins_and_account_changes_are_logged_as_structured_entries()
    {
        var capture = new Capture();
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), auth: o => o.MaxFailedSignIns = 2,
            services: s => s.AddSingleton<ILoggerProvider>(capture));
        var ann = await app.SignUpAsync("ann@example.com");
        await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "wrong password!" });
        await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "wrong password!" });
        await app.Scoped(a => a.UnlockAsync(ann.Uid));
        await app.SessionAsync(await app.PostAsync("/auth/v1/signIn", new { email = "ann@example.com", password = "correct horse battery" }));
        await app.Scoped(a => a.SetDisabledAsync(ann.Uid, true));

        List<(LogLevel Level, string Message, Dictionary<string, object?> Values)> e;
        lock (capture.Entries) e = [.. capture.Entries];
        Assert.Equal(["auth.signUp", "auth.signIn", "auth.lockout", "auth.signIn", "auth.unlock", "auth.signIn", "auth.disable"],
            e.Select(x => (string)x.Values["Operation"]!));
        Assert.Equal((LogLevel.Information, $"{ann.Uid} signed up with ann@example.com."), (e[0].Level, e[0].Message));
        Assert.Equal(ann.Uid, e[0].Values["Principal"]);
        Assert.Equal((LogLevel.Warning, "invalidCredentials", "ann@example.com"), (e[1].Level, e[1].Values["Outcome"], e[1].Values["Principal"]));
        Assert.Equal("Sign-in as ann@example.com failed: The email or password is wrong.", e[1].Message);
        Assert.Equal(("lockedOut", ann.Uid), (e[2].Values["Outcome"], e[2].Values["Principal"]));
        Assert.Equal("lockedOut", e[3].Values["Outcome"]);
        Assert.Equal("ok", e[5].Values["Outcome"]);
        Assert.Equal($"{ann.Uid} was disabled and signed out everywhere.", e[6].Message);
    }
}
