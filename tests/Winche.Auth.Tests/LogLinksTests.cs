using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Winche.Auth.Tests;

/// <summary>Emails only logged: with links (local development), or without them (no link anywhere, for a real server).</summary>
[Collection("postgres")]
public class LogLinksTests(PostgresFixture pg)
{
    private sealed class Captured : ILoggerProvider, ILogger
    {
        public readonly List<string> Lines = [];
        public ILogger CreateLogger(string category) => this;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? e, Func<TState, Exception?, string> format) { lock (Lines) Lines.Add(format(state, e)); }
        public void Dispose() { }
    }

    private async Task<List<string>> SignUpWith(Action<Email.AuthEmailOptions> email)
    {
        var log = new Captured();
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), services: s => s.AddLogging(b => b.AddProvider(log)), auth: o =>
            o.Email(e => { e.SendInBackground = false; e.AppName = "Test"; email(e); }));
        await app.SignUpAsync("ann@example.com");
        lock (log.Lines) return [.. log.Lines.Where(l => l.Contains("ann@example.com"))];
    }

    [Fact]
    public async Task Without_links_nothing_that_works_is_written()
    {
        var lines = await SignUpWith(e => e.LogLinks(withLinks: false));
        Assert.Contains(lines, l => l.Contains("not sent") && l.Contains("verifyEmail"));
        Assert.DoesNotContain(lines, l => l.Contains("code=") || l.Contains("https://"));   // no working link in any line
    }

    [Fact]
    public async Task With_links_for_local_development_the_link_is_logged()
    {
        Assert.Contains(await SignUpWith(e => e.LogLinks()), l => l.Contains("code="));
    }
}
