using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Testcontainers.PostgreSql;
using Winche.Auth.AspNetCore;
using Winche.Auth.DependencyInjection;

namespace Winche.Auth.Tests;

public sealed class PostgresFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:17-alpine").Build();
    private int _next;

    public async Task InitializeAsync() => await _container.StartAsync();
    public async Task DisposeAsync() => await _container.DisposeAsync();

    /// <summary>A new, empty database for one test.</summary>
    public async Task<string> NewDatabaseAsync()
    {
        var name = $"t{Interlocked.Increment(ref _next)}_{Guid.NewGuid():N}"[..20];
        await using var conn = new NpgsqlConnection(_container.GetConnectionString());
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand($"CREATE DATABASE {name}", conn);
        await cmd.ExecuteNonQueryAsync();
        return new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Database = name }.ConnectionString;
    }
}

[CollectionDefinition("postgres")]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>;

public sealed record Session(string AccessToken, string RefreshToken, string Uid, JsonElement Body);

/// <summary>A test app: Winche Auth on a fresh database, its endpoints, and /whoami echoing WincheClaims.From.</summary>
public sealed class TestApp : IAsyncDisposable
{
    public const string Issuer = "https://api.test";
    public WebApplication App { get; }
    public HttpClient Client { get; }

    private TestApp(WebApplication app)
    {
        App = app;
        Client = app.GetTestClient();
    }

    public static async Task<TestApp> StartAsync(
        string? connection,
        Action<WincheAuthOptions>? auth = null,
        Action<WincheTokenOptions>? trust = null,
        Action<IServiceCollection>? services = null,
        Action<WebApplication>? map = null,
        bool trustWinche = true,
        bool methods = true)
    {
        var b = WebApplication.CreateBuilder();
        b.WebHost.UseTestServer();
        b.Host.UseDefaultServiceProvider(o => { o.ValidateScopes = true; o.ValidateOnBuild = true; });   // as in Development
        b.Logging.ClearProviders();
        services?.Invoke(b.Services);
        if (connection is not null)
            b.Services.AddWincheAuth(o =>
            {
                o.ConnectionString = connection;
                o.Issuer = Issuer;
                o.KeyEncryptionSecret = "winche-auth-tests-key-encryption-secret-0123456789";
                o.UserEvents.PollInterval = TimeSpan.FromMilliseconds(200);
                if (methods)
                {
                    o.EmailPassword();
                    o.Anonymous();
                }
                auth?.Invoke(o);
            });
        b.Services.AddAuthentication().AddWincheTokens(t =>
        {
            if (trustWinche) t.TrustWincheAuth();
            trust?.Invoke(t);
        });
        var app = b.Build();
        app.UseAuthentication();
        if (connection is not null) app.MapWincheAuth();
        app.MapGet("/whoami", (HttpContext c) => WincheClaims.From(c) is { } claims ? Results.Json(claims) : Results.Json(new { signedOut = true }));
        map?.Invoke(app);
        await app.StartAsync();
        return new TestApp(app);
    }

    public async Task<HttpResponseMessage> PostAsync(string path, object? body = null, string? bearer = null)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body ?? new { }) };
        if (bearer is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await Client.SendAsync(req);
    }

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string? bearer, object? body = null)
    {
        using var req = new HttpRequestMessage(method, path);
        if (body is not null) req.Content = JsonContent.Create(body);
        if (bearer is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await Client.SendAsync(req);
    }

    public async Task<JsonElement> WhoAmI(string? bearer)
    {
        var resp = await SendAsync(HttpMethod.Get, "/whoami", bearer);
        return await Json(resp);
    }

    public async Task<Session> SessionAsync(HttpResponseMessage resp)
    {
        var body = await Json(resp);
        return new Session(body.GetProperty("accessToken").GetString()!, body.GetProperty("refreshToken").GetString()!,
            body.GetProperty("user").GetProperty("uid").GetString()!, body);
    }

    public Task<Session> SignUpAsync(string email, string password = "correct horse battery") =>
        PostAsync("/auth/v1/signUp", new { email, password }).ContinueWith(t => SessionAsync(t.Result)).Unwrap();

    public static async Task<JsonElement> Json(HttpResponseMessage resp)
    {
        var text = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.IsSuccessStatusCode, $"{(int)resp.StatusCode}: {text}");
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    /// <summary>A failure's status and auth's own code (the error's <c>reason</c>), checking it has the shared shape.</summary>
    public static async Task<(int Status, string Code)> Error(HttpResponseMessage resp)
    {
        var text = await resp.Content.ReadAsStringAsync();
        Assert.False(resp.IsSuccessStatusCode, $"expected a failure, got {(int)resp.StatusCode}: {text}");
        var error = JsonDocument.Parse(text).RootElement.GetProperty("error");
        var kind = error.GetProperty("code").GetString()!;
        Assert.True(WincheError.IsCode(kind), $"'{kind}' isn't a shared error code: {text}");
        if (!error.TryGetProperty("reason", out var reason)) return ((int)resp.StatusCode, kind);
        Assert.Equal(WincheError.Name(AuthErrorCodes.Kind(reason.GetString()!)), kind);
        Assert.Equal(WincheError.StatusOf(AuthErrorCodes.Kind(reason.GetString()!)), (int)resp.StatusCode);
        return ((int)resp.StatusCode, reason.GetString()!);
    }

    public T Service<T>() where T : notnull => App.Services.GetRequiredService<T>();

    public async Task<T> Scoped<T>(Func<IWincheAuth, Task<T>> f)
    {
        await using var scope = App.Services.CreateAsyncScope();
        return await f(scope.ServiceProvider.GetRequiredService<IWincheAuth>());
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await App.StopAsync();
        await App.DisposeAsync();
    }
}
