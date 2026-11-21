using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Winche.Auth.Email;
using Winche.Auth.Settings;
using Winche.Core;
using Winche.Secrets;
using Xunit;

namespace Winche.Auth.Tests;

/// <summary>A one-connection-at-a-time SMTP server that keeps what it's sent (enough for MailKit, no TLS).</summary>
public sealed class FakeSmtp : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public List<(string User, string Password, string Data)> Received { get; } = [];

    public FakeSmtp()
    {
        _listener.Start();
        _ = Task.Run(LoopAsync);
    }

    private async Task LoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
            await using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII);
            await using var writer = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
            await writer.WriteLineAsync("220 fake ESMTP");
            string user = "", password = "";
            while (await reader.ReadLineAsync() is { } line)
            {
                var cmd = line.Split(' ')[0].ToUpperInvariant();
                if (cmd is "EHLO") { await writer.WriteLineAsync("250-fake"); await writer.WriteLineAsync("250 AUTH PLAIN"); }
                else if (cmd is "AUTH")
                {
                    var plain = Encoding.UTF8.GetString(Convert.FromBase64String(line.Split(' ')[2])).Split('\0');
                    (user, password) = (plain[1], plain[2]);
                    await writer.WriteLineAsync("235 ok");
                }
                else if (cmd is "DATA")
                {
                    await writer.WriteLineAsync("354 go");
                    var data = new StringBuilder();
                    while (await reader.ReadLineAsync() is { } d && d != ".") data.AppendLine(d);
                    Received.Add((user, password, data.ToString()));
                    await writer.WriteLineAsync("250 queued");
                }
                else if (cmd is "QUIT") { await writer.WriteLineAsync("221 bye"); break; }
                else await writer.WriteLineAsync("250 ok");
            }
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
    }
}

/// <summary>Winche Auth's own settings changed from the console (o.UseSettings()).</summary>
[Collection("postgres")]
public class SignInSettingsTests(PostgresFixture pg)
{
    private const string MasterKey = "sign-in-settings-tests-master-key-0123456789";

    private static async Task<TestApp> Start(string db, Action<WincheAuthOptions>? auth = null) => await TestApp.StartAsync(db,
        services: s => s.AddWincheConfig(o => { o.ConnectionString = db; o.MasterKey = MasterKey; }),
        auth: o => { o.UseSettings(); auth?.Invoke(o); });

    private static JsonNode Doc(WincheAuthSettings s) => JsonSerializer.SerializeToNode(s, SettingsArea.Json)!;

    [Fact]
    public async Task Methods_lifetimes_and_password_rules_change_without_a_restart()
    {
        await using var app = await Start(await pg.NewDatabaseAsync());
        var area = app.Service<SettingsArea<WincheAuthSettings>>();
        Assert.True(area.Current.Anonymous);   // the code's values to start with
        Assert.Equal(15, area.Current.Sessions.AccessTokenMinutes);
        Assert.Equal(HttpStatusCode.OK, (await app.PostAsync("/auth/v1/signIn/anonymous")).StatusCode);

        await app.Service<SettingsStore>().SaveAsync(WincheAuthSettings.Area, Doc(area.Current with
        {
            Anonymous = false,
            EmailPassword = area.Current.EmailPassword with { MinLength = 14 },
            Sessions = new SessionSettings { AccessTokenMinutes = 5, RefreshTokenDays = 7 },
        }), "admin@example.com", "No guests");

        Assert.Equal((400, "SIGN_IN_METHOD_NOT_ENABLED"), await TestApp.Error(await app.PostAsync("/auth/v1/signIn/anonymous")));
        Assert.Equal(HttpStatusCode.BadRequest, (await app.PostAsync("/auth/v1/signUp", new { email = "ann@example.com", password = "thirteen-char" })).StatusCode);
        var session = await app.SignUpAsync("ann@example.com", "fourteen-chars!");
        var exp = new JsonWebToken(session.AccessToken).ValidTo;
        Assert.InRange(exp - DateTime.UtcNow, TimeSpan.FromMinutes(4), TimeSpan.FromMinutes(5.1));
        var config = await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/auth/v1/providers", null));
        Assert.False(config.GetProperty("anonymous").GetBoolean());

        // Back to the code's values.
        await app.Service<SettingsStore>().ResetAsync(WincheAuthSettings.Area, "admin@example.com", "Guests again");
        Assert.Equal(HttpStatusCode.OK, (await app.PostAsync("/auth/v1/signIn/anonymous")).StatusCode);
    }

    [Fact]
    public async Task Settings_that_cant_work_are_refused_with_reasons()
    {
        await using var app = await Start(await pg.NewDatabaseAsync());
        var current = app.Service<SettingsArea<WincheAuthSettings>>().Current;
        var bad = current with
        {
            EmailLink = new EmailLinkSettings { Enabled = true, LinkUrl = "https://app.example.com/finish" },
            Sessions = new SessionSettings { AccessTokenMinutes = 90, RefreshTokenDays = 1 },
            Providers = [new SignInProviderSettings { Name = "google", Kind = "google", Audiences = [] }],
        };
        var ex = await Assert.ThrowsAsync<SettingsValidationException>(() =>
            app.Service<SettingsStore>().SaveAsync(WincheAuthSettings.Area, Doc(bad), null, "x"));
        Assert.Contains(ex.Errors, e => e.Contains("Email-link sign-in needs email turned on"));
        Assert.Contains(ex.Errors, e => e.Contains("'google': set Audiences"));
    }

    [Fact]
    public async Task A_providers_keycloak_sync_is_set_in_settings_with_its_secret_in_the_secret_store()
    {
        await using var app = await Start(await pg.NewDatabaseAsync());
        var current = app.Service<SettingsArea<WincheAuthSettings>>().Current;
        var staff = new SignInProviderSettings
        {
            Name = "staff", Kind = "oidc", Authority = "https://id.example.com/realms/staff", Audiences = ["staff-app"],
            KeycloakSync = new KeycloakSyncSettings { ClientId = "winche-sync", PollSeconds = 30, Attributes = new Dictionary<string, string> { ["ward"] = "ward" } },
        };
        await app.Service<SettingsStore>().SaveAsync(WincheAuthSettings.Area, Doc(current with { Providers = [staff] }), "admin@example.com", "Follow Keycloak");

        var running = app.Service<WincheAuthOptions>().IdentityProviders.Single(p => p.Name == "staff");
        Assert.NotNull(running.KeycloakSync);
        Assert.Equal(("winche-sync", TimeSpan.FromSeconds(30), "auth.provider.staff.keycloakSync.clientSecret"),
            (running.KeycloakSync!.ClientId, running.KeycloakSync.PollInterval, running.KeycloakSync.ClientSecretName));
        Assert.Equal("ward", running.KeycloakSync.Attributes["ward"]);
        Assert.Equal("auth.provider.staff.keycloakSync.clientSecret", KeycloakSyncSettings.SecretName("staff"));

        // Only a Keycloak realm's provider can sync, and the sync needs its client.
        var ex = await Assert.ThrowsAsync<SettingsValidationException>(() => app.Service<SettingsStore>().SaveAsync(WincheAuthSettings.Area,
            Doc(current with { Providers = [staff with { Authority = "https://login.example.com", KeycloakSync = new KeycloakSyncSettings() }] }), null, "x"));
        Assert.Contains(ex.Errors, e => e.Contains("needs an OpenID Connect provider whose address is a Keycloak realm"));
        Assert.Contains(ex.Errors, e => e.Contains("give the Keycloak sync's client id"));
    }

    [Fact]
    public async Task Email_over_smtp_set_up_in_the_console_with_an_encrypted_password()
    {
        using var smtp = new FakeSmtp();
        await using var app = await Start(await pg.NewDatabaseAsync());
        var area = app.Service<SettingsArea<WincheAuthSettings>>();
        await app.Service<SecretStore>().SetAsync(SmtpEmailSender.SecretName, "smtp-pass", "admin@example.com");
        await app.Service<SettingsStore>().SaveAsync(WincheAuthSettings.Area, Doc(area.Current with
        {
            Email = new EmailSettings
            {
                Enabled = true, AppName = "Clinic", Sender = "smtp",
                Smtp = new SmtpSettings { Host = "127.0.0.1", Port = smtp.Port, Security = "none", Username = "mailer", FromAddress = "no-reply@example.com" },
            },
        }), "admin@example.com", "Send email");

        await app.SignUpAsync("ann@example.com");   // sends the verify link (on by default)
        var (user, password, data) = Assert.Single(smtp.Received);
        Assert.Equal(("mailer", "smtp-pass"), (user, password));
        Assert.Contains("From: Clinic <no-reply@example.com>", data);
        Assert.Contains("To: ann@example.com", data);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Sign_in_links_and_password_resets_go_over_smtp_sent_after_answering_or_before(bool background)
    {
        using var smtp = new FakeSmtp();
        await using var app = await Start(await pg.NewDatabaseAsync());
        var area = app.Service<SettingsArea<WincheAuthSettings>>();
        await app.Service<SecretStore>().SetAsync(SmtpEmailSender.SecretName, "smtp-pass", "admin@example.com");
        await app.Service<SettingsStore>().SaveAsync(WincheAuthSettings.Area, Doc(area.Current with
        {
            EmailLink = new EmailLinkSettings { Enabled = true, LinkUrl = "https://app.example.com/finish" },
            Email = new EmailSettings
            {
                Enabled = true, AppName = "Clinic", Sender = "smtp", SendVerificationOnSignUp = false, SendInBackground = background,
                Smtp = new SmtpSettings { Host = "127.0.0.1", Port = smtp.Port, Security = "none", Username = "mailer", FromAddress = "no-reply@example.com" },
            },
        }), "admin@example.com", "Send email");
        Assert.Equal(background, area.Current.Email.SendInBackground);
        await app.SignUpAsync("ann@example.com");

        // Through the HTTP endpoints: a background send happens after the request's services are disposed.
        Assert.Equal(HttpStatusCode.NoContent, (await app.PostAsync("/auth/v1/sendSignInLink", new { email = "ann@example.com" })).StatusCode);
        if (!background) Assert.Single(smtp.Received);   // sent before answering
        Assert.Equal(HttpStatusCode.NoContent, (await app.PostAsync("/auth/v1/sendPasswordReset", new { email = "ann@example.com" })).StatusCode);

        for (var i = 0; i < 100 && smtp.Received.Count < 2; i++) await Task.Delay(50);
        Assert.Equal(2, smtp.Received.Count);
        Assert.All(smtp.Received, r => Assert.Equal(("mailer", "smtp-pass"), (r.User, r.Password)));
        Assert.Contains(smtp.Received, r => r.Data.Contains("mode=signIn"));
        Assert.Contains(smtp.Received, r => r.Data.Contains("mode=resetPassword"));
    }

    [Fact]
    public async Task What_only_code_can_give_is_kept_for_a_provider_of_the_same_name()
    {
        await using var app = await Start(await pg.NewDatabaseAsync(), o =>
            o.OpenIdConnect("staff", p => { p.Authority = "https://login.example.com"; p.Audiences = ["app"]; p.AllowUnsignedTokensForTesting = true; }));
        var area = app.Service<SettingsArea<WincheAuthSettings>>();
        var staff = Assert.Single(area.Current.Providers);
        await app.Service<SettingsStore>().SaveAsync(WincheAuthSettings.Area, Doc(area.Current with
        {
            Providers = [staff with { DisplayName = "Staff login", CopiedClaims = ["role"], RequireSecondStep = true, SecondStepAcrValues = [" 2 ", ""] }],
        }), null, "Rename");
        var live = Assert.Single(app.Service<WincheAuthOptions>().IdentityProviders);
        Assert.Equal(("Staff login", true, "role"), (live.DisplayName, live.AllowUnsignedTokensForTesting, live.CopiedClaims.Single()));
        Assert.Equal((true, "2"), (live.RequireSecondStep, Assert.Single(live.SecondStepAcrValues)));   // a second step, set in the console
    }
}
