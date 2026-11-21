using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace Winche.Auth.Email;

/// <summary>An SMTP server to send Winche Auth's messages through.</summary>
public sealed class SmtpOptions
{
    public string Host { get; set; } = "";
    /// <summary>587 (STARTTLS) by default; 465 for TLS from the start.</summary>
    public int Port { get; set; } = 587;
    /// <summary>startTls (default), tls, or none (local test servers only).</summary>
    public string Security { get; set; } = "startTls";
    /// <summary>The user to sign in as; none for servers that don't ask.</summary>
    public string? Username { get; set; }
    /// <summary>
    /// The password. When the console sets up SMTP it's kept encrypted in Winche.Core's secret store instead
    /// (<see cref="SmtpEmailSender.SecretName"/>), and this stays empty.
    /// </summary>
    public string? Password { get; set; }
    /// <summary>The address messages come from, e.g. no-reply@example.com.</summary>
    public string FromAddress { get; set; } = "";
    /// <summary>The name shown beside it; the app's name when empty.</summary>
    public string? FromName { get; set; }

    internal IReadOnlyList<string> Problems()
    {
        var problems = new List<string>();
        if (string.IsNullOrWhiteSpace(Host)) problems.Add("Give the SMTP server's address.");
        if (Port is < 1 or > 65535) problems.Add("The SMTP port must be between 1 and 65535.");
        if (Security is not ("startTls" or "tls" or "none")) problems.Add("SMTP security is startTls, tls or none.");
        if (!MailboxAddress.TryParse(FromAddress, out _) || !FromAddress.Contains('@')) problems.Add("Give the address emails come from, like no-reply@example.com.");
        return problems;
    }
}

/// <summary>Sends through <see cref="SmtpOptions"/>; the password comes from the options or the secret store.</summary>
public sealed class SmtpEmailSender : IAuthEmailSender
{
    /// <summary>Where the console keeps the SMTP password (Winche.Core's secret store).</summary>
    public const string SecretName = "auth.smtp.password";

    private readonly AuthEmailOptions _email;
    private readonly IServiceProvider? _services;
    private readonly string? _password;

    /// <summary>Sends through <paramref name="email"/>'s SMTP server; the password from it or Winche.Core's secret store.</summary>
    public SmtpEmailSender(AuthEmailOptions email, IServiceProvider services)
    {
        _email = email;
        _services = services;
    }

    private SmtpEmailSender(AuthEmailOptions email, string? password)
    {
        _email = email;
        _password = password;
    }

    public async Task SendAsync(AuthEmailMessage message, CancellationToken ct) =>
        await SendAsync(_email.Smtp!, _email.AppName, _services is null ? _password : await PasswordAsync(ct), message, ct);

    /// <summary>
    /// A sender with the password already read, needing nothing from <c>services</c>: for sending after the request
    /// that asked has been answered (its services are gone by then).
    /// </summary>
    public async Task<SmtpEmailSender> ReadyAsync(CancellationToken ct) =>
        _services is null ? this : new SmtpEmailSender(_email, await PasswordAsync(ct));

    private async Task<string?> PasswordAsync(CancellationToken ct)
    {
        var password = _email.Smtp!.Password;
        if (string.IsNullOrEmpty(password) && _services?.GetService(typeof(Winche.Secrets.SecretStore)) is Winche.Secrets.SecretStore secrets && secrets.Available)
            password = await secrets.GetAsync(SecretName, ct);
        return password;
    }

    /// <summary>Sends a short test message through <paramref name="smtp"/> (the console's Send test email).</summary>
    public static Task SendTestAsync(SmtpOptions smtp, string appName, string? password, string to, CancellationToken ct)
    {
        if (smtp.Problems() is { Count: > 0 } problems) throw new AuthException(AuthErrorCodes.InvalidArgument, string.Join(" ", problems));
        const string text = "This is a test from Winche Auth: email from your app's sign-in will arrive like this.";
        return SendAsync(smtp, appName, password, new AuthEmailMessage(to, "test", $"{appName}: test email", text, $"<p>{text}</p>", null), ct);
    }

    internal static async Task SendAsync(SmtpOptions smtp, string appName, string? password, AuthEmailMessage message, CancellationToken ct)
    {
        var mime = new MimeMessage();
        mime.From.Add(new MailboxAddress(string.IsNullOrWhiteSpace(smtp.FromName) ? appName : smtp.FromName, smtp.FromAddress));
        mime.To.Add(MailboxAddress.Parse(message.To));
        mime.Subject = message.Subject;
        mime.Body = new BodyBuilder { TextBody = message.Text, HtmlBody = message.Html }.ToMessageBody();

        using var client = new SmtpClient { Timeout = 20_000 };
        var security = smtp.Security switch
        {
            "tls" => SecureSocketOptions.SslOnConnect,
            "none" => SecureSocketOptions.None,
            _ => SecureSocketOptions.StartTls,
        };
        try
        {
            await client.ConnectAsync(smtp.Host, smtp.Port, security, ct);
            if (!string.IsNullOrEmpty(smtp.Username)) await client.AuthenticateAsync(smtp.Username, password ?? "", ct);
            await client.SendAsync(mime, ct);
            await client.DisconnectAsync(true, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new AuthException(AuthErrorCodes.EmailNotSetUp, $"The SMTP server {smtp.Host}:{smtp.Port} didn't take the message: {ex.Message}");
        }
    }
}
