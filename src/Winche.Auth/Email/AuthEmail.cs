using Microsoft.Extensions.Logging;

namespace Winche.Auth.Email;

/// <summary>What Winche Auth emails: verify-email, reset-password and sign-in links, and email-changed notices.</summary>
public static class AuthEmailKinds
{
    public const string VerifyEmail = "verifyEmail";
    public const string ResetPassword = "resetPassword";
    public const string SignIn = "signIn";
    public const string EmailChanged = "emailChanged";
    /// <summary>The code in a confirm-new-email message (sent with the verifyEmail template to the new address).</summary>
    internal const string ChangeEmail = "changeEmail";
    /// <summary>The code in an email-changed notice: puts the old address back.</summary>
    internal const string RecoverEmail = "recoverEmail";

    public static readonly IReadOnlyList<string> All = [VerifyEmail, ResetPassword, SignIn, EmailChanged];
}

/// <summary>A message to send: plain text and HTML, and the link it carries.</summary>
public sealed record AuthEmailMessage(string To, string Kind, string Subject, string Text, string Html, string? Link);

/// <summary>
/// Sends Winche Auth's emails. Register one (<c>services.AddSingleton&lt;IAuthEmailSender, MySender&gt;()</c>) over your
/// mail service: SES, SendGrid, SMTP with MailKit, …
/// </summary>
public interface IAuthEmailSender
{
    Task SendAsync(AuthEmailMessage message, CancellationToken ct);
}

/// <summary>Sends nothing: writes each message and its link to the log (<c>e.LogLinks()</c>, for local development).</summary>
internal sealed class LogLinksEmailSender(ILogger<LogLinksEmailSender> logger) : IAuthEmailSender
{
    public Task SendAsync(AuthEmailMessage message, CancellationToken ct)
    {
        logger.LogWarning("Email to {To} ({Kind}): \"{Subject}\" {Link}", message.To, message.Kind, message.Subject, message.Link);
        return Task.CompletedTask;
    }
}

/// <summary>How Winche Auth sends email (<c>o.Email(e =&gt; …)</c>).</summary>
public sealed class AuthEmailOptions
{
    /// <summary>The app's name, for %APP_NAME% in the messages ("Reset your Clinic password"). Required.</summary>
    public string AppName { get; set; } = "";

    /// <summary>
    /// Where verify, reset and undo links go: a page of yours that reads <c>mode</c> and <c>code</c> and calls the API, or
    /// by default Winche Auth's own page at <c>{Issuer}/auth/v1/action</c>.
    /// </summary>
    public string? ActionUrl { get; set; }

    public TimeSpan VerifyLinkLifetime { get; set; } = TimeSpan.FromHours(24);
    public TimeSpan ResetLinkLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan SignInLinkLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan UndoLinkLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>At most this many messages to one address an hour (default 5); more are dropped quietly and logged.</summary>
    public int MaxPerAddressPerHour { get; set; } = 5;

    /// <summary>
    /// Password-reset and sign-in-link emails go out after the request is answered (default on), so how long it takes
    /// doesn't tell whether the address has an account; a failure to send is logged. Off: sent before answering.
    /// </summary>
    public bool SendInBackground { get; set; } = true;

    /// <summary>Send a verify-email link when someone signs up with a password (default true).</summary>
    public bool SendVerificationOnSignUp { get; set; } = true;

    /// <summary>Whether messages are only written to the log (<see cref="LogLinks"/>).</summary>
    public bool LogLinksOnly { get; internal set; }

    /// <summary>Send through this SMTP server (<see cref="UseSmtp"/>) instead of the app's <see cref="IAuthEmailSender"/>.</summary>
    public SmtpOptions? Smtp { get; internal set; }

    /// <summary>Sends the messages through an SMTP server (any provider: SES, Postmark, SendGrid, Microsoft 365, …).</summary>
    public AuthEmailOptions UseSmtp(Action<SmtpOptions> configure)
    {
        var o = new SmtpOptions();
        configure(o);
        Smtp = o;
        return this;
    }

    /// <summary>Send nothing: write each message's link to the log instead. For local development only.</summary>
    public AuthEmailOptions LogLinks()
    {
        LogLinksOnly = true;
        return this;
    }
}

/// <summary>Email-link sign-in (<c>o.EmailLink(l =&gt; …)</c>).</summary>
public sealed class EmailLinkOptions
{
    /// <summary>
    /// The app's page or deep link that finishes the sign-in: it gets <c>?mode=signIn&amp;code=…</c> and calls
    /// <c>POST /auth/v1/signIn/link</c> with the code. Required: the tokens must reach the app, not a browser page.
    /// </summary>
    public string LinkUrl { get; set; } = "";
}
