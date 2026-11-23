using System.Net;
using System.Text;

namespace Winche.Auth.Email;

/// <summary>A message's text with placeholders: %APP_NAME%, %EMAIL%, %NEW_EMAIL%, %PROVIDER%, %DISPLAY_NAME%, %LINK%.</summary>
public sealed record EmailTemplate(string Subject, string Body);

/// <summary>A template as the console shows it: the one in use, and the default it may override.</summary>
public sealed record EmailTemplateInfo(string Kind, string Name, string Subject, string Body, bool IsCustom, string DefaultSubject,
    string DefaultBody, string LinkLifetime, DateTimeOffset? UpdatedAt, string? UpdatedBy);

internal static class EmailTemplates
{
    public static readonly IReadOnlyDictionary<string, (string Name, EmailTemplate Template)> Defaults = new Dictionary<string, (string, EmailTemplate)>
    {
        [AuthEmailKinds.VerifyEmail] = ("Verify email", new("Verify your email for %APP_NAME%",
            "Hello %DISPLAY_NAME%,\n\nConfirm that %EMAIL% is your email address for %APP_NAME%:\n\n%LINK%\n\nIf you didn't ask for this, ignore this email.")),
        [AuthEmailKinds.ResetPassword] = ("Reset password", new("Reset your %APP_NAME% password",
            "Hello %DISPLAY_NAME%,\n\nSomeone asked to reset the password for %EMAIL%. To choose a new one:\n\n%LINK%\n\nIf it wasn't you, ignore this email: your password stays the same.")),
        [AuthEmailKinds.SignIn] = ("Sign-in link", new("Sign in to %APP_NAME%",
            "Hello,\n\nUse this link to sign in to %APP_NAME% as %EMAIL%:\n\n%LINK%\n\nThe link works once. If you didn't ask for it, ignore this email.")),
        [AuthEmailKinds.EmailChanged] = ("Email changed", new("Your %APP_NAME% email was changed",
            "Hello %DISPLAY_NAME%,\n\nThe email for your %APP_NAME% account was changed from %EMAIL% to %NEW_EMAIL%. If you didn't do this, undo it:\n\n%LINK%")),
        [AuthEmailKinds.ProviderLinked] = ("Sign-in method added", new("A sign-in method was added to your %APP_NAME% account",
            "Hello %DISPLAY_NAME%,\n\nA %PROVIDER% account can now sign in to your %APP_NAME% account (%EMAIL%). If you didn't do this, remove it (every device will be signed out):\n\n%LINK%")),
    };

    public static readonly IReadOnlyDictionary<string, string> ButtonText = new Dictionary<string, string>
    {
        [AuthEmailKinds.VerifyEmail] = "Verify email",
        [AuthEmailKinds.ResetPassword] = "Choose a new password",
        [AuthEmailKinds.SignIn] = "Sign in",
        [AuthEmailKinds.EmailChanged] = "Undo this change",
        [AuthEmailKinds.ProviderLinked] = "Remove it",
    };

    public static AuthEmailMessage Render(string kind, EmailTemplate template, string to, IReadOnlyDictionary<string, string?> values, string? link)
    {
        string Fill(string s, bool html)
        {
            var sb = new StringBuilder(s);
            foreach (var (k, v) in values)
                sb.Replace($"%{k}%", html ? WebUtility.HtmlEncode(v ?? "") : v ?? "");
            return sb.ToString();
        }

        var subject = Fill(template.Subject, false).Replace('\n', ' ').Trim();
        var text = Fill(template.Body, false).Replace("%LINK%", link ?? "");
        // Hello  , → Hello, when there's no display name.
        text = text.Replace(" ,", ",");

        var html = new StringBuilder("<div style=\"font-family:system-ui,-apple-system,Segoe UI,sans-serif;font-size:15px;line-height:1.6;color:#111827\">");
        foreach (var paragraph in Fill(template.Body, true).Replace(" ,", ",").Split("\n\n"))
        {
            if (paragraph.Trim() == "%LINK%")
            {
                if (link is null) continue;
                var href = WebUtility.HtmlEncode(link);
                html.Append($"<p><a href=\"{href}\" style=\"display:inline-block;background:#1D4ED8;color:#ffffff;text-decoration:none;font-weight:600;padding:10px 18px;border-radius:8px\">{WebUtility.HtmlEncode(ButtonText.GetValueOrDefault(kind, "Open"))}</a></p>");
                html.Append($"<p style=\"font-size:12px;color:#4B5563\">Or open this address: {href}</p>");
            }
            else
            {
                var p = paragraph.Replace("%LINK%", link is null ? "" : $"<a href=\"{WebUtility.HtmlEncode(link)}\">{WebUtility.HtmlEncode(link)}</a>");
                html.Append("<p>").Append(p.Replace("\n", "<br>")).Append("</p>");
            }
        }
        html.Append("</div>");
        return new AuthEmailMessage(to, kind, subject, text, html.ToString(), link);
    }
}
