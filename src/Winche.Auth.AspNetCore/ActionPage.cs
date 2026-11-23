using System.Net;
using Microsoft.AspNetCore.Http;
using Winche.Auth.Email;

namespace Winche.Auth.AspNetCore;

/// <summary>
/// Winche Auth's own page for emailed links (<c>/auth/v1/action</c>): verify an email, confirm a new one, undo a change,
/// set a new password. Opening the link only shows a button: mail scanners that open links don't use them up.
/// </summary>
internal static class ActionPage
{
    public static async Task<IResult> GetAsync(HttpContext http, IWincheAuth auth, WincheAuthOptions options)
    {
        var mode = http.Request.Query["mode"].ToString();
        var code = http.Request.Query["code"].ToString();
        // Links carry the code after '#', which browsers don't send: it never reaches a server log. This page reads it
        // and posts it, to show the form (nothing is used up until the reader presses the button).
        if (mode.Length == 0 && code.Length == 0) return Opener(options);
        if (mode == "test") return Page(options, "This is a test", "<p>The link in a test email works. Nothing else happens.</p>");
        if (mode == AuthEmailKinds.SignIn)
            return Page(options, "Open this link in the app", "<p>Sign-in links finish in the app: open the email on the device where you asked to sign in.</p>");
        ActionCodeInfo info;
        try { info = await auth.CheckActionCodeAsync(code, http.RequestAborted); }
        catch (AuthException ex) { return Page(options, "This link doesn't work", $"<p>{E(ex.Message)}</p>"); }
        return Form(options, info, code, null);
    }

    public static async Task<IResult> PostAsync(HttpContext http, IWincheAuth auth, WincheAuthOptions options)
    {
        var form = await http.Request.ReadFormAsync(http.RequestAborted);
        var code = form["code"].ToString();
        if (form["mode"].ToString() == "test") return Page(options, "This is a test", "<p>The link in a test email works. Nothing else happens.</p>");
        if (form["mode"].ToString() == AuthEmailKinds.SignIn)
            return Page(options, "Open this link in the app", "<p>Sign-in links finish in the app: open the email on the device where you asked to sign in.</p>");
        ActionCodeInfo info;
        try { info = await auth.CheckActionCodeAsync(code, http.RequestAborted); }
        catch (AuthException ex) { return Page(options, "This link doesn't work", $"<p>{E(ex.Message)}</p>"); }
        if (form["open"].ToString() == "1") return Form(options, info, code, null);   // just opened: show what it will do
        try
        {
            switch (info.Mode)
            {
                case AuthEmailKinds.ResetPassword:
                    await auth.ResetPasswordAsync(code, form["password"].ToString(), http.RequestAborted);
                    return Page(options, "Your password is changed", "<p>Sign in with your new password. Every device that was signed in has been signed out.</p>");
                case "verifyAndChangeEmail":
                    await auth.ApplyActionCodeAsync(code, http.RequestAborted);
                    return Page(options, "Your email is changed", $"<p>Your account's email is now <b>{E(info.Email)}</b>.</p>");
                case "unlinkProvider":
                    await auth.ApplyActionCodeAsync(code, http.RequestAborted);
                    return Page(options, "It's removed", "<p>That sign-in method no longer signs in to your account, and every device has been signed out. If you didn't add it, change your password too.</p>");
                case "recoverEmail":
                    await auth.ApplyActionCodeAsync(code, http.RequestAborted);
                    return Page(options, "Your email is back", $"<p>Your account's email is <b>{E(info.Email)}</b> again, and every device has been signed out. If someone else changed it, change your password too.</p>");
                default:
                    await auth.ApplyActionCodeAsync(code, http.RequestAborted);
                    return Page(options, "Your email is verified", $"<p><b>{E(info.Email)}</b> is verified. You can go back to {E(AppName(options))}.</p>");
            }
        }
        catch (AuthException ex)
        {
            return Form(options, info, code, ex.Message);
        }
    }

    private static IResult Form(WincheAuthOptions options, ActionCodeInfo info, string code, string? error)
    {
        var app = E(AppName(options));
        var err = error is null ? "" : $"<p class=\"error\" role=\"alert\">{E(error)}</p>";
        var hidden = $"<input type=\"hidden\" name=\"code\" value=\"{E(code)}\">";
        var (title, body) = info.Mode switch
        {
            AuthEmailKinds.ResetPassword => ("Choose a new password",
                $"<p>For <b>{E(info.Email)}</b> on {app}.</p>{err}<form method=\"post\">{hidden}" +
                $"<label for=\"password\">New password</label><input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"new-password\" required minlength=\"{options.EmailPasswordSignIn?.MinLength ?? 10}\">" +
                $"<p class=\"hint\">At least {options.EmailPasswordSignIn?.MinLength ?? 10} characters.</p><button type=\"submit\">Save password</button></form>"),
            "verifyAndChangeEmail" => ("Change your email",
                $"<p>Make <b>{E(info.Email)}</b> your email for {app}?</p>{err}<form method=\"post\">{hidden}<button type=\"submit\">Change my email</button></form>"),
            "unlinkProvider" => ("Remove the sign-in method",
                $"<p>Remove the sign-in method just added to your {app} account (<b>{E(info.Email)}</b>)? Every device will be signed out.</p>{err}<form method=\"post\">{hidden}<button type=\"submit\">Remove it</button></form>"),
            "recoverEmail" => ("Undo the email change",
                $"<p>Put <b>{E(info.Email)}</b> back as your email for {app}? Every device will be signed out.</p>{err}<form method=\"post\">{hidden}<button type=\"submit\">Undo the change</button></form>"),
            _ => ("Verify your email",
                $"<p>Confirm that <b>{E(info.Email)}</b> is your email for {app}.</p>{err}<form method=\"post\">{hidden}<button type=\"submit\">Verify my email</button></form>"),
        };
        return Page(options, title, body);
    }

    /// <summary>The page a link first opens: posts the code from after '#' to show the form, or says the link is incomplete.</summary>
    private static IResult Opener(WincheAuthOptions options)
    {
        var nonce = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        const string script = """
            var p = new URLSearchParams(location.hash.slice(1));
            if (p.get("code") || p.get("mode")) {
              var f = document.getElementById("open");
              f.elements.code.value = p.get("code") || "";
              f.elements.mode.value = p.get("mode") || "";
              history.replaceState(null, "", location.pathname);
              f.submit();
            } else {
              document.getElementById("missing").hidden = false;
            }
            """;
        var body = "<form id=\"open\" method=\"post\"><input type=\"hidden\" name=\"open\" value=\"1\"><input type=\"hidden\" name=\"code\"><input type=\"hidden\" name=\"mode\"></form>" +
            "<p id=\"missing\" hidden>This link is incomplete: open it straight from the email.</p>" +
            "<noscript><p>Turn on JavaScript to use this link.</p></noscript>" +
            $"<script nonce=\"{nonce}\">{script}</script>";
        return Page(options, "Opening your link…", body, nonce);
    }

    private static string AppName(WincheAuthOptions options) => options.EmailSending?.AppName ?? "the app";

    private static string E(string s) => WebUtility.HtmlEncode(s);

    private static IResult Page(WincheAuthOptions options, string title, string body, string? nonce = null) => new HtmlResult(nonce, $$"""
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="robots" content="noindex">
        <title>{{E(title)}} · {{E(AppName(options))}}</title>
        <style>
        :root{color-scheme:light dark;--bg:#F6F7F9;--card:#FFFFFF;--text:#111827;--muted:#4B5563;--line:#D1D5DB;--accent:#1D4ED8;--err:#B91C1C}
        @media (prefers-color-scheme:dark){:root{--bg:#0B0F17;--card:#151B26;--text:#F3F4F6;--muted:#9CA3AF;--line:#374151;--accent:#60A5FA;--err:#F87171} }
        body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px;box-sizing:border-box}
        main{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;max-width:420px;width:100%;box-sizing:border-box}
        h1{font-size:22px;margin:0 0 12px}
        p{margin:0 0 14px}
        .hint{font-size:13px;color:var(--muted);margin-top:6px}
        .error{color:var(--err)}
        label{display:block;font-size:14px;font-weight:600;margin-bottom:6px}
        input[type=password]{width:100%;box-sizing:border-box;height:44px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--text);font-size:16px}
        button{height:44px;padding:0 18px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-size:15px;font-weight:600;cursor:pointer}
        button:focus-visible,input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
        </style>
        </head>
        <body><main><h1>{{E(title)}}</h1>{{body}}</main></body>
        </html>
        """);

    private sealed class HtmlResult(string? nonce, string html) : IResult
    {
        public Task ExecuteAsync(HttpContext http)
        {
            var h = http.Response.Headers;
            h.ContentType = "text/html; charset=utf-8";
            h.CacheControl = "no-store";
            h["Referrer-Policy"] = "no-referrer";   // the code may be in the address
            h["X-Frame-Options"] = "DENY";
            h["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
                + (nonce is null ? "" : $"; script-src 'nonce-{nonce}'");
            return http.Response.WriteAsync(html);
        }
    }
}
