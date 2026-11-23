using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.Data;
using Winche.Auth.Email;
using Winche.Auth.Logging;

namespace Winche.Auth.Users;

/// <summary>The flows that go through email: verify, reset, sign-in links, changing the address, and the templates.</summary>
internal sealed partial class WincheAuthService
{
    // ── verify email ────────────────────────────────────────────────────────────

    public async Task SendEmailVerificationAsync(string uid, CancellationToken ct)
    {
        var email = RequireEmail();
        var user = await Find(uid);
        if (user.Email is null) throw new AuthException(AuthErrorCodes.InvalidArgument, "This account has no email address.");
        if (user.EmailConfirmed) return;
        await SendCodeAsync(AuthEmailKinds.VerifyEmail, AuthEmailKinds.VerifyEmail, user, user.Email, email.VerifyLinkLifetime, null, ct);
    }

    public async Task<WincheUserInfo> SetEmailVerifiedAsync(string uid, bool verified, CancellationToken ct)
    {
        var info = await SaveUpdatedAsync(uid, user => user.EmailConfirmed = verified, ct);
        Changed("auth.verified", uid, verified ? $"{uid}'s email was marked verified." : $"{uid}'s email was marked not verified.");
        return info;
    }

    public async Task<WincheUserInfo> SetEmailAsync(string uid, string email, CancellationToken ct)
    {
        email = CheckEmail(email);
        var user = await Find(uid);
        var old = user.Email;
        if (string.Equals(old, email, StringComparison.OrdinalIgnoreCase)) return await GetUserAsync(uid, ct) ?? throw new InvalidOperationException();
        if (await users.FindByEmailAsync(email) is { } other && other.Id != user.Id) throw EmailExists();
        var info = await SaveUpdatedAsync(uid, u => { u.Email = email; u.NormalizedEmail = users.NormalizeEmail(email); u.EmailConfirmed = true; }, ct);
        await sessions.RevokeAllAsync(uid, "email changed", ct);
        Changed("auth.setEmail", uid, $"{uid}'s email was changed from {old ?? "none"} to {email}; every session ended.");
        return info;
    }

    // ── action codes (verify, change, undo) ─────────────────────────────────────

    public async Task<ActionCodeInfo> CheckActionCodeAsync(string code, CancellationToken ct)
    {
        var row = await FindCodeAsync(code, null, ct);
        return new ActionCodeInfo(Mode(row.Kind), row.Email);
    }

    public Task<ActionCodeInfo> ApplyActionCodeAsync(string code, CancellationToken ct) => InTransaction(() => ApplyActionCodeCoreAsync(code, ct), ct);

    private async Task<ActionCodeInfo> ApplyActionCodeCoreAsync(string code, CancellationToken ct)
    {
        var row = await FindCodeAsync(code, [AuthEmailKinds.VerifyEmail, AuthEmailKinds.ChangeEmail, AuthEmailKinds.RecoverEmail, AuthEmailKinds.UnlinkProvider], ct);
        var user = row.UserId is null ? null : await users.FindByIdAsync(row.UserId);
        if (user is null) throw InvalidCode();
        var now = time.GetUtcNow();
        switch (row.Kind)
        {
            case AuthEmailKinds.VerifyEmail:
                // The address must still be theirs.
                if (!string.Equals(user.Email, row.Email, StringComparison.OrdinalIgnoreCase)) throw InvalidCode();
                user.EmailConfirmed = true;
                await Save(user);
                await UseAsync(row, ct);
                Changed("auth.verifyEmail", user.Id, $"{user.Id} verified {row.Email}.");
                await Record(WincheAuthUserEvent.Updated, await InfoAsync(user), ct);
                break;

            case AuthEmailKinds.ChangeEmail:
            {
                if (await users.FindByEmailAsync(row.Email) is { } other && other.Id != user.Id) throw EmailExists();
                var old = user.Email;
                // When it changed: an undo from the old address reverses this change and what was done after it (providers
                // linked before it are the owner's or were announced to them as they were linked).
                if (old is not null) await SetTokenAsync(user, ChangedAt(old), now.ToUnixTimeMilliseconds().ToString());
                user.Email = row.Email;
                user.NormalizedEmail = users.NormalizeEmail(row.Email);
                user.EmailConfirmed = true;
                await Save(user);
                await UseAsync(row, ct);
                await sessions.RevokeAllAsync(user.Id, "email changed", ct);
                Changed("auth.changeEmail", user.Id, $"{user.Id} changed their email from {old ?? "none"} to {row.Email}; every session ended.");
                // Tell the old address, with a link that puts it back.
                if (old is not null)
                    await SendCodeAsync(AuthEmailKinds.EmailChanged, AuthEmailKinds.RecoverEmail, user, old, RequireEmail().UndoLinkLifetime,
                        new Dictionary<string, string?> { ["EMAIL"] = old, ["NEW_EMAIL"] = row.Email }, ct, limit: false);
                await Record(WincheAuthUserEvent.Updated, await InfoAsync(user), ct);
                break;
            }

            case AuthEmailKinds.UnlinkProvider:
                await UnlinkFromEmailAsync(row, user, ct);
                break;

            case AuthEmailKinds.RecoverEmail:
            {
                if (await users.FindByEmailAsync(row.Email) is { } other && other.Id != user.Id) throw EmailExists();
                var changed = user.Email;
                user.Email = row.Email;
                user.NormalizedEmail = users.NormalizeEmail(row.Email);
                user.EmailConfirmed = true;
                // Whoever changed the address may have set a password or a second step since: the owner starts over
                // from their inbox (a password reset), with nothing the other person chose.
                if (user.PasswordHash is not null)
                {
                    var removed = await users.RemovePasswordAsync(user);
                    if (!removed.Succeeded) throw Failed(removed);
                }
                // …and providers linked since the change (each one linked before it was emailed to the owner with a link
                // that removes it). Not known when it changed: all go.
                var since = long.TryParse(await users.GetAuthenticationTokenAsync(user, TokenProvider, ChangedAt(row.Email)), out var ms) ? ms : (long?)null;
                await users.RemoveAuthenticationTokenAsync(user, TokenProvider, ChangedAt(row.Email));
                foreach (var login in await users.GetLoginsAsync(user))
                {
                    var linked = long.TryParse(await users.GetAuthenticationTokenAsync(user, TokenProvider, LinkedAt(login.LoginProvider, login.ProviderKey)), out var l)
                        ? l : user.CreatedAt.ToUnixTimeMilliseconds();   // linked as the account was made (or before links were dated)
                    if (since is { } cutoff && linked < cutoff) continue;
                    await users.RemoveAuthenticationTokenAsync(user, TokenProvider, LinkedAt(login.LoginProvider, login.ProviderKey));
                    ForgetProviderPhoto(user, login.LoginProvider);
                    var unlinked = await users.RemoveLoginAsync(user, login.LoginProvider, login.ProviderKey);
                    if (!unlinked.Succeeded) throw Failed(unlinked);
                }
                await ClearMfaAsync(user);   // a set-up only begun too
                await Save(user);
                await UseAsync(row, ct);
                await sessions.RevokeAllAsync(user.Id, "email change undone", ct);
                AuthEvents.Log(_events, LogLevel.Warning, "auth.recoverEmail", user.Id, "ok",
                    $"{user.Id} undid the change of their email to {changed}: it's {row.Email} again; the password, linked providers, two-step sign-in and every session were removed.", row.Email);
                await Record(WincheAuthUserEvent.Updated, await InfoAsync(user), ct);
                break;
            }
        }
        return new ActionCodeInfo(Mode(row.Kind), row.Email);
    }

    /// <summary>When the address was changed away from <paramref name="old"/> (Unix ms).</summary>
    private static string ChangedAt(string old) => "email-changed-from:" + old.ToLowerInvariant();

    /// <summary>When a provider account was linked (Unix ms).</summary>
    internal static string LinkedAt(string provider, string key) => $"linked-at:{provider}:{key}";

    /// <summary>Which provider account an unlink code (by its id) removes: "provider\tkey".</summary>
    private static string UnlinkTarget(Guid code) => $"unlink-code:{code:N}";

    // ── provider linked: the owner is told, with a link that removes it ─────────

    /// <summary>
    /// Emails the account's address that <paramref name="provider"/> was linked, with a link that unlinks it and signs
    /// every device out. Never held back by the hourly limit, and never replacing an earlier such link.
    /// </summary>
    internal async Task SendProviderLinkedAsync(WincheUser user, string provider, string? providerName, string key, CancellationToken ct)
    {
        if (options.EmailSending is null || string.IsNullOrEmpty(user.Email)) return;
        var settings = RequireEmail();
        Guid made = default;
        await SendCodeAsync(AuthEmailKinds.ProviderLinked, AuthEmailKinds.UnlinkProvider, user, user.Email, settings.UndoLinkLifetime,
            new Dictionary<string, string?> { ["PROVIDER"] = providerName ?? provider }, ct, limit: false, background: true, made: id => made = id);
        if (made != default) await SetTokenAsync(user, UnlinkTarget(made), $"{provider}\t{key}");
    }

    private async Task UnlinkFromEmailAsync(AuthActionCode row, WincheUser user, CancellationToken ct)
    {
        var target = await users.GetAuthenticationTokenAsync(user, TokenProvider, UnlinkTarget(row.Id));
        if (target?.Split('\t', 2) is not [var provider, var key]) throw InvalidCode();
        await users.RemoveAuthenticationTokenAsync(user, TokenProvider, UnlinkTarget(row.Id));
        if ((await users.GetLoginsAsync(user)).Any(l => l.LoginProvider == provider && l.ProviderKey == key))
        {
            ForgetProviderPhoto(user, provider);
            var unlinked = await users.RemoveLoginAsync(user, provider, key);
            if (!unlinked.Succeeded) throw Failed(unlinked);
            await users.RemoveAuthenticationTokenAsync(user, TokenProvider, LinkedAt(provider, key));
        }
        await Save(user);
        await UseAsync(row, ct);
        await sessions.RevokeAllAsync(user.Id, "a linked provider removed from the email", ct);
        AuthEvents.Log(_events, LogLevel.Warning, "auth.unlinkFromEmail", user.Id, "ok",
            $"{user.Id} removed the {provider} account linked to it from the email that announced it; every session was ended.", row.Email);
        await Record(WincheAuthUserEvent.Updated, await InfoAsync(user), ct);
    }

    // ── password reset ──────────────────────────────────────────────────────────

    public async Task SendPasswordResetAsync(string email, AuthRequestInfo info, CancellationToken ct)
    {
        var settings = RequireEmail();
        RequireEmailPassword();
        // Same answer whether or not there's such an account.
        var user = string.IsNullOrWhiteSpace(email) ? null : await users.FindByEmailAsync(email.Trim());
        if (user is null || user.Disabled)
        {
            AuthEvents.Log(_events, LogLevel.Information, "auth.sendPasswordReset", Trimmed(email), "noAccount",
                $"A password reset was asked for {Trimmed(email)}, which has no account: nothing was sent.", Trimmed(email));
            return;
        }
        // Sent after answering, so how long the request takes doesn't tell whether the address has an account.
        await SendCodeAsync(AuthEmailKinds.ResetPassword, AuthEmailKinds.ResetPassword, user, user.Email!, settings.ResetLinkLifetime, null, ct, background: true);
    }

    public async Task<WincheUserInfo> ResetPasswordAsync(string code, string newPassword, CancellationToken ct)
    {
        RequireEmailPassword();
        var row = await FindCodeAsync(code, [AuthEmailKinds.ResetPassword], ct);
        CheckPassword(newPassword);
        var user = (row.UserId is null ? null : await users.FindByIdAsync(row.UserId)) ?? throw InvalidCode();
        if (!string.Equals(user.Email, row.Email, StringComparison.OrdinalIgnoreCase)) throw InvalidCode();
        if (user.Disabled) throw Disabled();
        // All of it or none: a reset that fails part-way (a code used twice) leaves the account as it was.
        return await InTransaction(async () =>
        {
        await SecureClaimedAccountAsync(user, "reset its password", ct, row.Id);
        // Read again under the lock: the address or the account may have changed since the code was checked.
        if (!string.Equals(user.Email, row.Email, StringComparison.OrdinalIgnoreCase)) throw InvalidCode();
        if (user.Disabled) throw Disabled();
        if (user.PasswordHash is not null)
        {
            var removed = await users.RemovePasswordAsync(user);
            if (!removed.Succeeded) throw Failed(removed);
        }
        var added = await users.AddPasswordAsync(user, newPassword);
        if (!added.Succeeded) throw Failed(added);
        user.EmailConfirmed = true;   // they read the inbox
        user.IsAnonymous = false;
        await Save(user);
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
        await UseAsync(row, ct);
        await sessions.RevokeAllAsync(user.Id, "password reset", ct);
        Changed("auth.resetPassword", user.Id, $"{user.Id} reset their password by email; every session ended.");
        return await InfoAsync(user);
        }, ct);
    }

    // ── links for the app to send itself ────────────────────────────────────────

    public async Task<string> CreateEmailLinkAsync(string kind, string email, CancellationToken ct)
    {
        var settings = RequireEmail();
        email = CheckEmail(email);
        var user = await users.FindByEmailAsync(email);
        WincheUser Existing() => user ?? throw new AuthException(AuthErrorCodes.UserNotFound, $"No account has the email {email}.");
        if (kind == AuthEmailKinds.ResetPassword) RequireEmailPassword();
        var link = kind switch
        {
            AuthEmailKinds.VerifyEmail => await NewLinkAsync(kind, Existing(), email, settings.VerifyLinkLifetime, ct),
            AuthEmailKinds.ResetPassword => await NewLinkAsync(kind, Existing(), email, settings.ResetLinkLifetime, ct),
            AuthEmailKinds.SignIn when options.EmailLinkSignIn is null => throw NotEnabled("Email-link sign-in"),
            AuthEmailKinds.SignIn => await NewLinkAsync(kind, user, email, settings.SignInLinkLifetime, ct),
            _ => throw new AuthException(AuthErrorCodes.InvalidArgument, $"No link of kind '{kind}': verifyEmail, resetPassword or signIn."),
        };
        Changed($"auth.emailLink.{kind}", user?.Id ?? email, $"A {kind} link for {email} was made for the app to send.");
        return link;
    }

    // ── email-link sign-in ──────────────────────────────────────────────────────

    public async Task SendSignInLinkAsync(string email, AuthRequestInfo info, CancellationToken ct)
    {
        var settings = RequireEmail();
        if (options.EmailLinkSignIn is null) throw NotEnabled("Email-link sign-in");
        email = CheckEmail(email);
        var user = await users.FindByEmailAsync(email);
        if (user is { Disabled: true }) return;   // same answer as anyone else
        await SendCodeAsync(AuthEmailKinds.SignIn, AuthEmailKinds.SignIn, user, email, settings.SignInLinkLifetime, null, ct, background: true);
    }

    public Task<AuthTokens> SignInWithLinkAsync(string code, AuthRequestInfo info, CancellationToken ct) =>
        Logged("auth.signInLink", null, () => SignInWithLinkCoreAsync(code, info, ct), t => $"{t.User.Uid} signed in with an email link.", e => $"An email-link sign-in failed: {e.Message}");

    private async Task<AuthTokens> SignInWithLinkCoreAsync(string code, AuthRequestInfo info, CancellationToken ct)
    {
        if (options.EmailLinkSignIn is null) throw NotEnabled("Email-link sign-in");
        var row = await FindCodeAsync(code, [AuthEmailKinds.SignIn], ct);
        var user = await users.FindByEmailAsync(row.Email);
        if (user is null)
        {
            // The first sign-in makes the account.
            await BeforeCreateAsync(new AuthAttempt(row.Email, "emailLink", info.IpAddress), ct);
            user = NewUser();
            user.Email = row.Email;
            user.EmailConfirmed = true;
            await CreateAsync(user, null, ct: ct);
        }
        if (user.Disabled) throw Disabled();
        await BeforeSignInAsync(user, new AuthAttempt(user.Email, "emailLink", info.IpAddress), ct);
        // The account secured, verified and the code used together, or not at all.
        await InTransaction(async () =>
        {
            await SecureClaimedAccountAsync(user, "signed in with an email link", ct, row.Id);
            if (user.Disabled) throw Disabled();   // read again under the lock
            user.EmailConfirmed = true;
            await UseAsync(row, ct);
        }, ct);
        return await CompleteSignInAsync(user, "emailLink", info, ct);
    }

    // ── changing the email ──────────────────────────────────────────────────────

    public async Task ChangeEmailAsync(string uid, string newEmail, CancellationToken ct)
    {
        var settings = RequireEmail();
        var user = await Find(uid);
        if (user.Disabled) throw Disabled();
        newEmail = CheckEmail(newEmail);
        if (string.Equals(user.Email, newEmail, StringComparison.OrdinalIgnoreCase))
            throw new AuthException(AuthErrorCodes.InvalidArgument, "That's already the account's email.");
        if (await users.FindByEmailAsync(newEmail) is not null) throw EmailExists();
        // The change happens when the new address confirms it.
        await SendCodeAsync(AuthEmailKinds.VerifyEmail, AuthEmailKinds.ChangeEmail, user, newEmail, settings.VerifyLinkLifetime,
            new Dictionary<string, string?> { ["EMAIL"] = newEmail }, ct);
    }

    // ── templates ───────────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<EmailTemplateInfo>> GetEmailTemplatesAsync(CancellationToken ct)
    {
        var saved = await db.EmailTemplates.AsNoTracking().ToDictionaryAsync(t => t.Kind, ct);
        var settings = options.EmailSending ?? new AuthEmailOptions();
        return [.. AuthEmailKinds.All.Select(kind =>
        {
            var (name, d) = EmailTemplates.Defaults[kind];
            var s = saved.GetValueOrDefault(kind);
            var lifetime = kind switch
            {
                AuthEmailKinds.VerifyEmail => settings.VerifyLinkLifetime,
                AuthEmailKinds.ResetPassword => settings.ResetLinkLifetime,
                AuthEmailKinds.SignIn => settings.SignInLinkLifetime,
                _ => settings.UndoLinkLifetime,
            };
            return new EmailTemplateInfo(kind, name, s?.Subject ?? d.Subject, s?.Body ?? d.Body, s is not null, d.Subject, d.Body,
                Lifetime(lifetime), s?.UpdatedAt, s?.UpdatedBy);
        })];
    }

    public async Task SaveEmailTemplateAsync(string kind, string subject, string body, string? by, CancellationToken ct)
    {
        if (!AuthEmailKinds.All.Contains(kind)) throw new AuthException(AuthErrorCodes.InvalidArgument, $"There's no '{kind}' email.");
        subject = (subject ?? "").Trim();
        body = (body ?? "").Replace("\r\n", "\n").Trim();
        if (subject.Length is 0 or > 200) throw new AuthException(AuthErrorCodes.InvalidArgument, "The subject must be 1–200 characters.");
        if (body.Length is 0 or > 5000) throw new AuthException(AuthErrorCodes.InvalidArgument, "The message must be 1–5,000 characters.");
        if (!body.Contains("%LINK%", StringComparison.Ordinal))
            throw new AuthException(AuthErrorCodes.InvalidArgument, "The message must contain %LINK%: it's what the reader clicks.");
        var row = await db.EmailTemplates.FindAsync([kind], ct);
        if (row is null) db.EmailTemplates.Add(row = new AuthEmailTemplate { Kind = kind });
        row.Subject = subject;
        row.Body = body;
        row.UpdatedAt = time.GetUtcNow();
        row.UpdatedBy = by;
        await db.SaveChangesAsync(ct);
    }

    public async Task ResetEmailTemplateAsync(string kind, CancellationToken ct) =>
        await db.EmailTemplates.Where(t => t.Kind == kind).ExecuteDeleteAsync(ct);

    public async Task SendTestEmailAsync(string kind, string to, CancellationToken ct)
    {
        var settings = RequireEmail();
        if (!AuthEmailKinds.All.Contains(kind)) throw new AuthException(AuthErrorCodes.InvalidArgument, $"There's no '{kind}' email.");
        var template = await TemplateAsync(kind, ct);
        var values = new Dictionary<string, string?>
        {
            ["APP_NAME"] = settings.AppName, ["EMAIL"] = to, ["NEW_EMAIL"] = "new.address@example.com", ["DISPLAY_NAME"] = "", ["PROVIDER"] = "Google",
        };
        var message = EmailTemplates.Render(kind, template, to, values, $"{ActionUrl(settings)}?mode=test&code=this-is-a-test");
        await Sender(settings).SendAsync(message with { Subject = "[Test] " + message.Subject }, ct);
    }

    // ── helpers ─────────────────────────────────────────────────────────────────

    /// <summary>A new one-time code of <paramref name="codeKind"/> for <paramref name="to"/>, replacing earlier ones of its kind, as its link.</summary>
    private async Task<string> NewLinkAsync(string codeKind, WincheUser? user, string to, TimeSpan lifetime, CancellationToken ct, Action<Guid>? made = null)
    {
        var settings = RequireEmail();
        var now = time.GetUtcNow();
        var address = to.ToLowerInvariant();
        if (codeKind != AuthEmailKinds.UnlinkProvider)   // each linked provider keeps its own
            await db.ActionCodes.Where(c => c.Kind == codeKind && c.Email.ToLower() == address && c.UsedAt == null)
                .ExecuteUpdateAsync(u => u.SetProperty(c => c.UsedAt, now), ct);

        var code = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var id = Guid.NewGuid();
        db.ActionCodes.Add(new AuthActionCode
        {
            Id = id, Kind = codeKind, UserId = user?.Id, Email = to, CodeHash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(code)),
            CreatedAt = now, ExpiresAt = now + lifetime,
        });
        await db.SaveChangesAsync(ct);
        made?.Invoke(id);

        return codeKind == AuthEmailKinds.SignIn
            ? $"{options.EmailLinkSignIn!.LinkUrl}{(options.EmailLinkSignIn.LinkUrl.Contains('?') ? '&' : '?')}mode=signIn&code={code}"
            : settings.ActionUrl is null
            // Winche's own page: the code goes after '#', so it never reaches a server log; the page reads it from there.
            ? $"{ActionUrl(settings)}#mode={Mode(codeKind)}&code={code}"
            : $"{ActionUrl(settings)}?mode={Mode(codeKind)}&code={code}";
    }

    /// <summary>Makes a one-time code, and emails its link with the <paramref name="template"/> message.</summary>
    private async Task SendCodeAsync(string template, string codeKind, WincheUser? user, string to, TimeSpan lifetime,
        Dictionary<string, string?>? values, CancellationToken ct, bool limit = true, bool background = false, Action<Guid>? made = null)
    {
        var settings = RequireEmail();
        var now = time.GetUtcNow();
        // Addresses are compared without case: Victim@ and victim@ are one inbox, with one hourly allowance.
        var address = to.ToLowerInvariant();
        if (limit && await db.ActionCodes.CountAsync(c => c.Email.ToLower() == address && c.CreatedAt > now.AddHours(-1), ct) >= settings.MaxPerAddressPerHour)
        {
            AuthEvents.Log(_events, LogLevel.Warning, $"auth.send.{template}", user?.Id ?? to, "tooMany",
                $"Not sending another {template} email to {to}: {settings.MaxPerAddressPerHour} in the last hour.", to);
            return;
        }
        var link = await NewLinkAsync(codeKind, user, to, lifetime, ct, made);
        var all = new Dictionary<string, string?>
        {
            ["APP_NAME"] = settings.AppName, ["EMAIL"] = user?.Email ?? to, ["NEW_EMAIL"] = null, ["DISPLAY_NAME"] = user?.DisplayName ?? "",
        };
        foreach (var (k, v) in values ?? []) all[k] = v;
        var message = EmailTemplates.Render(template, await TemplateAsync(template, ct), to, all, link);
        var sender = Sender(settings);
        if (!background || !settings.SendInBackground)
        {
            await sender.SendAsync(message, ct);
            AuthEvents.Log(_events, LogLevel.Information, $"auth.send.{template}", user?.Id ?? to, "ok", $"Sent a {template} email to {to}.", to);
            return;
        }
        // Sent after the answer: by then this request's services are gone, so whatever the sender needs from them is read now.
        if (sender is SmtpEmailSender smtp) sender = await smtp.ReadyAsync(ct);
        var log = _events;
        _ = Task.Run(async () =>
        {
            try
            {
                await sender.SendAsync(message, CancellationToken.None);
                AuthEvents.Log(log, LogLevel.Information, $"auth.send.{template}", user?.Id ?? to, "ok", $"Sent a {template} email to {to}.", to);
            }
            catch (Exception ex)
            {
                AuthEvents.Log(log, LogLevel.Error, $"auth.send.{template}", user?.Id ?? to, "failed", $"Couldn't send a {template} email to {to}: {ex.Message}", to);
            }
        });
    }

    private async Task<AuthActionCode> FindCodeAsync(string code, string[]? kinds, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(code) || code.Length > 100) throw InvalidCode();
        var hash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(code.Trim()));
        var row = await db.ActionCodes.FirstOrDefaultAsync(c => c.CodeHash == hash, ct);
        if (row is null || row.UsedAt is not null || row.ExpiresAt <= time.GetUtcNow() || (kinds is not null && !kinds.Contains(row.Kind)))
            throw InvalidCode();
        return row;
    }

    /// <summary>Marks the code used, unless someone used it meanwhile (then it's refused).</summary>
    private async Task UseAsync(AuthActionCode row, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var used = await db.ActionCodes.Where(c => c.Id == row.Id && c.UsedAt == null).ExecuteUpdateAsync(u => u.SetProperty(c => c.UsedAt, now), ct);
        if (used == 0) throw InvalidCode();
    }

    private async Task<EmailTemplate> TemplateAsync(string kind, CancellationToken ct) =>
        await db.EmailTemplates.AsNoTracking().FirstOrDefaultAsync(t => t.Kind == kind, ct) is { } saved
            ? new EmailTemplate(saved.Subject, saved.Body)
            : EmailTemplates.Defaults[kind].Template;

    private AuthEmailOptions RequireEmail() =>
        options.EmailSending ?? throw new AuthException(AuthErrorCodes.EmailNotSetUp, "Email isn't set up for this app.");

    private IAuthEmailSender Sender(AuthEmailOptions settings) =>
        settings.LogLinksOnly
            ? ActivatorUtilities.CreateInstance<LogLinksEmailSender>(services)
            : settings.Smtp is not null
            ? new SmtpEmailSender(settings, services)
            : services.GetService<IAuthEmailSender>()
              ?? throw new AuthException(AuthErrorCodes.EmailNotSetUp, "Email isn't set up for this app: register an IAuthEmailSender.");

    private string ActionUrl(AuthEmailOptions settings) => settings.ActionUrl ?? $"{options.Issuer.TrimEnd('/')}/auth/v1/action";

    /// <summary>The link's mode: changeEmail confirms a new address, so it's verifyEmail to the reader's page.</summary>
    private static string Mode(string kind) => kind == AuthEmailKinds.ChangeEmail ? "verifyAndChangeEmail" : kind;

    private static string Lifetime(TimeSpan t) =>
        t.TotalDays >= 1 && t.TotalDays % 1 == 0 ? $"{t.TotalDays:0} day{(t.TotalDays == 1 ? "" : "s")}"
        : t.TotalHours >= 1 && t.TotalHours % 1 == 0 ? $"{t.TotalHours:0} hour{(t.TotalHours == 1 ? "" : "s")}"
        : $"{t.TotalMinutes:0} minutes";

    private static AuthException InvalidCode() =>
        new(AuthErrorCodes.InvalidCode, "This link has expired or was already used. Ask for a new one.");
}
