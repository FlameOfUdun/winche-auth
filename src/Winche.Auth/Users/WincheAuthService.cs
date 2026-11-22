using Microsoft.Extensions.DependencyInjection;
using System.Net.Mail;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using Npgsql;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.Data;
using Winche.Auth.Logging;
using Winche.Auth.Sessions;
using Winche.Auth.Tokens;

namespace Winche.Auth.Users;

internal sealed partial class WincheAuthService(
    UserManager<WincheUser> users,
    WincheAuthDbContext db,
    SessionStore sessions,
    TokenIssuer issuer,
    WincheAuthOptions options,
    TimeProvider time,
    IServiceProvider services,
    ILoggerFactory loggers,
    AuthUserEvents userEvents) : IWincheAuth
{
    private readonly ILogger _events = loggers.CreateLogger(AuthEvents.Category);

    /// <summary>Runs a sign-in style operation, logging how it went: who, and the outcome.</summary>
    private async Task<AuthTokens> Logged(string operation, string? tried, Func<Task<AuthTokens>> body, Func<AuthTokens, string> success,
        Func<AuthException, string> failure, LogLevel level = LogLevel.Information)
    {
        try
        {
            var tokens = await body();
            AuthEvents.Log(_events, level, operation, tokens.User.Uid, "ok", success(tokens), tokens.User.Email);
            return tokens;
        }
        catch (AuthException ex) when (ex.Code == AuthErrorCodes.MfaRequired)
        {
            AuthEvents.Log(_events, LogLevel.Information, operation, tried, "mfaRequired", $"{tried ?? "Someone"} passed the first sign-in step; waiting for their code.",
                tried?.Contains('@') == true ? tried : null);
            throw;
        }
        catch (AuthException ex)
        {
            AuthEvents.Log(_events, LogLevel.Warning, operation, tried, AuthEvents.Outcome(ex.Code), failure(ex), tried?.Contains('@') == true ? tried : null);
            throw;
        }
    }

    private void Changed(string operation, string uid, string message) => AuthEvents.Log(_events, LogLevel.Information, operation, uid, "ok", message);

    /// <summary>
    /// Runs <paramref name="body"/> in one transaction (joining the current one, if any): the changes it saves and the
    /// events it records commit together, or not at all.
    /// </summary>
    private async Task<T> InTransaction<T>(Func<Task<T>> body, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is not null) return await body();
        T result;
        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            result = await body();
            await tx.CommitAsync(ct);
        }
        userEvents.OnCommitted();
        return result;
    }

    private Task InTransaction(Func<Task> body, CancellationToken ct) => InTransaction(async () => { await body(); return true; }, ct);

    /// <summary>Records a user event in the current transaction, for the observers (webhooks, actions, the app's own).</summary>
    private Task Record(string type, WincheUserInfo user, CancellationToken ct, string? provider = null) =>
        AuthUserEvents.AppendAsync((NpgsqlConnection)db.Database.GetDbConnection(),
            (NpgsqlTransaction)(db.Database.CurrentTransaction ?? throw new InvalidOperationException("A user event outside a transaction.")).GetDbTransaction(),
            type, user, provider, ct);
    // A real hash to check against when the email is unknown, so a wrong email takes as long as a wrong password.
    private static string? _dummyHash;

    // ── signing in ──────────────────────────────────────────────────────────────

    public Task<AuthTokens> SignUpAsync(string email, string password, string? displayName, AuthRequestInfo info, CancellationToken ct) =>
        Logged("auth.signUp", Trimmed(email), () => SignUpCoreAsync(email, password, displayName, info, ct), t => $"{t.User.Uid} signed up with {t.User.Email}.", e => $"Sign-up as {Trimmed(email)} failed: {e.Message}");

    private async Task<AuthTokens> SignUpCoreAsync(string email, string password, string? displayName, AuthRequestInfo info, CancellationToken ct)
    {
        RequireEmailPassword();
        email = CheckEmail(email);
        CheckPassword(password);
        await BeforeCreateAsync(new AuthAttempt(email, "password", info.IpAddress), ct);
        if (await users.FindByEmailAsync(email) is not null) throw EmailExists();

        var user = NewUser();
        user.Email = email;
        user.DisplayName = Clean(displayName, 100);
        await CreateAsync(user, password, ct: ct);
        if (options.EmailSending is { SendVerificationOnSignUp: true } || options.EmailPasswordSignIn!.RequireVerifiedEmail)
            await SendCodeAsync(Email.AuthEmailKinds.VerifyEmail, Email.AuthEmailKinds.VerifyEmail, user, email, options.EmailSending!.VerifyLinkLifetime, null, ct);
        if (options.EmailPasswordSignIn!.RequireVerifiedEmail) throw NotVerified(email);
        return await StartSessionAsync(user, "password", info, ct);
    }

    public Task<AuthTokens> SignInAsync(string email, string password, AuthRequestInfo info, CancellationToken ct) =>
        Logged("auth.signIn", Trimmed(email), () => SignInCoreAsync(email, password, info, ct), t => $"{t.User.Uid} signed in with a password.", e => $"Sign-in as {Trimmed(email)} failed: {e.Message}");

    private async Task<AuthTokens> SignInCoreAsync(string email, string password, AuthRequestInfo info, CancellationToken ct)
    {
        RequireEmailPassword();
        var user = string.IsNullOrWhiteSpace(email) ? null : await users.FindByEmailAsync(email.Trim());
        if (user is null || user.PasswordHash is null)
        {
            users.PasswordHasher.VerifyHashedPassword(new WincheUser(), _dummyHash ??= users.PasswordHasher.HashPassword(new WincheUser(), "x-" + Guid.NewGuid()), password ?? "");
            throw InvalidCredentials();
        }
        if (await users.IsLockedOutAsync(user)) throw LockedOut(user);
        if (!await users.CheckPasswordAsync(user, password ?? ""))
        {
            await users.AccessFailedAsync(user);
            if (await users.IsLockedOutAsync(user))
            {
                AuthEvents.Log(_events, LogLevel.Warning, "auth.lockout", user.Id, "lockedOut",
                    $"{user.Id} ({user.Email}) is locked out after {options.MaxFailedSignIns} failed sign-ins in a row.", user.Email);
                throw LockedOut(user);
            }
            throw InvalidCredentials();
        }
        // With two-step sign-in the count carries on until the second step passes: a right password mustn't wipe out
        // wrong codes, or codes could be guessed without end by signing in again between tries.
        if (!user.TwoFactorEnabled) await users.ResetAccessFailedCountAsync(user);
        if (user.Disabled) throw Disabled();
        if (options.EmailPasswordSignIn!.RequireVerifiedEmail && !user.EmailConfirmed) throw NotVerified(user.Email!);
        await BeforeSignInAsync(user, new AuthAttempt(user.Email, "password", info.IpAddress), ct);
        return await CompleteSignInAsync(user, "password", info, ct);
    }

    public Task<AuthTokens> SignInAnonymouslyAsync(AuthRequestInfo info, CancellationToken ct) =>
        Logged("auth.anonymous", info.IpAddress, () => SignInAnonymouslyCoreAsync(info, ct), t => $"{t.User.Uid} signed in as a guest.", e => $"Guest sign-in failed: {e.Message}");

    private async Task<AuthTokens> SignInAnonymouslyCoreAsync(AuthRequestInfo info, CancellationToken ct)
    {
        if (!options.AnonymousSignIn) throw NotEnabled("Anonymous sign-in");
        await BeforeCreateAsync(new AuthAttempt(null, "anonymous", info.IpAddress), ct);
        var user = NewUser();
        user.IsAnonymous = true;
        await CreateAsync(user, null, ct: ct);
        return await StartSessionAsync(user, "anonymous", info, ct);
    }

    public Task<AuthTokens> RefreshAsync(string refreshToken, AuthRequestInfo info, CancellationToken ct) =>
        Logged("auth.refresh", info.IpAddress, () => RefreshCoreAsync(refreshToken, info, ct), t => $"{t.User.Uid} got a new access token.", e => $"A token refresh was refused: {e.Message}", LogLevel.Debug);

    private async Task<AuthTokens> RefreshCoreAsync(string refreshToken, AuthRequestInfo info, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(refreshToken)) throw new AuthException(AuthErrorCodes.InvalidRefreshToken, "A refresh token is required.");
        var (session, next) = await sessions.RotateAsync(refreshToken, info, ct);
        var user = await users.FindByIdAsync(session.UserId);
        if (user is null || user.Disabled)
        {
            await sessions.RevokeAllAsync(session.UserId, user is null ? "user deleted" : "user disabled", ct);
            throw user is null ? new AuthException(AuthErrorCodes.UserNotFound, "This account no longer exists.") : Disabled();
        }
        return await TokensAsync(user, session.Provider, session.AuthTime, next, ct, session.SecondFactor is not null);
    }

    public async Task SignOutAsync(string refreshToken, CancellationToken ct)
    {
        if (await sessions.RevokeByTokenAsync(refreshToken ?? "", ct))
            AuthEvents.Log(_events, LogLevel.Information, "auth.signOut", null, "ok", "A session was signed out.");
    }

    public Task<AuthTokens> LinkPasswordAsync(string uid, string email, string password, AuthRequestInfo info, CancellationToken ct) =>
        Logged("auth.link", uid, () => LinkPasswordCoreAsync(uid, email, password, info, ct), t => $"{t.User.Uid} upgraded from a guest to {t.User.Email}.", e => $"{uid} couldn't upgrade to {Trimmed(email)}: {e.Message}");

    private async Task<AuthTokens> LinkPasswordCoreAsync(string uid, string email, string password, AuthRequestInfo info, CancellationToken ct)
    {
        RequireEmailPassword();
        var user = await Find(uid);
        if (!user.IsAnonymous) throw new AuthException(AuthErrorCodes.NotAnonymous, "Only an anonymous account can be upgraded this way.");
        if (user.Disabled) throw Disabled();
        email = CheckEmail(email);
        CheckPassword(password);
        if (await users.FindByEmailAsync(email) is not null) throw EmailExists();
        user.Email = email;
        user.NormalizedEmail = users.NormalizeEmail(email);
        user.IsAnonymous = false;
        var added = await users.AddPasswordAsync(user, password);
        if (!added.Succeeded) throw Failed(added);
        await Save(user);
        // As at sign-up: the address is checked before it can sign in, when the app asks for that.
        if (options.EmailSending is { SendVerificationOnSignUp: true } || options.EmailPasswordSignIn!.RequireVerifiedEmail)
            await SendCodeAsync(Email.AuthEmailKinds.VerifyEmail, Email.AuthEmailKinds.VerifyEmail, user, email, options.EmailSending!.VerifyLinkLifetime, null, ct);
        if (options.EmailPasswordSignIn!.RequireVerifiedEmail)
        {
            await sessions.RevokeAllAsync(user.Id, "guest upgraded; email not verified yet", ct);
            throw NotVerified(email);
        }
        return await StartSessionAsync(user, "password", info, ct);
    }

    public Task<AuthTokens> ChangePasswordAsync(string uid, string currentPassword, string newPassword, AuthRequestInfo info, CancellationToken ct) =>
        Logged("auth.password", uid, () => ChangePasswordCoreAsync(uid, currentPassword, newPassword, info, ct), t => $"{t.User.Uid} changed their password; their other sessions ended.", e => $"{uid} couldn't change their password: {e.Message}");

    private async Task<AuthTokens> ChangePasswordCoreAsync(string uid, string currentPassword, string newPassword, AuthRequestInfo info, CancellationToken ct)
    {
        RequireEmailPassword();
        var user = await Find(uid);
        if (user.Disabled) throw Disabled();
        CheckPassword(newPassword);
        if (user.PasswordHash is null || !await users.CheckPasswordAsync(user, currentPassword ?? "")) throw InvalidCredentials();
        var changed = await users.ChangePasswordAsync(user, currentPassword!, newPassword);
        if (!changed.Succeeded) throw Failed(changed);
        await sessions.RevokeAllAsync(user.Id, "password changed", ct);
        return await StartSessionAsync(user, "password", info, ct);
    }

    public Task<AuthTokens> SignInAsUserAsync(string uid, AuthRequestInfo info, CancellationToken ct) =>
        Logged("auth.custom", uid, () => SignInAsUserCoreAsync(uid, info, ct), t => $"{t.User.Uid} was signed in by the app's code.", e => $"Signing in {uid} by code failed: {e.Message}");

    private async Task<AuthTokens> SignInAsUserCoreAsync(string uid, AuthRequestInfo info, CancellationToken ct)
    {
        var user = await Find(uid);
        if (user.Disabled) throw Disabled();
        return await StartSessionAsync(user, "custom", info, ct);
    }

    // ── custom tokens ───────────────────────────────────────────────────────────

    public Task<string> CreateCustomTokenAsync(string uid, TimeSpan? lifetime, CancellationToken ct)
    {
        if (!ValidUid(uid)) throw new AuthException(AuthErrorCodes.InvalidArgument, "A uid is 1 to 64 letters, digits, '-' or '_'.");
        var life = lifetime ?? TimeSpan.FromHours(1);
        if (life <= TimeSpan.Zero || life > TimeSpan.FromHours(1))
            throw new AuthException(AuthErrorCodes.InvalidArgument, "A custom token lasts at most an hour.");
        return issuer.CustomTokenAsync(uid, life, ct);
    }

    public Task<AuthTokens> SignInWithCustomTokenAsync(string token, AuthRequestInfo info, CancellationToken ct) =>
        Logged("auth.customToken", null, () => SignInWithCustomTokenCoreAsync(token, info, ct), t => $"{t.User.Uid} signed in with a custom token.",
            e => $"Signing in with a custom token failed: {e.Message}");

    private async Task<AuthTokens> SignInWithCustomTokenCoreAsync(string token, AuthRequestInfo info, CancellationToken ct)
    {
        var uid = (string.IsNullOrWhiteSpace(token) || token.Length > 4096 ? null : await issuer.ReadCustomTokenAsync(token.Trim(), ct))
            ?? throw new AuthException(AuthErrorCodes.InvalidCustomToken, "The custom token isn't valid (or has expired).");
        var user = await users.FindByIdAsync(uid);
        if (user is null)
        {
            // The app's server vouches for this uid: its first sign-in makes the account.
            await BeforeCreateAsync(new AuthAttempt(null, "custom", info.IpAddress), ct);
            user = NewUser(uid);
            await CreateAsync(user, null, ct: ct);
        }
        if (user.Disabled) throw Disabled();
        await BeforeSignInAsync(user, new AuthAttempt(user.Email, "custom", info.IpAddress), ct);
        return await StartSessionAsync(user, "custom", info, ct);   // the app's server vouched: no second step asked
    }

    // ── checks before sign-up and sign-in ───────────────────────────────────────

    /// <summary>The app's BeforeCreate hook, then every <see cref="IWincheAuthGate"/>.</summary>
    private async Task BeforeCreateAsync(AuthAttempt attempt, CancellationToken ct)
    {
        if (options.Events.BeforeCreate is { } before) await before(attempt, services);
        foreach (var gate in services.GetServices<IWincheAuthGate>())
            try { await gate.BeforeCreateAsync(attempt, ct); }
            catch (WincheDeniedException ex) { throw new AuthDeniedException(ex.Message); }
    }

    /// <summary>The app's BeforeSignIn hook, then every <see cref="IWincheAuthGate"/>.</summary>
    private async Task BeforeSignInAsync(WincheUser user, AuthAttempt attempt, CancellationToken ct)
    {
        var info = await InfoAsync(user);
        if (options.Events.BeforeSignIn is { } hook) await hook(info, attempt, services);
        foreach (var gate in services.GetServices<IWincheAuthGate>())
            try { await gate.BeforeSignInAsync(info, attempt, ct); }
            catch (WincheDeniedException ex) { throw new AuthDeniedException(ex.Message); }
    }

    // ── managing users ──────────────────────────────────────────────────────────

    public async Task<WincheUserInfo?> GetUserAsync(string uid, CancellationToken ct) =>
        await users.FindByIdAsync(uid) is { } u ? await InfoAsync(u) : null;

    public async Task<WincheUserInfo?> FindByEmailAsync(string email, CancellationToken ct) =>
        await users.FindByEmailAsync(email) is { } u ? await InfoAsync(u) : null;

    public async Task<UserPage> ListUsersAsync(string? search, int offset, int limit, CancellationToken ct)
    {
        IQueryable<WincheUser> q = db.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = $"%{search.Trim().Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_")}%";
            q = q.Where(u => u.Id == search.Trim() || EF.Functions.ILike(u.Email!, s) || EF.Functions.ILike(u.DisplayName!, s));
        }
        var total = await q.CountAsync(ct);
        var page = await q.OrderByDescending(u => u.CreatedAt).ThenBy(u => u.Id)
            .Skip(Math.Max(0, offset)).Take(Math.Clamp(limit, 1, 500)).ToListAsync(ct);
        var ids = page.Select(u => u.Id).ToList();
        var logins = (await db.UserLogins.AsNoTracking().Where(l => ids.Contains(l.UserId)).Select(l => new { l.UserId, l.LoginProvider }).ToListAsync(ct))
            .ToLookup(l => l.UserId, l => l.LoginProvider);
        return new UserPage([.. page.Select(u => WincheUserInfo.From(u, time.GetUtcNow(), [.. logins[u.Id]], options))], total);
    }

    public async Task<UserListPage> ListUsersPageAsync(string? pageToken, int pageSize, CancellationToken ct)
    {
        IQueryable<WincheUser> q = db.Users.AsNoTracking();
        if (!string.IsNullOrEmpty(pageToken))
        {
            // After the last one of the previous page, newest first: (created, id) keeps its place as users come and go.
            string[] parts;
            try { parts = System.Text.Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(pageToken)).Split('|', 2); }
            catch (FormatException) { parts = []; }
            if (parts.Length != 2 || !long.TryParse(parts[0], out var ticks))
                throw new AuthException(AuthErrorCodes.InvalidArgument, "That pageToken isn't one this server gave.");
            var at = new DateTimeOffset(ticks, TimeSpan.Zero);
            var id = parts[1];
            q = q.Where(u => u.CreatedAt < at || (u.CreatedAt == at && string.Compare(u.Id, id) > 0));
        }
        var size = Math.Clamp(pageSize, 1, 1000);
        var page = await q.OrderByDescending(u => u.CreatedAt).ThenBy(u => u.Id).Take(size + 1).ToListAsync(ct);
        var more = page.Count > size;
        if (more) page.RemoveAt(size);
        var ids = page.Select(u => u.Id).ToList();
        var logins = (await db.UserLogins.AsNoTracking().Where(l => ids.Contains(l.UserId)).Select(l => new { l.UserId, l.LoginProvider }).ToListAsync(ct))
            .ToLookup(l => l.UserId, l => l.LoginProvider);
        var next = more ? Base64UrlEncoder.Encode(System.Text.Encoding.UTF8.GetBytes($"{page[^1].CreatedAt.UtcTicks}|{page[^1].Id}")) : null;
        return new UserListPage([.. page.Select(u => WincheUserInfo.From(u, time.GetUtcNow(), [.. logins[u.Id]], options))], next);
    }

    public async Task<WincheUserInfo> CreateUserAsync(string? email, string? password, string? displayName, CancellationToken ct)
    {
        var user = NewUser();
        user.DisplayName = Clean(displayName, 100);
        if (email is null)
        {
            if (password is not null) throw new AuthException(AuthErrorCodes.InvalidArgument, "A password needs an email.");
            user.IsAnonymous = true;
        }
        else
        {
            user.Email = CheckEmail(email);
            if (password is not null) CheckPassword(password);
            if (await users.FindByEmailAsync(user.Email) is not null) throw EmailExists();
        }
        await BeforeCreateAsync(new AuthAttempt(user.Email, user.IsAnonymous ? "anonymous" : "password", null), ct);
        await CreateAsync(user, password, ct: ct);
        Changed("auth.create", user.Id, $"{user.Id} ({user.Email ?? "a guest"}) was created by the app's code or the console.");
        return await InfoAsync(user);
    }

    public Task<WincheUserInfo> UpdateProfileAsync(string uid, string? displayName, string? photoUrl, CancellationToken ct) =>
        PatchProfileAsync(uid, new ProfilePatch(true, displayName, true, photoUrl), ct);

    public Task<WincheUserInfo> PatchProfileAsync(string uid, ProfilePatch patch, CancellationToken ct)
    {
        if (patch is { SetPhotoUrl: true, PhotoUrl: { Length: > 0 } photoUrl } && !(Uri.TryCreate(photoUrl, UriKind.Absolute, out var url) && url.Scheme is "https" or "http"))
            throw new AuthException(AuthErrorCodes.InvalidArgument, "photoUrl must be an http(s) URL.");
        return InTransaction(async () =>
        {
            await LockUser(uid, ct);
            var user = await Find(uid);
            if (patch.SetDisplayName) user.DisplayName = Clean(patch.DisplayName, 100);
            var url = patch.SetPhotoUrl ? Clean(patch.PhotoUrl, 2000) : options.PhotoUrlOf(user);
            // The uploaded photo's own address, even one from before the server moved (an app's cached copy): unchanged.
            if (user is { PhotoSource: "upload", PhotoUrl: { } stored } && url is not null
                && url.EndsWith("/photos/" + stored[(stored.LastIndexOf('/') + 1)..], StringComparison.Ordinal))
                url = options.PhotoUrlOf(user);
            if (url != options.PhotoUrlOf(user))
            {
                // A new link (or none) replaces an uploaded photo, and a provider's no longer follows sign-ins.
                if (await db.Photos.FindAsync([uid], ct) is { } kept) db.Photos.Remove(kept);
                user.PhotoUrl = url;
                user.PhotoSource = url is null ? null : "link";
            }
            await Save(user);
            var info = await InfoAsync(user);
            await Record(WincheAuthUserEvent.Updated, info, ct);
            return info;
        }, ct);
    }

    public async Task<WincheUserInfo> SetPasswordAsync(string uid, string password, CancellationToken ct)
    {
        RequireEmailPassword();
        CheckPassword(password);
        var info = await InTransaction(async () =>
        {
            var user = await Find(uid);
            if (user.Email is null) throw new AuthException(AuthErrorCodes.InvalidArgument, "This account has no email address to sign in with: set one first.");
            if (user.PasswordHash is not null)
            {
                var removed = await users.RemovePasswordAsync(user);
                if (!removed.Succeeded) throw Failed(removed);
            }
            var added = await users.AddPasswordAsync(user, password);
            if (!added.Succeeded) throw Failed(added);
            await sessions.RevokeAllAsync(uid, "password set by the app", ct);
            var info = await InfoAsync(user);
            await Record(WincheAuthUserEvent.Updated, info, ct);
            return info;
        }, ct);
        Changed("auth.setPassword", uid, $"{uid}'s password was set by the app's code or the console; every session ended.");
        return info;
    }

    /// <summary>Changes a user, saves them and records <c>updated</c>, in one transaction.</summary>
    private Task<WincheUserInfo> SaveUpdatedAsync(string uid, Action<WincheUser> change, CancellationToken ct) => InTransaction(async () =>
    {
        var user = await Find(uid);
        change(user);
        await Save(user);
        var info = await InfoAsync(user);
        await Record(WincheAuthUserEvent.Updated, info, ct);
        return info;
    }, ct);

    public async Task<WincheUserInfo> SetDisabledAsync(string uid, bool disabled, CancellationToken ct)
    {
        var info = await InTransaction(async () =>
        {
            var user = await Find(uid);
            user.Disabled = disabled;
            await Save(user);
            if (disabled) await sessions.RevokeAllAsync(uid, "user disabled", ct);
            var info = await InfoAsync(user);
            await Record(disabled ? WincheAuthUserEvent.Disabled : WincheAuthUserEvent.Enabled, info, ct);
            return info;
        }, ct);
        Changed(disabled ? "auth.disable" : "auth.enable", uid, disabled ? $"{uid} was disabled and signed out everywhere." : $"{uid} was enabled.");
        return info;
    }

    public async Task<WincheUserInfo> SetCustomClaimsAsync(string uid, IReadOnlyDictionary<string, object?>? claims, CancellationToken ct)
    {
        var (info, json) = await InTransaction(async () =>
        {
            var user = await Find(uid);
            user.CustomClaims = CustomClaims.Serialize(claims);
            await Save(user);
            var info = await InfoAsync(user);
            await Record(WincheAuthUserEvent.ClaimsChanged, info, ct);
            return (info, user.CustomClaims);
        }, ct);
        Changed("auth.claims", uid, json is null ? $"{uid}'s custom claims were cleared." : $"{uid}'s custom claims were set to {json}.");
        return info;
    }

    public async Task DeleteUserAsync(string uid, CancellationToken ct)
    {
        var email = await InTransaction(async () =>
        {
            var user = await Find(uid);
            var info = await InfoAsync(user);
            var deleted = await users.DeleteAsync(user);   // sessions cascade
            if (!deleted.Succeeded) throw Failed(deleted);
            await Record(WincheAuthUserEvent.Deleted, info, ct);
            return user.Email;
        }, ct);
        Changed("auth.delete", uid, $"{uid} ({email ?? "a guest"}) was deleted.");
    }

    public Task<IReadOnlyList<SessionInfo>> ListSessionsAsync(string uid, CancellationToken ct) => sessions.ActiveAsync(uid, ct);

    public Task<bool> RevokeSessionAsync(string uid, Guid sessionId, CancellationToken ct) => sessions.RevokeAsync(uid, sessionId, ct);

    public async Task<int> RevokeSessionsAsync(string uid, CancellationToken ct)
    {
        var count = await sessions.RevokeAllAsync(uid, "signed out everywhere", ct);
        Changed("auth.revoke", uid, $"{uid} was signed out everywhere ({count} session{(count == 1 ? "" : "s")}).");
        return count;
    }

    public async Task<WincheUserInfo> UnlockAsync(string uid, CancellationToken ct)
    {
        var user = await Find(uid);
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
        Changed("auth.unlock", uid, $"{uid} was unlocked.");
        return await InfoAsync(user);
    }

    // ── helpers ─────────────────────────────────────────────────────────────────

    private async Task<AuthTokens> StartSessionAsync(WincheUser user, string provider, AuthRequestInfo info, CancellationToken ct, string? secondFactor = null,
        string? providerSessionId = null)
    {
        var now = time.GetUtcNow();
        return await InTransaction(async () =>
        {
            user.LastSignInAt = now;
            await Save(user);
            var refresh = await sessions.CreateAsync(user.Id, provider, now, info, ct, secondFactor, providerSessionId);
            var tokens = await TokensAsync(user, provider, now, refresh, ct, secondFactor is not null);
            await Record(WincheAuthUserEvent.SignedIn, tokens.User, ct, provider);
            return tokens;
        }, ct);
    }

    private async Task<AuthTokens> TokensAsync(WincheUser user, string provider, DateTimeOffset authTime, string refresh, CancellationToken ct, bool mfa = false)
    {
        var (token, expires) = await issuer.IssueAsync(user, provider, authTime, ct, mfa, SessionStore.IdOf(refresh));
        return new AuthTokens(token, expires, (int)options.AccessTokenLifetime.TotalSeconds, refresh, await InfoAsync(user));
    }

    /// <summary>
    /// Makes the account, <paramref name="also"/> (its first sign-in method), runs <c>AfterCreate</c> and records
    /// <c>created</c>, in one transaction: a failure anywhere leaves no half-made account behind.
    /// </summary>
    private Task CreateAsync(WincheUser user, string? password, Func<Task>? also = null, CancellationToken ct = default) => InTransaction(async () =>
    {
        IdentityResult result;
        try { result = password is null ? await users.CreateAsync(user) : await users.CreateAsync(user, password); }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            throw EmailExists();
        }
        if (!result.Succeeded) throw Failed(result);
        if (also is not null) await also();
        if (options.Events.AfterCreate is { } after) await after(await InfoAsync(user), services);
        await Record(WincheAuthUserEvent.Created, await InfoAsync(user), ct);
    }, ct);

    private async Task Save(WincheUser user)
    {
        IdentityResult result;
        try { result = await users.UpdateAsync(user); }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            throw EmailExists();
        }
        if (!result.Succeeded) throw Failed(result);
    }

    /// <summary>
    /// Someone just proved they own <paramref name="user"/>'s email, which was never verified: whoever made the account
    /// may not be them (signed up with their address first). Everything that person could have set up goes — the
    /// password, linked providers, two-step sign-in, every session — so the account is the address owner's alone.
    /// </summary>
    private async Task SecureClaimedAccountAsync(WincheUser user, string how, CancellationToken ct)
    {
        if (user.EmailConfirmed) return;
        var logins = await users.GetLoginsAsync(user);
        if (user.PasswordHash is null && logins.Count == 0 && !user.TwoFactorEnabled) return;
        // What whoever made the account showed as the owner goes too: their name and photo (an upload is deleted).
        await db.Photos.Where(p => p.UserId == user.Id).ExecuteDeleteAsync(ct);
        user.DisplayName = null;
        user.PhotoUrl = null;
        user.PhotoSource = null;
        if (user.PasswordHash is not null)
        {
            var removed = await users.RemovePasswordAsync(user);
            if (!removed.Succeeded) throw Failed(removed);
        }
        foreach (var login in logins)
        {
            ForgetProviderPhoto(user, login.LoginProvider);
            var unlinked = await users.RemoveLoginAsync(user, login.LoginProvider, login.ProviderKey);
            if (!unlinked.Succeeded) throw Failed(unlinked);
        }
        if (user.TwoFactorEnabled) await ClearMfaAsync(user);
        await sessions.RevokeAllAsync(user.Id, "email proven by its owner", ct);
        await Save(user);
        await Record(WincheAuthUserEvent.Updated, await InfoAsync(user), ct);   // observers drop the name and photo too
        AuthEvents.Log(_events, LogLevel.Warning, "auth.claimed", user.Id, "ok",
            $"{user.Id}'s email {user.Email} was unverified until its owner {how}: its password, linked providers, two-step sign-in, name, photo and sessions were removed.",
            user.Email);
    }

    private async Task<WincheUser> Find(string uid) =>
        (string.IsNullOrEmpty(uid) ? null : await users.FindByIdAsync(uid))
        ?? throw new AuthException(AuthErrorCodes.UserNotFound, "There's no user with that uid.");

    private WincheUser NewUser(string? uid = null)
    {
        uid ??= NewUid();
        return new WincheUser { Id = uid, UserName = uid, CreatedAt = time.GetUtcNow(), LockoutEnabled = true };
    }

    /// <summary>28 random letters and digits.</summary>
    internal static string NewUid() => RandomNumberGenerator.GetString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 28);

    private async Task<WincheUserInfo> InfoAsync(WincheUser u) =>
        WincheUserInfo.From(u, time.GetUtcNow(), await db.UserLogins.AsNoTracking().Where(l => l.UserId == u.Id).Select(l => l.LoginProvider).ToListAsync(), options);

    private void RequireEmailPassword()
    {
        if (options.EmailPasswordSignIn is null) throw NotEnabled("Email and password sign-in");
    }

    private static string CheckEmail(string? email)
    {
        email = Trimmed(email);
        if (string.IsNullOrEmpty(email) || email.Length > 254 || !MailAddress.TryCreate(email, out var parsed) || parsed.Address != email || !email.Contains('.', StringComparison.Ordinal))
            throw new AuthException(AuthErrorCodes.InvalidEmail, "That isn't a valid email address.");
        return email;
    }

    private void CheckPassword(string? password)
    {
        var min = options.EmailPasswordSignIn?.MinLength ?? 10;
        if (string.IsNullOrEmpty(password) || password.Length < min)
            throw new AuthException(AuthErrorCodes.WeakPassword, $"Passwords need at least {min} characters.");
        if (password.Length > 256) throw new AuthException(AuthErrorCodes.WeakPassword, "Passwords can be at most 256 characters.");
    }

    private static string? Trimmed(string? s) => s?.Trim();

    private static string? Clean(string? s, int max) => string.IsNullOrWhiteSpace(s) ? null : s.Trim().Length <= max ? s.Trim() : s.Trim()[..max];

    private static AuthException Failed(IdentityResult r)
    {
        var first = r.Errors.FirstOrDefault();
        return first?.Code switch
        {
            "DuplicateEmail" => EmailExists(),
            "InvalidEmail" => new AuthException(AuthErrorCodes.InvalidEmail, "That isn't a valid email address."),
            { } c when c.StartsWith("Password", StringComparison.Ordinal) => new AuthException(AuthErrorCodes.WeakPassword, first!.Description),
            _ => new AuthException(AuthErrorCodes.InvalidArgument, first?.Description ?? "The request couldn't be completed."),
        };
    }

    private static AuthException InvalidCredentials() => new(AuthErrorCodes.InvalidCredentials, "The email or password is wrong.");
    private static AuthException EmailExists() => new(AuthErrorCodes.EmailExists, "An account with that email already exists.");
    private static AuthException NotVerified(string email) =>
        new(AuthErrorCodes.EmailNotVerified, $"Verify your email first: we've sent a link to {email}. Then sign in.");
    private static AuthException Disabled() => new(AuthErrorCodes.UserDisabled, "This account has been disabled.");
    private static AuthException NotEnabled(string what) => new(AuthErrorCodes.NotEnabled, $"{what} isn't turned on for this app.");

    private AuthException LockedOut(WincheUser user)
    {
        var minutes = user.LockoutEnd is { } end ? Math.Max(1, (int)Math.Ceiling((end - time.GetUtcNow()).TotalMinutes)) : (int)options.LockoutDuration.TotalMinutes;
        return new AuthException(AuthErrorCodes.LockedOut, $"Too many failed sign-ins. Try again in {minutes} minute{(minutes == 1 ? "" : "s")}.");
    }
}
