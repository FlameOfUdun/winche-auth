using Npgsql;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Winche.Auth.Data;
using Winche.Auth.Logging;
using Winche.Auth.Providers;
using Winche.Auth.Tokens;

namespace Winche.Auth.Users;

/// <summary>Sign-in with Google, Apple and OpenID Connect providers: their ID tokens exchanged for Winche tokens.</summary>
internal sealed partial class WincheAuthService
{
    public Task<AuthTokens> SignInWithProviderAsync(string provider, string idToken, string? nonce, AuthRequestInfo info, CancellationToken ct) =>
        Logged($"auth.signIn.{Safe(provider)}", null, () => SignInWithProviderCoreAsync(provider, idToken, nonce, info, ct),
            t => $"{t.User.Uid} signed in with {ProviderName(provider)}.", e => $"A sign-in with {ProviderName(provider)} failed: {e.Message}");

    private async Task<AuthTokens> SignInWithProviderCoreAsync(string name, string idToken, string? nonce, AuthRequestInfo info, CancellationToken ct)
    {
        var provider = Provider(name);
        var id = await services.GetRequiredService<IdTokenValidator>().ValidateAsync(provider, idToken, nonce, ct);
        var user = await users.FindByLoginAsync(provider.Name, id.Subject);
        if (user is null)
        {
            var email = id.Email?.Trim();
            if (email is not null && await users.FindByEmailAsync(email) is not null)
            {
                // Merging silently would hand the account to whoever controls the provider's account: the user links it.
                if (id.EmailVerified)
                    throw new AuthException(AuthErrorCodes.AccountExists,
                        $"An account with {email} already exists. Sign in the way you did before, then link {provider.DisplayName ?? provider.Name} to it.");
                email = null;   // unverified: don't claim the address
            }
            await BeforeCreateAsync(new AuthAttempt(email, provider.Name, info.IpAddress), ct);
            var uid = provider.UseSubjectAsUid && ValidUid(id.Subject) && await users.FindByIdAsync(id.Subject) is null ? id.Subject : null;
            user = NewUser(uid);
            user.Email = email;
            user.EmailConfirmed = email is not null && id.EmailVerified;
            user.DisplayName = Clean(id.Name, 100);
            TakeProviderPhoto(user, provider.Name, id.Picture);
            CopyClaims(user, provider, id);
            await CreateAsync(user, null, async () =>
            {
                IdentityResult added;
                try { added = await users.AddLoginAsync(user, new UserLoginInfo(provider.Name, id.Subject, provider.DisplayName)); }
                catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
                {
                    // The same account signing up twice at once: the other attempt made it.
                    throw new AuthException(AuthErrorCodes.CredentialInUse, $"That {provider.DisplayName ?? provider.Name} account was just linked to another user. Sign in again.");
                }
                if (!added.Succeeded) throw Failed(added);
            }, ct);
        }
        else
        {
            if (user.Disabled) throw Disabled();
            TakeProviderPhoto(user, provider.Name, id.Picture);   // refreshed while it's the provider's
            CopyClaims(user, provider, id);
            if (id.EmailVerified && string.Equals(user.Email, id.Email, StringComparison.OrdinalIgnoreCase)) user.EmailConfirmed = true;
            await Save(user);
        }
        if (provider.KeycloakSync is not null) user = await SyncAtSignInAsync(provider, id.Subject, user, ct);
        await BeforeSignInAsync(user, new AuthAttempt(user.Email, provider.Name, info.IpAddress), ct);
        return await CompleteSignInAsync(user, provider.Name, info, ct, id.SecondStep, provider.RequireSecondStep, id.Claims.GetValueOrDefault("sid") as string);
    }

    public async Task<int> EndProviderSessionsAsync(string provider, string logoutToken, CancellationToken ct)
    {
        try
        {
            var ended = await EndProviderSessionsCoreAsync(provider, logoutToken, ct);
            AuthEvents.Log(_events, LogLevel.Information, $"auth.providerSignOut.{Safe(provider)}", null, "ok",
                $"{ProviderName(provider)} signed someone out: {ended} session(s) ended.");
            return ended;
        }
        catch (AuthException ex)
        {
            AuthEvents.Log(_events, LogLevel.Warning, $"auth.providerSignOut.{Safe(provider)}", null, AuthEvents.Outcome(ex.Code),
                $"A sign-out from {ProviderName(provider)} was refused: {ex.Message}");
            throw;
        }
    }

    private async Task<int> EndProviderSessionsCoreAsync(string name, string logoutToken, CancellationToken ct)
    {
        var provider = Provider(name);
        var (sid, sub) = await services.GetRequiredService<IdTokenValidator>().ValidateLogoutTokenAsync(provider, logoutToken, ct);
        var userId = sid is null && await users.FindByLoginAsync(provider.Name, sub!) is { } user ? user.Id : null;
        if (sid is null && userId is null) return 0;   // nobody here signed in with them
        return await sessions.EndProviderSessionsAsync(provider.Name, sid, userId, ct);
    }

    public Task<AuthTokens> LinkProviderAsync(string uid, string provider, string idToken, string? nonce, AuthRequestInfo info, CancellationToken ct) =>
        Logged($"auth.link.{Safe(provider)}", uid, () => LinkProviderCoreAsync(uid, provider, idToken, nonce, info, ct),
            t => $"{t.User.Uid} linked {ProviderName(provider)} to their account.", e => $"{uid} couldn't link {ProviderName(provider)}: {e.Message}");

    private async Task<AuthTokens> LinkProviderCoreAsync(string uid, string name, string idToken, string? nonce, AuthRequestInfo info, CancellationToken ct)
    {
        var provider = Provider(name);
        var user = await Find(uid);
        if (user.Disabled) throw Disabled();
        var id = await services.GetRequiredService<IdTokenValidator>().ValidateAsync(provider, idToken, nonce, ct);
        var sid = id.Claims.GetValueOrDefault("sid") as string;
        if (await users.FindByLoginAsync(provider.Name, id.Subject) is { } owner)
        {
            if (owner.Id != user.Id)
                throw new AuthException(AuthErrorCodes.CredentialInUse, $"That {provider.DisplayName ?? provider.Name} account is already linked to another user.");
            return await StartSessionAsync(user, provider.Name, info, ct, providerSessionId: sid);   // already linked: nothing to do
        }
        if ((await users.GetLoginsAsync(user)).Any(l => l.LoginProvider == provider.Name))
            throw new AuthException(AuthErrorCodes.ProviderAlreadyLinked, $"Another {provider.DisplayName ?? provider.Name} account is already linked: unlink it first.");
        var added = await users.AddLoginAsync(user, new UserLoginInfo(provider.Name, id.Subject, provider.DisplayName));
        if (!added.Succeeded) throw Failed(added);
        if (user.IsAnonymous)
        {
            user.IsAnonymous = false;
            if (user.Email is null && id.Email is { } email && await users.FindByEmailAsync(email) is null)
            {
                user.Email = email;
                user.NormalizedEmail = users.NormalizeEmail(email);
                user.EmailConfirmed = id.EmailVerified;
            }
        }
        user.DisplayName ??= Clean(id.Name, 100);
        TakeProviderPhoto(user, provider.Name, id.Picture);
        CopyClaims(user, provider, id);
        await Save(user);
        return await StartSessionAsync(user, provider.Name, info, ct, providerSessionId: sid);
    }

    public async Task<WincheUserInfo?> FindByProviderAsync(string provider, string subject, CancellationToken ct) =>
        await users.FindByLoginAsync(provider, subject) is { } u ? await InfoAsync(u) : null;

    public Task<WincheUserInfo> UnlinkProviderAsync(string uid, string provider, CancellationToken ct) =>
        InTransaction(() => UnlinkProviderCoreAsync(uid, provider, ct), ct);

    private async Task<WincheUserInfo> UnlinkProviderCoreAsync(string uid, string provider, CancellationToken ct)
    {
        var user = await Find(uid);
        var logins = await users.GetLoginsAsync(user);
        var login = logins.FirstOrDefault(l => l.LoginProvider == provider)
            ?? throw new AuthException(AuthErrorCodes.InvalidArgument, $"{ProviderName(provider)} isn't linked to this account.");
        // Only ways that work: a password counts when password sign-in is on.
        var methods = logins.Count + (user.PasswordHash is not null && options.EmailPasswordSignIn is not null ? 1 : 0)
            + (options.EmailLinkSignIn is not null && user is { Email: not null, EmailConfirmed: true } ? 1 : 0);
        if (methods <= 1)
            throw new AuthException(AuthErrorCodes.LastSignInMethod, $"{ProviderName(provider)} is the only way to sign in to this account: add another first.");
        var removed = await users.RemoveLoginAsync(user, login.LoginProvider, login.ProviderKey);
        if (!removed.Succeeded) throw Failed(removed);
        Changed($"auth.unlink.{Safe(provider)}", uid, $"{uid} unlinked {ProviderName(provider)}.");
        var info = await InfoAsync(user);
        await Record(WincheAuthUserEvent.Updated, info, ct);
        return info;
    }

    /// <summary>
    /// With the Keycloak sync on, the user as Keycloak has them now (attributes, roles, groups), so the first token
    /// already carries them. Keycloak not answering doesn't stop the sign-in: the sync catches up later.
    /// </summary>
    private async Task<WincheUser> SyncAtSignInAsync(IdentityProviderOptions provider, string subject, WincheUser user, CancellationToken ct)
    {
        try
        {
            var reader = services.GetRequiredService<ProviderSyncs>().Reader(provider);
            using var quick = CancellationTokenSource.CreateLinkedTokenSource(ct);
            quick.CancelAfter(TimeSpan.FromSeconds(5));
            if (await reader.UserAsync(subject, quick.Token) is not { } state) return user;   // the token was valid: a deletion is for the sync to see
            if (await SyncFromProviderAsync(provider, subject, state, reader.ClaimNames, ct) is null) return user;
            return await users.FindByIdAsync(user.Id) ?? user;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or System.Text.Json.JsonException && !ct.IsCancellationRequested)
        {
            AuthEvents.Log(_events, LogLevel.Warning, $"auth.sync.{provider.Name}", user.Id, "unavailable",
                $"Couldn't read {user.Id} from {ProviderName(provider.Name)} at sign-in ({ex.Message}); the sync catches up later.", user.Email);
            return user;
        }
    }

    private IdentityProviderOptions Provider(string name) =>
        options.IdentityProviders.FirstOrDefault(p => p.Name == name)
        ?? throw new AuthException(AuthErrorCodes.NotEnabled, $"Sign-in with '{name}' isn't turned on for this app.");

    private string ProviderName(string name) =>
        options.IdentityProviders.FirstOrDefault(p => p.Name == name) is { } p ? p.DisplayName ?? p.Name : name;

    private static string Safe(string? name) => name is { Length: > 0 and <= 40 } && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_') ? name : "unknown";

    /// <summary>Copies the provider's mapped claims into the user's custom claims (and drops ones its token no longer has).</summary>
    private static void CopyClaims(WincheUser user, IdentityProviderOptions provider, IdTokenIdentity id)
    {
        if (provider.CopiedClaims.Count == 0) return;
        var claims = new Dictionary<string, object?>(CustomClaims.Parse(user.CustomClaims));
        foreach (var name in provider.CopiedClaims)
        {
            if (id.Claims.GetValueOrDefault(name) is { } value) claims[name] = value;
            else claims.Remove(name);
        }
        user.CustomClaims = CustomClaims.Serialize(claims);
    }

    private static bool ValidUid(string s) =>
        s.Length is > 0 and <= 64 && s.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':');

    private static string? PhotoOrNull(string? url) =>
        url is { Length: > 0 and <= 2000 } && Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme is "https" or "http" ? url : null;
}
