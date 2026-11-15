using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Winche.Auth.Data;
using Winche.Auth.Logging;
using Winche.Auth.Mfa;

namespace Winche.Auth.Users;

/// <summary>Two-step sign-in: an authenticator app (TOTP) and single-use recovery codes.</summary>
internal sealed partial class WincheAuthService
{
    private const string TokenProvider = "Winche";
    private const string TotpKey = "TotpKey";
    private const string TotpPendingKey = "TotpPendingKey";
    private const string TotpLastStep = "TotpLastStep";
    private const string RecoveryCodes = "RecoveryCodes";
    private const string MfaKind = "mfa";

    /// <summary>
    /// The end of a first-step sign-in (password, email link, provider): a session, or — when the user has two-step
    /// sign-in — MFA_REQUIRED with a short-lived <c>mfaToken</c> for <see cref="SignInWithMfaAsync"/>.
    /// Two-step belongs to the account: a user who turned it on needs a second step whichever way they sign in. A
    /// provider that already checked one (<paramref name="providerSecondStep"/>) counts, so they aren't asked twice; a
    /// provider that requires one (<paramref name="requireSecondStep"/>) refuses users who have neither.
    /// </summary>
    private async Task<AuthTokens> CompleteSignInAsync(WincheUser user, string provider, AuthRequestInfo info, CancellationToken ct,
        string? providerSecondStep = null, bool requireSecondStep = false, string? providerSessionId = null)
    {
        if (providerSecondStep is not null) return await StartSessionAsync(user, provider, info, ct, $"{provider}:{providerSecondStep}", providerSessionId);
        // An enrolled second step is always asked for, even if the app has since turned two-step sign-in off.
        if (!user.TwoFactorEnabled)
        {
            if (requireSecondStep)
                throw new AuthException(AuthErrorCodes.SecondStepRequired,
                    $"Signing in with {provider} needs a second step, like a one-time code, and this sign-in had none. Sign in with {provider} again using one.");
            return await StartSessionAsync(user, provider, info, ct, providerSessionId: providerSessionId);
        }
        var pending = options.MfaSettings?.PendingLifetime ?? TimeSpan.FromMinutes(5);
        var now = time.GetUtcNow();
        var token = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        db.ActionCodes.Add(new AuthActionCode
        {
            Id = Guid.NewGuid(), Kind = MfaKind, UserId = user.Id, Email = provider,
            CodeHash = SHA256.HashData(Encoding.ASCII.GetBytes(token)), CreatedAt = now, ExpiresAt = now + pending,
        });
        await db.SaveChangesAsync(ct);
        throw new AuthException(AuthErrorCodes.MfaRequired, "Enter the code from your authenticator app.")
        {
            Details = new Dictionary<string, object?> { ["mfaToken"] = token, ["factors"] = new[] { "totp", "recovery" } },
        };
    }

    public Task<AuthTokens> SignInWithMfaAsync(string mfaToken, string code, AuthRequestInfo info, CancellationToken ct) =>
        Logged("auth.signIn.mfa", null, () => SignInWithMfaCoreAsync(mfaToken, code, info, ct),
            t => $"{t.User.Uid} finished signing in with their second step.", e => $"A second sign-in step failed: {e.Message}");

    private async Task<AuthTokens> SignInWithMfaCoreAsync(string mfaToken, string code, AuthRequestInfo info, CancellationToken ct)
    {
        AuthActionCode row;
        try { row = await FindCodeAsync(mfaToken, [MfaKind], ct); }
        catch (AuthException) { throw new AuthException(AuthErrorCodes.InvalidCode, "The sign-in took too long or was already finished: start again."); }
        var user = (row.UserId is null ? null : await users.FindByIdAsync(row.UserId)) ?? throw InvalidCode();
        if (user.Disabled) throw Disabled();
        if (await users.IsLockedOutAsync(user)) throw LockedOut(user);
        var factor = await VerifySecondFactorAsync(user, code);
        if (factor is null)
        {
            await users.AccessFailedAsync(user);
            if (await users.IsLockedOutAsync(user))
            {
                await UseAsync(row, ct);   // start over after the lockout
                AuthEvents.Log(_events, LogLevel.Warning, "auth.lockout", user.Id, "lockedOut", $"{user.Id} is locked out after wrong second-step codes.", user.Email);
                throw LockedOut(user);
            }
            throw new AuthException(AuthErrorCodes.InvalidMfaCode, "That code isn't right. Try the newest one from your authenticator app.");
        }
        await users.ResetAccessFailedCountAsync(user);
        await UseAsync(row, ct);
        return await StartSessionAsync(user, row.Email, info, ct, factor);
    }

    public async Task<MfaEnrollment> StartTotpEnrollmentAsync(string uid, CancellationToken ct)
    {
        var mfa = RequireMfa();
        var user = await Find(uid);
        if (user.IsAnonymous) throw new AuthException(AuthErrorCodes.InvalidArgument, "Guests can't add two-step sign-in: create an account first.");
        if (user.TwoFactorEnabled) throw new AuthException(AuthErrorCodes.MfaAlreadyEnabled, "Two-step sign-in is already on: turn it off first to change the app.");
        // The one waiting to be confirmed, if any: a reload of the set-up page shows the same key, so an app already
        // scanned keeps working; a new one only when there's none.
        var secret = await users.GetAuthenticationTokenAsync(user, TokenProvider, TotpPendingKey);
        if (string.IsNullOrEmpty(secret))
        {
            secret = Totp.NewSecret();
            await SetTokenAsync(user, TotpPendingKey, secret);
        }
        var issuer = mfa.Issuer ?? options.EmailSending?.AppName ?? new Uri(options.Issuer).Host;
        return new MfaEnrollment(secret, Totp.Uri(issuer, user.Email ?? user.Id, secret));
    }

    public async Task<IReadOnlyList<string>> ConfirmTotpEnrollmentAsync(string uid, string code, CancellationToken ct) =>
        await ConfirmTotpEnrollmentAsync(uid, code, null, ct);

    /// <summary>Turns two-step sign-in on and signs out every session but <paramref name="keepSession"/> (the one turning it on).</summary>
    public async Task<IReadOnlyList<string>> ConfirmTotpEnrollmentAsync(string uid, string code, Guid? keepSession, CancellationToken ct)
    {
        RequireMfa();
        var user = await Find(uid);
        var pending = await users.GetAuthenticationTokenAsync(user, TokenProvider, TotpPendingKey)
            ?? throw new AuthException(AuthErrorCodes.InvalidArgument, "Start adding the authenticator app first.");
        if (Totp.Match(pending, code, time.GetUtcNow(), 0) is not { } step)
            throw new AuthException(AuthErrorCodes.InvalidMfaCode, "That code isn't right: check the app's clock and try the newest code.");
        await SetTokenAsync(user, TotpKey, pending);
        await SetTokenAsync(user, TotpLastStep, step.ToString());
        await users.RemoveAuthenticationTokenAsync(user, TokenProvider, TotpPendingKey);
        var codes = await NewRecoveryCodesAsync(user);
        user.TwoFactorEnabled = true;
        await Save(user);
        // Securing the account ends the sessions an intruder may hold.
        await sessions.RevokeAllAsync(uid, "two-step sign-in turned on", ct, keepSession);
        Changed("auth.mfa.enroll", uid, $"{uid} turned on two-step sign-in with an authenticator app; their other sessions ended.");
        return codes;
    }

    public async Task<IReadOnlyList<string>> RegenerateRecoveryCodesAsync(string uid, string code, CancellationToken ct)
    {
        var user = await MfaUser(uid);
        if (await VerifySecondFactorAsync(user, code) is null) throw new AuthException(AuthErrorCodes.InvalidMfaCode, "That code isn't right.");
        var codes = await NewRecoveryCodesAsync(user);
        Changed("auth.mfa.recoveryCodes", uid, $"{uid} made new recovery codes; the old ones stopped working.");
        return codes;
    }

    public async Task DisableMfaAsync(string uid, string code, CancellationToken ct)
    {
        var user = await MfaUser(uid);
        if (await VerifySecondFactorAsync(user, code) is null) throw new AuthException(AuthErrorCodes.InvalidMfaCode, "That code isn't right.");
        await ClearMfaAsync(user);
        Changed("auth.mfa.disable", uid, $"{uid} turned off two-step sign-in.");
    }

    public async Task<WincheUserInfo> ResetMfaAsync(string uid, CancellationToken ct)
    {
        var user = await Find(uid);
        await ClearMfaAsync(user);
        AuthEvents.Log(_events, LogLevel.Warning, "auth.mfa.reset", uid, "ok", $"{uid}'s two-step sign-in was turned off by an admin (a lost device?).", user.Email);
        return await InfoAsync(user);
    }

    public async Task<MfaStatus> GetMfaStatusAsync(string uid, CancellationToken ct)
    {
        var user = await Find(uid);
        var codes = await users.GetAuthenticationTokenAsync(user, TokenProvider, RecoveryCodes);
        return new MfaStatus(user.TwoFactorEnabled, user.TwoFactorEnabled ? (codes?.Split(';', StringSplitOptions.RemoveEmptyEntries).Length ?? 0) : 0);
    }

    /// <summary>"totp" or "recovery" when <paramref name="code"/> is good (and used up), else null.</summary>
    private async Task<string?> VerifySecondFactorAsync(WincheUser user, string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        var key = await users.GetAuthenticationTokenAsync(user, TokenProvider, TotpKey);
        if (key is not null)
        {
            var last = long.TryParse(await users.GetAuthenticationTokenAsync(user, TokenProvider, TotpLastStep), out var l) ? l : 0;
            if (Totp.Match(key, code, time.GetUtcNow(), last) is { } step)
            {
                await SetTokenAsync(user, TotpLastStep, step.ToString());
                return "totp";
            }
        }
        var stored = await users.GetAuthenticationTokenAsync(user, TokenProvider, RecoveryCodes);
        if (stored is null) return null;
        var hashes = stored.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList();
        var hash = RecoveryHash(code);
        if (!hashes.Remove(hash)) return null;
        await SetTokenAsync(user, RecoveryCodes, string.Join(';', hashes));
        AuthEvents.Log(_events, LogLevel.Information, "auth.mfa.recoveryUsed", user.Id, "ok",
            $"{user.Id} used a recovery code; {hashes.Count} left.", user.Email);
        return "recovery";
    }

    private async Task<IReadOnlyList<string>> NewRecoveryCodesAsync(WincheUser user)
    {
        var count = options.MfaSettings?.RecoveryCodes ?? 10;
        var codes = Enumerable.Range(0, count).Select(_ =>
        {
            var raw = RandomNumberGenerator.GetString("abcdefghjkmnpqrstuvwxyz23456789", 10);
            return $"{raw[..5]}-{raw[5..]}";
        }).ToList();
        await SetTokenAsync(user, RecoveryCodes, string.Join(';', codes.Select(RecoveryHash)));
        return codes;
    }

    /// <summary>Recovery codes are kept as hashes; spaces, dashes and case don't matter.</summary>
    private static string RecoveryHash(string code) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(new string(code.Where(char.IsAsciiLetterOrDigit).Select(char.ToLowerInvariant).ToArray()))));

    private async Task ClearMfaAsync(WincheUser user)
    {
        foreach (var name in new[] { TotpKey, TotpPendingKey, TotpLastStep, RecoveryCodes })
            await users.RemoveAuthenticationTokenAsync(user, TokenProvider, name);
        user.TwoFactorEnabled = false;
        await Save(user);
    }

    private async Task SetTokenAsync(WincheUser user, string name, string value)
    {
        var result = await users.SetAuthenticationTokenAsync(user, TokenProvider, name, value);
        if (!result.Succeeded) throw Failed(result);
    }

    private async Task<WincheUser> MfaUser(string uid)
    {
        var user = await Find(uid);
        if (!user.TwoFactorEnabled) throw new AuthException(AuthErrorCodes.MfaNotEnabled, "Two-step sign-in isn't on for this account.");
        return user;
    }

    private MfaOptions RequireMfa() =>
        options.MfaSettings ?? throw new AuthException(AuthErrorCodes.NotEnabled, "Two-step sign-in isn't turned on for this app.");
}
