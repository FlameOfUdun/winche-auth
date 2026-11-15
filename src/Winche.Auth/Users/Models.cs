using Winche.Auth.Data;


namespace Winche.Auth;

/// <summary>A user as apps and the console see them.</summary>
public sealed record WincheUserInfo(
    string Uid, string? Email, bool EmailVerified, string? DisplayName, string? PhotoUrl, bool IsAnonymous, bool Disabled,
    IReadOnlyList<string> Providers, IReadOnlyDictionary<string, object?> CustomClaims, DateTimeOffset CreatedAt,
    DateTimeOffset? LastSignInAt, DateTimeOffset? LockedOutUntil, bool MfaEnabled = false)
{
    internal static WincheUserInfo From(WincheUser u, DateTimeOffset now, IReadOnlyList<string> logins)
    {
        var providers = new List<string>();
        if (u.IsAnonymous) providers.Add("anonymous");
        if (u.PasswordHash is not null) providers.Add("password");
        providers.AddRange(logins.Order(StringComparer.Ordinal));
        return new WincheUserInfo(u.Id, u.Email, u.EmailConfirmed, u.DisplayName, u.PhotoUrl, u.IsAnonymous, u.Disabled, providers,
            Tokens.CustomClaims.Parse(u.CustomClaims), u.CreatedAt, u.LastSignInAt, u.LockoutEnd is { } end && end > now ? end : null, u.TwoFactorEnabled);
    }
}

/// <summary>What a successful sign-in returns: an access token for API calls and a refresh token for new ones.</summary>
public sealed record AuthTokens(string AccessToken, DateTimeOffset ExpiresAt, int ExpiresIn, string RefreshToken, WincheUserInfo User);

/// <summary>A signed-in device.</summary>
public sealed record SessionInfo(Guid Id, string Provider, DateTimeOffset CreatedAt, DateTimeOffset LastUsedAt, DateTimeOffset ExpiresAt, string? UserAgent, string? IpAddress);

/// <summary>Where a request came from, kept on its session.</summary>
public sealed record AuthRequestInfo(string? IpAddress, string? UserAgent)
{
    public static readonly AuthRequestInfo Server = new(null, "server");
}

/// <summary>A new authenticator app: the secret to type in, and the <c>otpauth://</c> address to show as a QR code.</summary>
public sealed record MfaEnrollment(string Secret, string OtpAuthUri);

/// <summary>Whether two-step sign-in is on, and how many recovery codes are left.</summary>
public sealed record MfaStatus(bool Enabled, int RecoveryCodesLeft);

/// <summary>A page of users.</summary>
/// <summary>A page of users, newest first, and the token for the next page (null on the last).</summary>
public sealed record UserListPage(IReadOnlyList<WincheUserInfo> Users, string? NextPageToken);

public sealed record UserPage(IReadOnlyList<WincheUserInfo> Users, int Total);

/// <summary>What an emailed link does: its mode (verifyEmail, verifyAndChangeEmail, recoverEmail, resetPassword, signIn) and address.</summary>
public sealed record ActionCodeInfo(string Mode, string Email);
