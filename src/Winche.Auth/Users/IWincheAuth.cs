namespace Winche.Auth;

/// <summary>
/// Winche Auth for your server code and the endpoints: signing users in and managing them. Scoped; failures throw
/// <see cref="AuthException"/> with a stable <see cref="AuthException.Code"/>.
/// </summary>
public interface IWincheAuth
{
    // ── signing in ──
    Task<AuthTokens> SignUpAsync(string email, string password, string? displayName, AuthRequestInfo info, CancellationToken ct = default);
    Task<AuthTokens> SignInAsync(string email, string password, AuthRequestInfo info, CancellationToken ct = default);
    Task<AuthTokens> SignInAnonymouslyAsync(AuthRequestInfo info, CancellationToken ct = default);
    /// <summary>New tokens for a refresh token (which is replaced).</summary>
    Task<AuthTokens> RefreshAsync(string refreshToken, AuthRequestInfo info, CancellationToken ct = default);
    /// <summary>Ends the session the refresh token belongs to.</summary>
    Task SignOutAsync(string refreshToken, CancellationToken ct = default);
    /// <summary>Turns an anonymous user into one with an email and password, keeping their uid and data.</summary>
    Task<AuthTokens> LinkPasswordAsync(string uid, string email, string password, AuthRequestInfo info, CancellationToken ct = default);
    /// <summary>Changes the password; every other session ends, and this one continues with new tokens.</summary>
    Task<AuthTokens> ChangePasswordAsync(string uid, string currentPassword, string newPassword, AuthRequestInfo info, CancellationToken ct = default);
    /// <summary>Tokens for a user without a password: for signing users in through systems of your own.</summary>
    Task<AuthTokens> SignInAsUserAsync(string uid, AuthRequestInfo info, CancellationToken ct = default);

    // ── managing users ──
    Task<WincheUserInfo?> GetUserAsync(string uid, CancellationToken ct = default);
    Task<WincheUserInfo?> FindByEmailAsync(string email, CancellationToken ct = default);
    /// <summary>The user linked to <paramref name="provider"/>'s account <paramref name="subject"/> (its ID tokens' <c>sub</c>).</summary>
    Task<WincheUserInfo?> FindByProviderAsync(string provider, string subject, CancellationToken ct = default);
    /// <summary>Users newest first; <paramref name="search"/> matches email, name or uid.</summary>
    /// <summary>
    /// Every user, a page at a time, newest first: pass the previous page's <see cref="UserListPage.NextPageToken"/>.
    /// Unlike offsets, a page keeps its place while users are added or deleted.
    /// </summary>
    Task<UserListPage> ListUsersPageAsync(string? pageToken = null, int pageSize = 100, CancellationToken ct = default);

    Task<UserPage> ListUsersAsync(string? search = null, int offset = 0, int limit = 50, CancellationToken ct = default);
    /// <summary>Creates a user: with an email (and a password, or none to set one later), or anonymous with neither.</summary>
    Task<WincheUserInfo> CreateUserAsync(string? email, string? password, string? displayName = null, CancellationToken ct = default);
    /// <summary>Sets (or replaces) a user's password, for any user with an email; every session ends. Needs email and password sign-in.</summary>
    Task<WincheUserInfo> SetPasswordAsync(string uid, string password, CancellationToken ct = default);

    /// <summary>
    /// A token the app's server hands to a client, which signs in with it (<c>signIn/custom</c>) as <paramref name="uid"/>,
    /// making the account if there's none; valid for <paramref name="lifetime"/> (at most and by default an hour).
    /// For users that sign in through a system of your own. Their claims come from <see cref="SetCustomClaimsAsync"/>.
    /// </summary>
    Task<string> CreateCustomTokenAsync(string uid, TimeSpan? lifetime = null, CancellationToken ct = default);

    /// <summary>Signs in with a token from <see cref="CreateCustomTokenAsync"/>.</summary>
    Task<AuthTokens> SignInWithCustomTokenAsync(string token, AuthRequestInfo info, CancellationToken ct = default);

    /// <summary>
    /// A verify-email, password-reset or sign-in link (<c>kind</c>: <see cref="Email.AuthEmailKinds"/>) for the app to send
    /// itself, through its own mail or channel; nothing is emailed. Needs o.Email (for the links' addresses and lifetimes).
    /// </summary>
    Task<string> CreateEmailLinkAsync(string kind, string email, CancellationToken ct = default);

    /// <summary>
    /// The name and photo link shown for the user (null or empty clears one). A new link replaces an uploaded photo
    /// (and stops a provider's from being refreshed).
    /// </summary>
    Task<WincheUserInfo> UpdateProfileAsync(string uid, string? displayName, string? photoUrl, CancellationToken ct = default);
    /// <summary>
    /// Keeps <paramref name="image"/> as the user's photo (JPEG, PNG or WebP, at most <see cref="WincheAuthLimits.MaxPhotoBytes"/>:
    /// shrink it first, 256 × 256 is plenty) and points <c>photoUrl</c> at it (<c>/auth/v1/photos/{id}</c>, a new id each time).
    /// </summary>
    Task<WincheUserInfo> SetPhotoAsync(string uid, byte[] image, CancellationToken ct = default);
    /// <summary>Removes an uploaded photo (and <c>photoUrl</c> with it); a provider's picture comes back at the next sign-in with it.</summary>
    Task<WincheUserInfo> RemovePhotoAsync(string uid, CancellationToken ct = default);
    /// <summary>An uploaded photo by its id (the last part of its address), or null.</summary>
    Task<UserPhoto?> GetPhotoAsync(string photoId, CancellationToken ct = default);
    /// <summary>A disabled user can't sign in or refresh, and their sessions end; tokens already issued expire within the access token lifetime.</summary>
    Task<WincheUserInfo> SetDisabledAsync(string uid, bool disabled, CancellationToken ct = default);
    /// <summary>Replaces the user's custom claims (null or empty clears them); they're in the next token.</summary>
    Task<WincheUserInfo> SetCustomClaimsAsync(string uid, IReadOnlyDictionary<string, object?>? claims, CancellationToken ct = default);
    Task DeleteUserAsync(string uid, CancellationToken ct = default);
    Task<IReadOnlyList<SessionInfo>> ListSessionsAsync(string uid, CancellationToken ct = default);
    Task<bool> RevokeSessionAsync(string uid, Guid sessionId, CancellationToken ct = default);
    /// <summary>Signs the user out everywhere.</summary>
    Task<int> RevokeSessionsAsync(string uid, CancellationToken ct = default);
    // ── Google, Apple, OpenID Connect ──
    /// <summary>Exchanges a provider's ID token for Winche tokens; the first sign-in makes the user.</summary>
    Task<AuthTokens> SignInWithProviderAsync(string provider, string idToken, string? nonce, AuthRequestInfo info, CancellationToken ct = default);
    /// <summary>Links a provider account to the user (an anonymous user stops being anonymous).</summary>
    Task<AuthTokens> LinkProviderAsync(string uid, string provider, string idToken, string? nonce, AuthRequestInfo info, CancellationToken ct = default);
    /// <summary>Unlinks a provider, unless it's the user's only way to sign in.</summary>
    Task<WincheUserInfo> UnlinkProviderAsync(string uid, string provider, CancellationToken ct = default);

    /// <summary>
    /// A provider's back-channel logout (OpenID Connect Back-Channel Logout): its <paramref name="logoutToken"/> checked, the
    /// session it names ends (or every session of the person it names that came through it). How many ended.
    /// </summary>
    Task<int> EndProviderSessionsAsync(string provider, string logoutToken, CancellationToken ct = default);

    // ── two-step sign-in (needs o.Mfa) ──
    /// <summary>Finishes a sign-in that answered MFA_REQUIRED, with an authenticator code or a recovery code.</summary>
    Task<AuthTokens> SignInWithMfaAsync(string mfaToken, string code, AuthRequestInfo info, CancellationToken ct = default);
    /// <summary>Starts adding an authenticator app: a secret and its otpauth:// address (for a QR code).</summary>
    Task<MfaEnrollment> StartTotpEnrollmentAsync(string uid, CancellationToken ct = default);
    /// <summary>Turns two-step sign-in on once the app's first code checks out; returns the recovery codes (shown once).</summary>
    Task<IReadOnlyList<string>> ConfirmTotpEnrollmentAsync(string uid, string code, CancellationToken ct = default);
    /// <summary>Like <see cref="ConfirmTotpEnrollmentAsync(string, string, CancellationToken)"/>, keeping <paramref name="keepSession"/> (the one turning it on) signed in.</summary>
    Task<IReadOnlyList<string>> ConfirmTotpEnrollmentAsync(string uid, string code, Guid? keepSession, CancellationToken ct = default);
    /// <summary>New recovery codes (the old ones stop working), with a current code.</summary>
    Task<IReadOnlyList<string>> RegenerateRecoveryCodesAsync(string uid, string code, CancellationToken ct = default);
    /// <summary>Turns two-step sign-in off, with a current code.</summary>
    Task DisableMfaAsync(string uid, string code, CancellationToken ct = default);
    /// <summary>Turns two-step sign-in off without a code: for an admin helping someone who lost their device.</summary>
    Task<WincheUserInfo> ResetMfaAsync(string uid, CancellationToken ct = default);
    Task<MfaStatus> GetMfaStatusAsync(string uid, CancellationToken ct = default);

    // ── email (needs o.Email) ──
    /// <summary>Emails the user a verify-email link (nothing if already verified).</summary>
    Task SendEmailVerificationAsync(string uid, CancellationToken ct = default);
    Task<WincheUserInfo> SetEmailVerifiedAsync(string uid, bool verified, CancellationToken ct = default);
    /// <summary>
    /// An admin's change of the account's email, at once (no link): marked verified, and every session ended. Refused when
    /// another account has it. The user's own change is <see cref="ChangeEmailAsync"/>.
    /// </summary>
    Task<WincheUserInfo> SetEmailAsync(string uid, string email, CancellationToken ct = default);
    /// <summary>What an emailed link's code is for, without using it.</summary>
    Task<ActionCodeInfo> CheckActionCodeAsync(string code, CancellationToken ct = default);
    /// <summary>Uses a verify-email, confirm-new-email or undo-email-change code.</summary>
    Task<ActionCodeInfo> ApplyActionCodeAsync(string code, CancellationToken ct = default);
    /// <summary>Emails a reset link if the address has an account; the same answer either way.</summary>
    Task SendPasswordResetAsync(string email, AuthRequestInfo info, CancellationToken ct = default);
    /// <summary>Sets a new password from a reset link; every session ends.</summary>
    Task<WincheUserInfo> ResetPasswordAsync(string code, string newPassword, CancellationToken ct = default);
    /// <summary>Emails a one-time sign-in link (needs o.EmailLink); the first use makes the account.</summary>
    Task SendSignInLinkAsync(string email, AuthRequestInfo info, CancellationToken ct = default);
    Task<AuthTokens> SignInWithLinkAsync(string code, AuthRequestInfo info, CancellationToken ct = default);
    /// <summary>Emails the new address a link; the change happens when it's opened, and the old address is told (with an undo link).</summary>
    Task ChangeEmailAsync(string uid, string newEmail, CancellationToken ct = default);
    Task<IReadOnlyList<Email.EmailTemplateInfo>> GetEmailTemplatesAsync(CancellationToken ct = default);
    Task SaveEmailTemplateAsync(string kind, string subject, string body, string? by, CancellationToken ct = default);
    Task ResetEmailTemplateAsync(string kind, CancellationToken ct = default);
    Task SendTestEmailAsync(string kind, string to, CancellationToken ct = default);

    /// <summary>Ends a lockout after failed sign-ins.</summary>
    Task<WincheUserInfo> UnlockAsync(string uid, CancellationToken ct = default);
}
