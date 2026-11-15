using Microsoft.AspNetCore.Identity;

namespace Winche.Auth.Data;

/// <summary>An app user (table <c>auth_users</c>). <c>Id</c> is the uid; <c>UserName</c> is the uid too, so email can change.</summary>
internal sealed class WincheUser : IdentityUser
{
    public string? DisplayName { get; set; }
    public string? PhotoUrl { get; set; }
    public bool IsAnonymous { get; set; }
    public bool Disabled { get; set; }
    /// <summary>Custom claims as a JSON object, added to the user's tokens (rules: <c>request.auth.token.*</c>).</summary>
    public string? CustomClaims { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastSignInAt { get; set; }
}

/// <summary>A signed-in device (table <c>auth_sessions</c>): its refresh token, replaced on every use.</summary>
internal sealed class AuthSession
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = "";
    /// <summary>The sign-in method that started it: password, anonymous, custom, …</summary>
    public string Provider { get; set; } = "";
    /// <summary>The second step that completed the sign-in (totp, recovery), or null.</summary>
    public string? SecondFactor { get; set; }
    /// <summary>The identity provider's session it came from (the ID token's <c>sid</c>): its back-channel logout ends it.</summary>
    public string? ProviderSessionId { get; set; }
    /// <summary>SHA-256 of the current refresh token's secret.</summary>
    public byte[] TokenHash { get; set; } = [];
    /// <summary>SHA-256 of the one before it: presented again means it was copied, and the session is ended.</summary>
    public byte[]? PreviousTokenHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset AuthTime { get; set; }
    public DateTimeOffset LastUsedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }
    public string? UserAgent { get; set; }
    public string? IpAddress { get; set; }
}

/// <summary>A one-time code in an emailed link (table <c>auth_action_codes</c>); only its hash is stored.</summary>
internal sealed class AuthActionCode
{
    public Guid Id { get; set; }
    /// <summary>verifyEmail, resetPassword, signIn, changeEmail, recoverEmail.</summary>
    public string Kind { get; set; } = "";
    public string? UserId { get; set; }
    /// <summary>The address the link was sent to (for recoverEmail, the address to put back).</summary>
    public string Email { get; set; } = "";
    public byte[] CodeHash { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
}

/// <summary>An email template changed in the console (table <c>auth_email_templates</c>); the defaults are built in.</summary>
internal sealed class AuthEmailTemplate
{
    public string Kind { get; set; } = "";
    public string Subject { get; set; } = "";
    public string Body { get; set; } = "";
    public DateTimeOffset UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
}

/// <summary>A token signing key (table <c>auth_signing_keys</c>).</summary>
internal sealed class AuthSigningKey
{
    public string Kid { get; set; } = "";
    public string Algorithm { get; set; } = "ES256";
    /// <summary>The private key (PKCS#8), AES-GCM encrypted when <see cref="Encrypted"/>.</summary>
    public byte[] PrivateKey { get; set; } = [];
    public bool Encrypted { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    /// <summary>When a newer key took over signing; it still checks the tokens it signed until they expire.</summary>
    public DateTimeOffset? RetiredAt { get; set; }
}
