namespace Winche.Auth;

/// <summary>Why an auth request failed: a stable <see cref="Code"/> for apps and a sentence for people.</summary>
public class AuthException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;

    /// <summary>Extra values for the app, sent beside the code (e.g. the <c>mfaToken</c> of <c>MFA_REQUIRED</c>).</summary>
    public IReadOnlyDictionary<string, object?>? Details { get; init; }

    /// <summary>
    /// The error every Winche package answers with: <c>code</c> the shared kind (<see cref="AuthErrorCodes.Kind"/>),
    /// <c>reason</c> this <see cref="Code"/>, <c>details</c> the <see cref="Details"/>.
    /// </summary>
    public WincheError Error => new(AuthErrorCodes.Kind(Code), Message, Code,
        Details is { Count: > 0 } d ? System.Text.Json.JsonSerializer.SerializeToNode(d)!.AsObject() : null);
}

/// <summary>Thrown by your <see cref="WincheAuthEvents"/> hook to refuse a sign-up or sign-in; its message is shown to the user.</summary>
public sealed class AuthDeniedException(string message) : AuthException(AuthErrorCodes.Denied, message);

/// <summary>The error codes Winche Auth returns.</summary>
public static class AuthErrorCodes
{
    public const string InvalidCredentials = "INVALID_CREDENTIALS";
    public const string EmailExists = "EMAIL_EXISTS";
    public const string InvalidEmail = "INVALID_EMAIL";
    public const string WeakPassword = "WEAK_PASSWORD";
    public const string UserDisabled = "USER_DISABLED";
    public const string UserNotFound = "USER_NOT_FOUND";
    public const string LockedOut = "LOCKED_OUT";
    public const string TooManyAttempts = "TOO_MANY_ATTEMPTS";

    /// <summary>The action needs a recent sign-in (changing the email, deleting the account…): sign in again, then retry.</summary>
    public const string RequiresRecentSignIn = "REQUIRES_RECENT_SIGN_IN";

    /// <summary>A custom token that isn't valid, or has expired.</summary>
    public const string InvalidCustomToken = "INVALID_CUSTOM_TOKEN";
    public const string InvalidRefreshToken = "INVALID_REFRESH_TOKEN";
    public const string NotEnabled = "SIGN_IN_METHOD_NOT_ENABLED";
    public const string NotAnonymous = "NOT_ANONYMOUS";
    public const string InvalidClaims = "INVALID_CLAIMS";
    public const string InvalidArgument = "INVALID_ARGUMENT";
    public const string Denied = "DENIED";
    public const string EmailNotVerified = "EMAIL_NOT_VERIFIED";
    public const string InvalidCode = "INVALID_CODE";
    public const string EmailNotSetUp = "EMAIL_NOT_SET_UP";
    public const string InvalidIdToken = "INVALID_ID_TOKEN";
    public const string AccountExists = "ACCOUNT_EXISTS_WITH_OTHER_METHOD";
    public const string CredentialInUse = "CREDENTIAL_ALREADY_IN_USE";
    public const string ProviderAlreadyLinked = "PROVIDER_ALREADY_LINKED";
    public const string LastSignInMethod = "LAST_SIGN_IN_METHOD";
    public const string MfaRequired = "MFA_REQUIRED";
    public const string InvalidMfaCode = "INVALID_MFA_CODE";
    public const string MfaNotEnabled = "MFA_NOT_ENABLED";
    public const string MfaAlreadyEnabled = "MFA_ALREADY_ENABLED";
    /// <summary>The provider requires a second step (<c>RequireSecondStep</c>), and this sign-in had none: neither the provider's nor Winche's.</summary>
    public const string SecondStepRequired = "SECOND_STEP_REQUIRED";

    /// <summary>
    /// The shared kind of <paramref name="code"/>: on the wire, an auth error's <c>code</c> is this and its own code
    /// (<c>INVALID_CREDENTIALS</c>, …) is the <c>reason</c>.
    /// </summary>
    public static WincheErrorCode Kind(string code) => code switch
    {
        InvalidCredentials or InvalidRefreshToken or InvalidIdToken or InvalidCustomToken or MfaRequired or InvalidMfaCode or SecondStepRequired => WincheErrorCode.Unauthenticated,
        UserDisabled or Denied or EmailNotVerified => WincheErrorCode.PermissionDenied,
        UserNotFound => WincheErrorCode.NotFound,
        EmailExists or AccountExists or CredentialInUse or ProviderAlreadyLinked => WincheErrorCode.AlreadyExists,
        LockedOut or TooManyAttempts => WincheErrorCode.ResourceExhausted,
        NotEnabled or NotAnonymous or EmailNotSetUp or LastSignInMethod or MfaNotEnabled or MfaAlreadyEnabled or RequiresRecentSignIn => WincheErrorCode.FailedPrecondition,
        _ => WincheErrorCode.InvalidArgument,   // INVALID_EMAIL, WEAK_PASSWORD, INVALID_CLAIMS, INVALID_ARGUMENT, INVALID_CODE
    };
}
