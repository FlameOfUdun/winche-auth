namespace Winche.Auth;

/// <summary>How Winche Auth signs users in and issues tokens. Set with <c>services.AddWincheAuth(o => …)</c>.</summary>
public sealed class WincheAuthOptions
{
    /// <summary>The PostgreSQL database that holds the users, sessions and signing keys (tables <c>auth_*</c>).</summary>
    public string ConnectionString { get; set; } = "";

    /// <summary>
    /// The token issuer (<c>iss</c>): your API's public base URL, e.g. <c>https://api.example.com</c>. Other services
    /// can check Winche tokens from <c>{Issuer}/.well-known/openid-configuration</c>.
    /// </summary>
    public string Issuer { get; set; } = "";

    /// <summary>Where uploaded photos are served, under the issuer: set by MapWincheAuth from its prefix.</summary>
    internal string PhotosPath { get; set; } = "/auth/v1/photos";

    /// <summary>An uploaded photo's address, from today's issuer and path.</summary>
    internal string PhotoAddress(string photoId) => $"{Issuer.TrimEnd('/')}{PhotosPath}/{photoId}";

    /// <summary>
    /// The user's photo address: an uploaded one is rebuilt from its id, so it follows a new issuer or path; any other
    /// is the link as kept.
    /// </summary>
    internal string? PhotoUrlOf(Data.WincheUser u) =>
        u is { PhotoSource: "upload", PhotoUrl: { } url } && url.LastIndexOf('/') is var i and >= 0 && i < url.Length - 1
            ? PhotoAddress(url[(i + 1)..]) : u.PhotoUrl;

    /// <summary>The token audience (<c>aud</c>); the issuer when not set.</summary>
    public string? Audience { get; set; }

    /// <summary>How long an access token is valid (default 15 minutes). Disabling a user takes effect within this time.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long a session lasts without being used (default 60 days); each refresh renews it.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(60);

    /// <summary>A new signing key takes over when the active one is this old (default 90 days).</summary>
    public TimeSpan KeyRotationInterval { get; set; } = TimeSpan.FromDays(90);

    /// <summary>
    /// How long a new signing key is published (in <c>/.well-known/jwks.json</c>) before it signs anything, so services
    /// that cache the key set know it by then (default one day; at most half <see cref="KeyRotationInterval"/>).
    /// </summary>
    public TimeSpan KeyPublishAhead { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// A secret (32+ characters, from configuration or a secret store) that encrypts the signing keys' private parts in
    /// the database. Not needed with a Winche master key (<c>AddWincheConfig</c>), which one is derived from; one of
    /// the two is required: keys are never stored unencrypted.
    /// </summary>
    public string? KeyEncryptionSecret { get; set; }

    /// <summary>Sign-in attempts that fail in a row before an account is locked (default 5).</summary>
    public int MaxFailedSignIns { get; set; } = 5;

    /// <summary>How long a locked account stays locked (default 15 minutes).</summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Email and password sign-in, when turned on with <see cref="EmailPassword"/>.</summary>
    public EmailPasswordOptions? EmailPasswordSignIn { get; internal set; }

    /// <summary>How email is sent, when turned on with <see cref="Email"/>.</summary>
    public Email.AuthEmailOptions? EmailSending { get; internal set; }

    /// <summary>Email-link sign-in, when turned on with <see cref="EmailLink"/>.</summary>
    public Email.EmailLinkOptions? EmailLinkSignIn { get; internal set; }

    /// <summary>
    /// Turns on email: verify-email, reset-password and email-change links (and sign-in links with <see cref="EmailLink"/>).
    /// Register an <see cref="Email.IAuthEmailSender"/> to send them, or use <c>e.LogLinks()</c> locally.
    /// </summary>
    public WincheAuthOptions Email(Action<Email.AuthEmailOptions>? configure = null)
    {
        var o = new Email.AuthEmailOptions();
        configure?.Invoke(o);
        EmailSending = o;
        return this;
    }

    /// <summary>Turns on sign-in with a one-time link sent by email (no password). Needs <see cref="Email"/>.</summary>
    public WincheAuthOptions EmailLink(Action<Email.EmailLinkOptions> configure)
    {
        var o = new Email.EmailLinkOptions();
        configure(o);
        EmailLinkSignIn = o;
        return this;
    }

    private volatile IReadOnlyList<Providers.IdentityProviderOptions> _providers = [];

    /// <summary>The sign-in providers whose ID tokens are exchanged (Google, Apple, OpenID Connect).</summary>
    public IReadOnlyList<Providers.IdentityProviderOptions> IdentityProviders => _providers;

    internal void ReplaceProviders(IReadOnlyList<Providers.IdentityProviderOptions> providers) => _providers = providers;

    /// <summary>
    /// Lets the console change these settings (sign-in methods, providers, two-step sign-in, token lifetimes, lockout,
    /// email) without a deploy: what's set here becomes the starting values. Needs <c>AddWincheConfig(…)</c> to save
    /// changes; without it the values here apply. Hooks (<see cref="Events"/>) stay in code.
    /// </summary>
    public WincheAuthOptions UseSettings()
    {
        SettingsEnabled = true;
        return this;
    }

    /// <summary>Whether the console may change these settings (<see cref="UseSettings"/>).</summary>
    public bool SettingsEnabled { get; private set; }

    /// <summary>Sign in with Google: the app signs in with Google and exchanges the ID token. Set your client ids as audiences.</summary>
    public WincheAuthOptions Google(Action<Providers.IdentityProviderOptions> configure) =>
        AddProvider("google", "google", configure, p =>
        {
            p.Authority = string.IsNullOrEmpty(p.Authority) ? "https://accounts.google.com" : p.Authority;
            if (p.Issuers.Count == 0) p.Issuers = ["https://accounts.google.com", "accounts.google.com"];
            p.DisplayName ??= "Google";
        });

    /// <summary>Sign in with Apple: the app signs in with Apple and exchanges the ID token. Set your bundle or service ids as audiences.</summary>
    public WincheAuthOptions Apple(Action<Providers.IdentityProviderOptions> configure) =>
        AddProvider("apple", "apple", configure, p =>
        {
            p.Authority = string.IsNullOrEmpty(p.Authority) ? "https://appleid.apple.com" : p.Authority;
            p.DisplayName ??= "Apple";
        });

    /// <summary>Sign in with any OpenID Connect provider (Keycloak, Auth0, Entra ID, …) by exchanging its ID tokens.</summary>
    public WincheAuthOptions OpenIdConnect(string name, Action<Providers.IdentityProviderOptions> configure) =>
        AddProvider(name, "oidc", configure, _ => { });

    private WincheAuthOptions AddProvider(string name, string kind, Action<Providers.IdentityProviderOptions> configure, Action<Providers.IdentityProviderOptions> defaults)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 40 || name.Any(c => !char.IsAsciiLetterLower(c) && !char.IsAsciiDigit(c) && c is not '-' and not '_'))
            throw new ArgumentException("A provider's name is lower-case letters, digits, - and _.", nameof(name));
        if (name is "password" or "anonymous" or "emailLink" or "custom" || _providers.Any(p => p.Name == name))
            throw new ArgumentException($"The provider name '{name}' is taken.", nameof(name));
        var p = new Providers.IdentityProviderOptions { Name = name, Kind = kind };
        configure(p);
        defaults(p);
        _providers = [.. _providers, p];
        return this;
    }

    /// <summary>Google's and Apple's well-known addresses, for providers made from settings.</summary>
    internal static void KindDefaults(Providers.IdentityProviderOptions p)
    {
        switch (p.Kind)
        {
            case "google":
                p.Authority = string.IsNullOrEmpty(p.Authority) ? "https://accounts.google.com" : p.Authority;
                if (p.Issuers.Count == 0) p.Issuers = ["https://accounts.google.com", "accounts.google.com"];
                p.DisplayName ??= "Google";
                break;
            case "apple":
                p.Authority = string.IsNullOrEmpty(p.Authority) ? "https://appleid.apple.com" : p.Authority;
                p.DisplayName ??= "Apple";
                break;
        }
    }

    /// <summary>Two-step sign-in, when turned on with <see cref="Mfa"/>.</summary>
    public MfaOptions? MfaSettings { get; internal set; }

    /// <summary>
    /// Turns on two-step sign-in: users may add an authenticator app (TOTP); then every sign-in also asks for a code
    /// from it (or a recovery code). Their tokens carry <c>mfa: true</c>, which rules can require.
    /// </summary>
    public WincheAuthOptions Mfa(Action<MfaOptions>? configure = null)
    {
        var o = new MfaOptions();
        configure?.Invoke(o);
        MfaSettings = o;
        return this;
    }

    /// <summary>Whether anonymous (guest) sign-in is on (<see cref="Anonymous"/>).</summary>
    public bool AnonymousSignIn { get; internal set; }

    /// <summary>Your code's say in sign-up and sign-in.</summary>
    public WincheAuthEvents Events { get; } = new();

    /// <summary>
    /// Custom claims anyone signed in may see in a user's public profile, which the database's <c>expand</c> returns for
    /// <c>user:</c> paths (besides uid, display name and photo). None by default.
    /// </summary>
    public IList<string> PublicProfileClaims { get; } = new List<string>();

    /// <summary>How user events reach <see cref="IWincheAuthObserver"/>s (and the app's webhooks and triggers).</summary>
    public WincheAuthEventOptions UserEvents { get; } = new();

    /// <summary>Turns on sign-up and sign-in with an email address and a password.</summary>
    public WincheAuthOptions EmailPassword(Action<EmailPasswordOptions>? configure = null)
    {
        var o = new EmailPasswordOptions();
        configure?.Invoke(o);
        EmailPasswordSignIn = o;
        return this;
    }

    /// <summary>Turns on anonymous sign-in: a guest user with a uid, upgraded later by linking an email and password.</summary>
    public WincheAuthOptions Anonymous()
    {
        AnonymousSignIn = true;
        return this;
    }

    internal string EffectiveAudience => string.IsNullOrEmpty(Audience) ? Issuer : Audience;

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(ConnectionString)) throw new InvalidOperationException("Winche Auth: set ConnectionString.");
        if (string.IsNullOrWhiteSpace(Issuer)) throw new InvalidOperationException("Winche Auth: set Issuer (your API's public base URL).");
        if (KeyEncryptionSecret is { Length: < 32 }) throw new InvalidOperationException("Winche Auth: KeyEncryptionSecret must be at least 32 characters.");
        if (Problems().FirstOrDefault() is { } problem) throw new InvalidOperationException($"Winche Auth: {problem}");
    }

    /// <summary>What's wrong with the changeable settings, in sentences (shared by startup and the console).</summary>
    internal IReadOnlyList<string> Problems()
    {
        var problems = new List<string>();
        if (AccessTokenLifetime <= TimeSpan.Zero || RefreshTokenLifetime <= AccessTokenLifetime)
            problems.Add("Sessions must last longer than access tokens (RefreshTokenLifetime > AccessTokenLifetime).");
        if (MaxFailedSignIns < 1 || LockoutDuration <= TimeSpan.Zero) problems.Add("Lockout needs at least 1 failed sign-in and a duration.");
        if (EmailPasswordSignIn is { MinLength: < 6 }) problems.Add("Passwords must be at least 6 characters.");
        if (EmailSending is { AppName: var appName } && string.IsNullOrWhiteSpace(appName))
            problems.Add("Give the app's name for the emails (Email(e => e.AppName = …)).");
        if (EmailSending?.Smtp is { } smtp && smtp.Problems() is { Count: > 0 } sp) problems.AddRange(sp);
        foreach (var p in _providers)
            try { p.Validate(); }
            catch (InvalidOperationException ex) { problems.Add(ex.Message.Replace("Winche Auth provider", "Provider")); }
        if (_providers.GroupBy(p => p.Name).FirstOrDefault(g => g.Count() > 1) is { } twice) problems.Add($"Two providers are named '{twice.Key}'.");
        if (EmailLinkSignIn is not null && EmailSending is null) problems.Add("Email-link sign-in needs email turned on to send the links.");
        if (EmailLinkSignIn is not null && !Uri.TryCreate(EmailLinkSignIn.LinkUrl, UriKind.Absolute, out _))
            problems.Add("Email-link sign-in needs the link address: the app's page or deep link that finishes the sign-in.");
        if (EmailPasswordSignIn is { RequireVerifiedEmail: true } && EmailSending is null)
            problems.Add("Requiring a verified email needs email turned on to send the verify links.");
        return problems;
    }
}

/// <summary>Two-step sign-in.</summary>
public sealed class MfaOptions
{
    /// <summary>The name authenticator apps show beside the code ("Clinic"); the email app name, else the issuer.</summary>
    public string? Issuer { get; set; }

    /// <summary>How long the first step stays good while the user finds their code (default 5 minutes).</summary>
    public TimeSpan PendingLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Recovery codes made at enrolment (default 10); each works once.</summary>
    public int RecoveryCodes { get; set; } = 10;
}

/// <summary>Email and password rules.</summary>
public sealed class EmailPasswordOptions
{
    /// <summary>The shortest password allowed (default 10). Length is the only rule: no forced character classes.</summary>
    public int MinLength { get; set; } = 10;

    /// <summary>
    /// Users must verify their email before they can sign in with a password (default false). Sign-up then creates the
    /// account, sends the link and answers <c>EMAIL_NOT_VERIFIED</c> instead of signing in.
    /// </summary>
    public bool RequireVerifiedEmail { get; set; }
}

/// <summary>Who is signing up or in, for <see cref="WincheAuthEvents"/>.</summary>
public sealed record AuthAttempt(string? Email, string Provider, string? IpAddress);

/// <summary>
/// A check on sign-ups and sign-ins, registered in DI (any number; Winche.Functions registers one for
/// <c>users.beforeCreate</c> / <c>users.beforeSignIn</c>). Runs after <see cref="WincheAuthEvents"/>' own hooks; throw
/// <see cref="AuthDeniedException"/> or <see cref="WincheDeniedException"/> to refuse with a message for the user.
/// </summary>
public interface IWincheAuthGate
{
    /// <summary>Before a user is created (sign-up, anonymous or provider sign-in, an admin creating one).</summary>
    Task BeforeCreateAsync(AuthAttempt attempt, CancellationToken ct);

    /// <summary>Before a sign-in succeeds (after its credentials check out).</summary>
    Task BeforeSignInAsync(WincheUserInfo user, AuthAttempt attempt, CancellationToken ct);
}

/// <summary>Hooks into sign-up and sign-in. Throw <see cref="AuthDeniedException"/> to refuse.</summary>
public sealed class WincheAuthEvents
{
    /// <summary>Before a user is created (sign-up, anonymous sign-in or an admin creating one).</summary>
    public Func<AuthAttempt, IServiceProvider, Task>? BeforeCreate { get; set; }

    /// <summary>After a user is created, e.g. to create their <c>users/{uid}</c> document.</summary>
    public Func<WincheUserInfo, IServiceProvider, Task>? AfterCreate { get; set; }

    /// <summary>Before a sign-in succeeds (after the password checks out), e.g. to block a user for a reason of your own.</summary>
    public Func<WincheUserInfo, AuthAttempt, IServiceProvider, Task>? BeforeSignIn { get; set; }
}
