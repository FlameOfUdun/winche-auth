using Winche.Auth.Email;
using Winche.Auth.Providers;

namespace Winche.Auth.Settings;

/// <summary>
/// The settings area <c>auth.signIn</c> (<c>o.UseSettings()</c>): Winche Auth's sign-in methods, providers, two-step
/// sign-in, sessions, lockout and email, as the console changes them. The code's options are the starting values.
/// </summary>
public sealed record WincheAuthSettings
{
    public const string Area = "auth.signIn";

    public EmailPasswordSettings EmailPassword { get; init; } = new();
    public bool Anonymous { get; init; }
    public EmailLinkSettings EmailLink { get; init; } = new();
    public TwoStepSettings TwoStep { get; init; } = new();
    public IReadOnlyList<SignInProviderSettings> Providers { get; init; } = [];
    public SessionSettings Sessions { get; init; } = new();
    public LockoutSettings Lockout { get; init; } = new();
    public EmailSettings Email { get; init; } = new();

    /// <summary>The settings as the code sets them.</summary>
    public static WincheAuthSettings From(WincheAuthOptions o) => new()
    {
        EmailPassword = o.EmailPasswordSignIn is { } ep ? new() { Enabled = true, MinLength = ep.MinLength, RequireVerifiedEmail = ep.RequireVerifiedEmail } : new(),
        Anonymous = o.AnonymousSignIn,
        EmailLink = o.EmailLinkSignIn is { } el ? new() { Enabled = true, LinkUrl = el.LinkUrl } : new(),
        TwoStep = o.MfaSettings is { } m ? new() { Enabled = true, Issuer = m.Issuer, RecoveryCodes = m.RecoveryCodes } : new(),
        Providers = [.. o.IdentityProviders.Select(p => new SignInProviderSettings
        {
            Name = p.Name, Kind = p.Kind, DisplayName = p.DisplayName, Authority = p.Authority, Audiences = [.. p.Audiences],
            UseSubjectAsUid = p.UseSubjectAsUid, CopiedClaims = [.. p.CopiedClaims],
            RequireSecondStep = p.RequireSecondStep, SecondStepAcrValues = [.. p.SecondStepAcrValues], CountsAsSecondStep = p.CountsAsSecondStep,
        })],
        Sessions = new() { AccessTokenMinutes = (int)o.AccessTokenLifetime.TotalMinutes, RefreshTokenDays = (int)o.RefreshTokenLifetime.TotalDays },
        Lockout = new() { MaxFailedSignIns = o.MaxFailedSignIns, LockoutMinutes = (int)o.LockoutDuration.TotalMinutes },
        Email = o.EmailSending is { } e ? new()
        {
            Enabled = true, AppName = e.AppName, ActionUrl = e.ActionUrl, SendVerificationOnSignUp = e.SendVerificationOnSignUp,
            MaxPerAddressPerHour = e.MaxPerAddressPerHour, VerifyLinkHours = (int)e.VerifyLinkLifetime.TotalHours, ResetLinkHours = (int)e.ResetLinkLifetime.TotalHours,
            Sender = e.LogLinksOnly ? "logLinks" : e.Smtp is not null ? "smtp" : "app", SendInBackground = e.SendInBackground,
            Smtp = e.Smtp is { } s ? new() { Host = s.Host, Port = s.Port, Security = s.Security, Username = s.Username, FromAddress = s.FromAddress, FromName = s.FromName } : null,
        } : new(),
    };

    /// <summary>
    /// Writes these settings onto the live options. Parts only code can give (claim mapping functions, test keys, an
    /// SMTP password set in code) are kept from <paramref name="code"/>'s providers and email of the same name.
    /// </summary>
    internal void ApplyTo(WincheAuthOptions target, CodeParts code)
    {
        target.EmailPasswordSignIn = EmailPassword.Enabled ? new EmailPasswordOptions { MinLength = EmailPassword.MinLength, RequireVerifiedEmail = EmailPassword.RequireVerifiedEmail } : null;
        target.AnonymousSignIn = Anonymous;
        target.EmailLinkSignIn = EmailLink.Enabled ? new EmailLinkOptions { LinkUrl = EmailLink.LinkUrl } : null;
        target.MfaSettings = TwoStep.Enabled
            ? new MfaOptions { Issuer = string.IsNullOrWhiteSpace(TwoStep.Issuer) ? null : TwoStep.Issuer, RecoveryCodes = TwoStep.RecoveryCodes, PendingLifetime = code.MfaPending }
            : null;
        target.ReplaceProviders([.. Providers.Select(p =>
        {
            var o = new IdentityProviderOptions
            {
                Name = p.Name, Kind = p.Kind, DisplayName = string.IsNullOrWhiteSpace(p.DisplayName) ? null : p.DisplayName, Authority = p.Authority ?? "",
                Audiences = [.. p.Audiences], UseSubjectAsUid = p.UseSubjectAsUid, CopiedClaims = [.. p.CopiedClaims],
                RequireSecondStep = p.RequireSecondStep, SecondStepAcrValues = [.. p.SecondStepAcrValues.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim())],
                CountsAsSecondStep = p.CountsAsSecondStep,
            };
            if (code.Providers.FirstOrDefault(c => c.Name == p.Name && c.Kind == p.Kind) is { } c)
            {
                o.SigningKeys = c.SigningKeys;
                o.AllowUnsignedTokensForTesting = c.AllowUnsignedTokensForTesting;
                o.KeycloakSync = c.KeycloakSync;   // set in code: kept when the console edits the provider
                if (c.Authority == o.Authority) o.Issuers = [.. c.Issuers];
            }
            if (o.KeycloakSync is null && p.KeycloakSync is { } ks)
            {
                var sync = new KeycloakSyncOptions
                {
                    ClientId = ks.ClientId, AdminServer = string.IsNullOrWhiteSpace(ks.AdminServer) ? null : ks.AdminServer.Trim(),
                    PollInterval = TimeSpan.FromSeconds(ks.PollSeconds), ReconcileInterval = TimeSpan.FromHours(ks.ReconcileHours),
                    ClientSecretName = KeycloakSyncSettings.SecretName(p.Name),
                };
                foreach (var (attribute, claim) in ks.Attributes) sync.MapAttribute(attribute, claim);
                o.KeycloakSync = sync;
            }
            WincheAuthOptions.KindDefaults(o);
            return o;
        })]);
        target.AccessTokenLifetime = TimeSpan.FromMinutes(Sessions.AccessTokenMinutes);
        target.RefreshTokenLifetime = TimeSpan.FromDays(Sessions.RefreshTokenDays);
        target.MaxFailedSignIns = Lockout.MaxFailedSignIns;
        target.LockoutDuration = TimeSpan.FromMinutes(Lockout.LockoutMinutes);
        target.EmailSending = Email.Enabled ? new AuthEmailOptions
        {
            AppName = Email.AppName, ActionUrl = string.IsNullOrWhiteSpace(Email.ActionUrl) ? null : Email.ActionUrl,
            SendVerificationOnSignUp = Email.SendVerificationOnSignUp, MaxPerAddressPerHour = Email.MaxPerAddressPerHour,
            VerifyLinkLifetime = TimeSpan.FromHours(Email.VerifyLinkHours), ResetLinkLifetime = TimeSpan.FromHours(Email.ResetLinkHours),
            SignInLinkLifetime = code.SignInLinkLifetime, UndoLinkLifetime = code.UndoLinkLifetime,
            LogLinksOnly = Email.Sender == "logLinks", LogWithLinks = code.LogWithLinks, SendInBackground = Email.SendInBackground,
            Smtp = Email.Sender == "smtp" && Email.Smtp is { } s ? new SmtpOptions
            {
                Host = s.Host, Port = s.Port, Security = s.Security, Username = string.IsNullOrWhiteSpace(s.Username) ? null : s.Username,
                FromAddress = s.FromAddress, FromName = string.IsNullOrWhiteSpace(s.FromName) ? null : s.FromName,
                Password = code.SmtpPassword is { } pw && code.SmtpHost == s.Host ? pw : null,
            } : null,
        } : null;
    }

    /// <summary>What's wrong with these settings, in sentences.</summary>
    public IReadOnlyList<string> Problems(CodeParts code)
    {
        var problems = new List<string>();
        if (Sessions.AccessTokenMinutes is < 1 or > 1440) problems.Add("Access tokens last 1 minute to 24 hours.");
        if (Sessions.RefreshTokenDays is < 1 or > 3650) problems.Add("Sessions last 1 day to 10 years.");
        if (Lockout.MaxFailedSignIns > 100) problems.Add("Lock out after at most 100 failed sign-ins.");
        if (Lockout.LockoutMinutes > 1440 * 30) problems.Add("Lockouts last at most 30 days.");
        if (TwoStep.RecoveryCodes is < 1 or > 50) problems.Add("Give 1 to 50 recovery codes.");
        if (Email.MaxPerAddressPerHour is < 1 or > 100) problems.Add("Send 1 to 100 emails per address per hour.");
        if (Email.VerifyLinkHours is < 1 or > 720 || Email.ResetLinkHours is < 1 or > 72) problems.Add("Verify links last 1–720 hours, reset links 1–72 hours.");
        if (Email.Enabled && Email.Sender is not ("app" or "smtp" or "logLinks")) problems.Add("Email is sent by the app, over SMTP, or only logged (logLinks).");
        if (Email.Enabled && Email.Sender == "smtp" && Email.Smtp is null) problems.Add("Fill in the SMTP server.");
        if (Email.Enabled && Email.ActionUrl is { Length: > 0 } au && !Uri.TryCreate(au, UriKind.Absolute, out _)) problems.Add("The action page must be a full address.");
        foreach (var p in Providers)
        {
            if (p.Kind is not ("google" or "apple" or "oidc")) problems.Add($"Provider '{p.Name}': the kind is google, apple or oidc.");
            if (string.IsNullOrWhiteSpace(p.Name) || p.Name.Length > 40 || p.Name.Any(c => !char.IsAsciiLetterLower(c) && !char.IsAsciiDigit(c) && c is not '-' and not '_'))
                problems.Add($"Provider '{p.Name}': a name is lower-case letters, digits, - and _.");
            else if (p.Name is "password" or "anonymous" or "emailLink" or "custom") problems.Add($"The provider name '{p.Name}' is taken.");
            if (p.KeycloakSync is { } ks)
            {
                if (p.Kind != "oidc" || KeycloakRealm.From(p.Authority ?? "", ks.AdminServer) is null)
                    problems.Add($"Provider '{p.Name}': Keycloak sync needs an OpenID Connect provider whose address is a Keycloak realm (…/realms/<realm>).");
                if (string.IsNullOrWhiteSpace(ks.ClientId)) problems.Add($"Provider '{p.Name}': give the Keycloak sync's client id.");
                if (ks.PollSeconds is < 2 or > 3600 || ks.ReconcileHours is < 1 or > 24 * 30) problems.Add($"Provider '{p.Name}': read events every 2 s to 1 h, compare everyone every 1 hour to 30 days.");
            }
        }
        if (problems.Count > 0) return problems;
        var trial = new WincheAuthOptions();
        ApplyTo(trial, code);
        return trial.Problems();
    }

    /// <summary>What only the app's code can give, kept when settings are applied.</summary>
    public sealed record CodeParts(IReadOnlyList<IdentityProviderOptions> Providers, TimeSpan MfaPending, TimeSpan SignInLinkLifetime, TimeSpan UndoLinkLifetime,
        string? SmtpHost, string? SmtpPassword, bool LogWithLinks = true)
    {
        internal static CodeParts From(WincheAuthOptions o) => new(o.IdentityProviders, o.MfaSettings?.PendingLifetime ?? TimeSpan.FromMinutes(5),
            o.EmailSending?.SignInLinkLifetime ?? TimeSpan.FromHours(1), o.EmailSending?.UndoLinkLifetime ?? TimeSpan.FromDays(7),
            o.EmailSending?.Smtp?.Host, o.EmailSending?.Smtp?.Password, o.EmailSending?.LogWithLinks ?? true);
    }
}

public sealed record EmailPasswordSettings
{
    public bool Enabled { get; init; }
    public int MinLength { get; init; } = 10;
    public bool RequireVerifiedEmail { get; init; }
}

public sealed record EmailLinkSettings
{
    public bool Enabled { get; init; }
    public string LinkUrl { get; init; } = "";
}

public sealed record TwoStepSettings
{
    public bool Enabled { get; init; }
    public string? Issuer { get; init; }
    public int RecoveryCodes { get; init; } = 10;
}

public sealed record SignInProviderSettings
{
    public string Name { get; init; } = "";
    /// <summary>google, apple or oidc.</summary>
    public string Kind { get; init; } = "oidc";
    public string? DisplayName { get; init; }
    /// <summary>The provider's address (Google's and Apple's are filled in).</summary>
    public string? Authority { get; init; }
    /// <summary>The app's client ids at the provider: its ID tokens must be for one of them.</summary>
    public IReadOnlyList<string> Audiences { get; init; } = [];
    public bool UseSubjectAsUid { get; init; }
    public IReadOnlyList<string> CopiedClaims { get; init; } = [];
    /// <summary>Every sign-in with it needs a second step, the provider's or Winche's (<see cref="IdentityProviderOptions.RequireSecondStep"/>).</summary>
    public bool RequireSecondStep { get; init; }
    /// <summary>Its sign-in counts as a second step on its own (<see cref="IdentityProviderOptions.CountsAsSecondStep"/>).</summary>
    public bool CountsAsSecondStep { get; init; }
    /// <summary><c>acr</c> values that mean the provider checked a second step (<see cref="IdentityProviderOptions.SecondStepAcrValues"/>).</summary>
    public IReadOnlyList<string> SecondStepAcrValues { get; init; } = [];

    /// <summary>
    /// Keeps its users in step with Keycloak (a Keycloak realm's provider): see <see cref="IdentityProviderOptions.SyncFromKeycloak"/>.
    /// Its client secret is the secret <see cref="KeycloakSyncSettings.SecretName"/>. A sync set in code wins.
    /// </summary>
    public KeycloakSyncSettings? KeycloakSync { get; init; }
}

/// <summary>A provider's Keycloak sync, as settings (<see cref="KeycloakSyncOptions"/>).</summary>
public sealed record KeycloakSyncSettings
{
    /// <summary>A confidential client with a service account holding view-users and view-events.</summary>
    public string ClientId { get; init; } = "";
    /// <summary>Where the server reaches Keycloak, when not at the provider's authority.</summary>
    public string? AdminServer { get; init; }
    public int PollSeconds { get; init; } = 10;
    public int ReconcileHours { get; init; } = 24;
    /// <summary>Keycloak user attributes kept as custom claims: attribute name → claim name.</summary>
    public IReadOnlyDictionary<string, string> Attributes { get; init; } = new Dictionary<string, string>();

    /// <summary>The secret store's name for the sync client's secret of the provider <paramref name="provider"/>.</summary>
    public static string SecretName(string provider) => $"auth.provider.{provider}.keycloakSync.clientSecret";
}

public sealed record SessionSettings
{
    public int AccessTokenMinutes { get; init; } = 15;
    public int RefreshTokenDays { get; init; } = 60;
}

public sealed record LockoutSettings
{
    public int MaxFailedSignIns { get; init; } = 5;
    public int LockoutMinutes { get; init; } = 15;
}

public sealed record EmailSettings
{
    public bool Enabled { get; init; }
    public string AppName { get; init; } = "";
    public string? ActionUrl { get; init; }
    public bool SendVerificationOnSignUp { get; init; } = true;
    public int MaxPerAddressPerHour { get; init; } = 5;
    public int VerifyLinkHours { get; init; } = 24;
    public int ResetLinkHours { get; init; } = 1;
    /// <summary>app (the app's IAuthEmailSender), smtp, or logLinks (local only).</summary>
    public string Sender { get; init; } = "app";
    public SmtpSettings? Smtp { get; init; }
    /// <summary>Send sign-in-link and password-reset emails after answering (default), so how long the answer takes doesn't tell whether the address has an account.</summary>
    public bool SendInBackground { get; init; } = true;
}

public sealed record SmtpSettings
{
    public string Host { get; init; } = "";
    public int Port { get; init; } = 587;
    public string Security { get; init; } = "startTls";
    public string? Username { get; init; }
    public string FromAddress { get; init; } = "";
    public string? FromName { get; init; }
}
