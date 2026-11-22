# Winche Auth

Authentication for the Winche stack: users sign up and in through a REST API, and get short-lived
**access tokens** that Winche.Database, Winche.Storage and your own endpoints accept, plus **refresh tokens** for new ones.
Or keep your own identity provider and trust its tokens directly. You can do both at once.

- **Users** on ASP.NET Core Identity and PostgreSQL (tables `auth_*`, migrated on start): email and password, anonymous
  guests, lockout after repeated failures.
- **Tokens** are ES256 JWTs signed by Winche, with the public keys at `/.well-known/jwks.json`. Keys rotate every 90
  days; the next key is published a day before it signs (`KeyPublishAhead`), so services caching the key set know it in
  time, and a retired key still checks the tokens it signed. One server at a time rotates (a Postgres advisory lock).
  Private keys are always stored encrypted: set `KeyEncryptionSecret`, or a master key with `AddWincheConfig`; without
  either it won't start. Keys left unencrypted by an earlier version are encrypted on start.
- **Refresh tokens** are replaced on every use; a replaced one presented again ends the session (it was copied).
- **Trusted issuers**: accept Keycloak, Auth0, Entra ID or any OpenID Connect provider's tokens as they are.

| Package | |
|---|---|
| `Winche.Auth` | users, sessions, signing keys, `IWincheAuth` |
| `Winche.Auth.AspNetCore` | the REST API, the `Winche` authentication scheme, `WincheClaims` |

## Install

```sh
dotnet add package Winche.Auth.AspNetCore   # the /auth/v1 endpoints and token checking; brings Winche.Auth
```

## Setup

```csharp
builder.Services.AddWincheAuth(o =>
{
    o.ConnectionString = connectionString;
    o.Issuer = "https://api.example.com";               // your API's public base URL
    o.KeyEncryptionSecret = builder.Configuration["WincheAuth:KeySecret"];   // encrypts the signing keys at rest
    o.EmailPassword(p => p.MinLength = 10);
    o.Anonymous();
});

builder.Services.AddAuthentication().AddWincheTokens(t => t.TrustWincheAuth());

// Who is calling, for every Winche package (rules' request.auth, logs, functions' ctx.auth): the verified token.
builder.Services.AddWincheCaller(WincheClaims.FromAsync);

var app = builder.Build();
app.UseAuthentication();
app.UseWincheCaller();
app.MapWincheAuth();                                    // /auth/v1/… and /.well-known/…
```

**From the console.** With `o.UseSettings()` and `AddWincheConfig` (Winche.Core), the sign-in methods, sessions,
lockout and email settings become the settings area `auth.signIn`: the code's values are where they start, and the Winche
console changes them (Authentication → Settings), applied without a restart, with earlier versions to restore.

`AddWincheTokens` makes `Winche` the default authentication scheme unless the app already set one. If it did, forward to
`WincheAuthDefaults.Scheme`, or leave it: `WincheClaims.FromAsync` authenticates with it on its own.

User events (created, signed in, claims changed, …) are published to the app's change sinks — Winche.Webhooks, and
through it Winche.Functions' triggers — with no extra package; setting claims when a user changes is a function with
that trigger. Without `KeyEncryptionSecret`, its signing keys are encrypted with a key derived from the project's
master key (`AddWincheConfig`).

## The API (`/auth/v1`)

| | |
|---|---|
| `POST signUp` `{email, password, displayName?}` | a new user, signed in |
| `POST signIn` `{email, password}` | |
| `POST signIn/anonymous` | a guest user with a uid |
| `POST token` `{refreshToken}` | new tokens; the refresh token is replaced |
| `POST signOut` `{refreshToken}` | ends that session |
| `POST link/password` `{email, password}` | turns the signed-in anonymous user into one with a password, same uid |
| `GET me`, `PATCH me` `{displayName?, photoUrl?}`, `DELETE me` | the signed-in user (a patch: what's left out stays; `null` clears) |
| `POST me/photo` (the image as the body), `DELETE me/photo` | the signed-in user's photo, kept by Winche Auth (below) |
| `GET photos/{id}` | an uploaded photo: open to anyone with its address, cached for a day |
| `POST me/password` `{currentPassword, newPassword}` | other sessions end; this one gets new tokens |
| `POST sendVerification` | emails the signed-in user a verify link |
| `POST sendPasswordReset` `{email}` | emails a reset link (the same answer whether or not the address has an account) |
| `POST resetPassword` `{code, newPassword}` | every session ends |
| `POST sendSignInLink` `{email}`, `POST signIn/link` `{code}` | email-link sign-in; the first use makes the account |
| `POST me/email` `{newEmail}` | emails the new address; the change happens when it's opened |
| `POST action/check`, `POST action/apply` `{code}` | what a link's code is for; use a verify, change or undo code |
| `POST signIn/idp` `{provider, idToken, nonce?}` | Google, Apple or an OpenID Connect provider's ID token for Winche tokens |
| `POST link/idp` `{provider, idToken, nonce?}`, `POST unlink` `{provider}` | add or remove a sign-in method on the signed-in user |
| `GET providers` | what a sign-in screen can offer |
| `POST signIn/custom` `{token}` | a custom token from your server (`CreateCustomTokenAsync`) |
| `POST providers/{name}/backchannel-logout` (form `logout_token`) | the provider's back-channel logout, below |
| `POST providers/{name}/changed` | the Keycloak sync's webhook, below |
| `POST signIn/mfa` `{mfaToken, code}` | the second step, after a sign-in answered `MFA_REQUIRED` |
| `GET me/mfa`, `POST me/mfa/totp/start`, `POST me/mfa/totp/confirm` `{code}` | add an authenticator app |
| `POST me/mfa/recoveryCodes` `{code}`, `POST me/mfa/disable` `{code}` | new recovery codes; turn it off |

Sign-ins return `{accessToken, expiresIn, expiresAt, refreshToken, user}`. Failures return
the error every Winche API sends, `{error: {code, message, reason, details?}}`: `code` is the shared kind and `reason`
auth's own, e.g. `unauthenticated`/`INVALID_CREDENTIALS` (401: a wrong password and an unknown email look the same),
`already-exists`/`EMAIL_EXISTS` (409), `invalid-argument`/`WEAK_PASSWORD` or `INVALID_EMAIL` (400),
`permission-denied`/`USER_DISABLED` (403), `resource-exhausted`/`LOCKED_OUT` or `TOO_MANY_ATTEMPTS` (429),
`unauthenticated`/`INVALID_REFRESH_TOKEN` (401).

### Photos

A user's photo is `photoUrl`, one of three things (`photoSource` says which):

- **`upload`:** a small image Winche Auth keeps, from `POST me/photo` or `SetPhotoAsync` (JPEG, PNG or WebP by its
  own bytes, whatever the request says; at most 100 KB: shrink it first, 256 × 256 is plenty). It's served at
  `/auth/v1/photos/<id>` (under whatever prefix the host maps, on the issuer, so it follows a new address), an id that
  can't be guessed and is new with each photo, so it's open to `<img>` tags (which can't send a token). Caches may keep
  it a day. Removing it, or deleting the user, removes it. It's kept as sent: strip what the image carries (a phone
  photo's location, say) before uploading; shrinking it on a canvas does.
- **`provider:<name>`:** a sign-in provider's picture (Google's, an OpenID Connect provider's `picture`), a link to
  them, refreshed at each sign-in while it's theirs. It's never downloaded. Unlinking the provider takes it away.
- **`link`:** a link set by the app (`PATCH me`) or an admin; it replaces an upload, and sign-ins no longer change it.

Whichever was chosen last wins: an upload or a link stays through sign-ins; removing an upload lets the provider's
picture back at the next sign-in.

## Google, Apple and OpenID Connect

The app signs in with the provider itself (Google Sign-In, Sign in with Apple, an OpenID Connect login) and posts the
**ID token** to `signIn/idp`; Winche checks it against the provider's keys and signs the user in, making them a Winche
user the first time.

```csharp
o.Google(g => g.Audiences = ["…apps.googleusercontent.com"]);        // your client ids
o.Apple(a => a.Audiences = ["com.example.app"]);                       // bundle or service ids
o.OpenIdConnect("keycloak", k =>
{
    k.Authority = "https://auth.example.com/realms/example";
    k.Audiences = ["clinic-app"];
    k.UseSubjectAsUid = true;      // keep Keycloak's ids as Winche uids: users/{uid} documents still match
    k.MapClaims("role", "org");    // copied into custom claims at each sign-in
});
```

- **Same email, different method:** if an account already has the provider's (verified) email, sign-in answers
  `ACCOUNT_EXISTS_WITH_OTHER_METHOD`: the user signs in the old way and links the provider (`link/idp`). Merging silently
  would hand the account to whoever controls the provider account.
- **Linking:** a guest who links a provider keeps their uid. One account per provider per user; a provider account
  links to one user (`CREDENTIAL_ALREADY_IN_USE`). The last way to sign in can't be unlinked.
- **Nonce:** send the raw `nonce` you gave the provider; Winche accepts it as sent (Google) or as its SHA-256 (Apple).
- **Claims from the provider** (`MapClaims`) refresh at each sign-in through it, and, with the Keycloak sync below, as
  soon as they change there.

### Signing out at the provider (back-channel logout)

A provider that supports OpenID Connect Back-Channel Logout (Keycloak, Entra ID, Okta…) can end Winche sessions when
someone signs out there. Register `<your API>/auth/v1/providers/<name>/backchannel-logout` as the client's back-channel
logout URL. Its logout token (checked: signed by the provider, for one of the provider's audiences, recent, about a
sign-out) ends the session it names (`sid`: each session remembers the ID token's `sid`), or every session the person it
names (`sub`) started through that provider. `IWincheAuth.EndProviderSessionsAsync` does the same from your own code.

### Keeping Keycloak users in step

Without it, a user disabled in Keycloak keeps their Winche sessions until they next sign in there. With it, Winche
follows Keycloak, one way: it only reads Keycloak, never writes to it.

```csharp
o.OpenIdConnect("keycloak", k =>
{
    k.Authority = "https://id.example.com/realms/example";
    k.Audiences = ["clinic-app"];
    k.MapClaims("role", "realm_access");
    k.SyncFromKeycloak(s =>
    {
        s.ClientId = "winche-sync";                               // a confidential client with a service account
        s.ClientSecret = builder.Configuration["Keycloak:SyncSecret"];
        s.WebhookSecret = builder.Configuration["Keycloak:WebhookSecret"];   // optional, below
        s.MapAttribute("department", "dept").MapAttribute("wards");    // user attributes as claims
    });
});
```

Set in settings instead (the console's Authentication → Sign-in method, with `o.UseSettings()`): the provider's
`keycloakSync` (`KeycloakSyncSettings`: `ClientId`, `AdminServer`, `PollSeconds`, `ReconcileHours`, `Attributes`), its
client secret kept encrypted in the app's secret store (Winche.Secrets) as `auth.provider.<name>.keycloakSync.clientSecret`
(`KeycloakSyncSettings.SecretName(name)`). A sync set in code wins.

| In Keycloak | In Winche |
|---|---|
| Disabled | Disabled, every session ended (`disabled` event) |
| Enabled again | Enabled, if the sync disabled them (never one an admin disabled here) |
| Deleted | Disabled and unlinked from Keycloak; the account and its data stay for an admin to decide |
| Name, email, email verified | Updated (an email another account here has is left, with a warning in the logs) |
| Roles, groups, attributes | The copied claims (`s.Claims`, else `MapClaims`): `realm_access` from realm roles, `groups` from group paths, anything else from the user attribute of that name |

**Custom attributes.** `s.MapAttribute(attribute, claim)` keeps a Keycloak user attribute as a custom claim (one value
a string, several a list, none removes it). It's read from Keycloak itself, at each sign-in through it and whenever it
changes there, so the first token already has it and Keycloak needs no token mapper. If Keycloak doesn't answer at
sign-in, the sign-in still works and the sync fills it in later. Keycloak only keeps attributes its user profile allows:
under *Realm settings → User profile* declare them, or set *Unmanaged attributes* to *Only administrators can edit*
(users then can't see or change them).

Only users who have signed in through the provider are synced: they're matched by their Keycloak id, never by email.
Passwords and Keycloak's own two-step setup stay in Keycloak.

- **How:** every `PollInterval` (10 seconds) one server (an advisory lock) reads Keycloak's saved events since the last
  run: user events (`UPDATE_PROFILE`, `UPDATE_EMAIL`, `VERIFY_EMAIL`, `DELETE_ACCOUNT`) and admin events on users, their
  role mappings and group memberships. It then re-reads each named user, so applying one twice is harmless. Every
  `ReconcileInterval` (daily) it compares every linked user, catching what events miss: a role changed on a group or a
  composite role, events that expired or weren't saved.
- **In Keycloak:** in the realm's settings turn on *Save events* (with those types) and *Save admin events*. Make a
  confidential client `winche-sync` with only *Service accounts* on, and give its service account the
  `realm-management` roles `view-users` and `view-events`.
- **Webhook (optional):** Keycloak has no webhooks of its own; with an event-listener plugin that sends them, point it
  at `POST /auth/v1/providers/keycloak/changed` with `Authorization: Bearer <WebhookSecret>`. Its body is ignored: it
  only makes the sync read Keycloak now, on whichever server runs it. A lost webhook just waits for the next poll.
- **Watching it:** `ProviderSyncs.StatusAsync()` (last run, last error, events read up to, last comparison); the logs
  (`auth.sync.keycloak`, each change with what changed); the health check (degraded when it fails or stops).

This is the other way to use an existing identity provider: its users become Winche users (sessions, the console,
revocation). Trusting its tokens directly (`TrustIssuer`) needs no Winche users at all.

## Two-step sign-in

```csharp
o.Mfa(m => m.Issuer = "Clinic");   // the name authenticator apps show
```

Users add an authenticator app (any TOTP app: Google Authenticator, 1Password, Authy, …): `totp/start` returns a
secret and an `otpauth://` address to show as a QR code (starting again before confirming returns the same secret, so
a reload doesn't break an app already scanned), and `totp/confirm` with the app's first code turns it on and
returns ten **recovery codes**, shown once. From then on a password, email-link or provider sign-in answers
`MFA_REQUIRED` (401; `details` has the `mfaToken`, valid five minutes, and the `factors`); `signIn/mfa` with a code from the app, or a recovery code,
finishes it.

- Each code works once (a replayed code is refused); wrong codes count toward the account's lockout, and a right
  password doesn't reset that count until the second step passes (so codes can't be guessed by signing in again).
- Turning it on ends every other session. Once a user has it, it's always asked for, even if the app later turns
  two-step sign-in off.
- Tokens from a session that passed the second step carry `mfa: true` — rules can require it:
  `allow write: if request.auth.token.mfa == true;`
- **A provider's own second step.** A provider sign-in whose ID token shows a second step (a standard `amr` such as
  `otp` or `mfa`, or an `acr` in `SecondStepAcrValues`) needs no Winche code; `CountsAsSecondStep` makes every sign-in
  through the provider count (it checks one for everyone). `RequireSecondStep` refuses one without a second step, the
  provider's or Winche's (`SECOND_STEP_REQUIRED`). All three are also provider settings.
- Recovery codes are stored as hashes, each usable once; new ones (with a current code) replace them all.
- Turning it off needs a current code; an admin can turn it off for someone who lost their phone (`ResetMfaAsync`, or
  the console).

## Email

```csharp
o.Email(e =>
{
    e.AppName = "Clinic";
    e.ActionUrl = "https://app.example.com/auth/action";   // optional: Winche Auth's own page by default
});
o.EmailPassword(p => p.RequireVerifiedEmail = true);       // optional
o.EmailLink(l => l.LinkUrl = "https://app.example.com/finish-sign-in");   // optional: sign in without a password
builder.Services.AddSingleton<IAuthEmailSender, MyEmailSender>();          // your mail service (SES, SendGrid, …), or e.UseSmtp(…)
```

- **Verify email:** sign-up sends a link (`SendVerificationOnSignUp`); opening it sets `email_verified`. With
  `RequireVerifiedEmail`, sign-up and sign-in answer `EMAIL_NOT_VERIFIED` (403) until it's opened.
- **Reset password:** a one-hour link to choose a new password; every session ends.
- **Email-link sign-in:** a one-time link to the app's `LinkUrl` (`?mode=signIn&code=…`); the app posts the code to
  `signIn/link`.
- **Changing the email:** the new address confirms it (every session ends); the old one gets a notice with a seven-day
  **undo** link, which puts the address back, removes the password and two-step sign-in (whoever changed the address
  may have set them) and signs every device out: the owner sets a new password from their inbox.
- **An address proven by its owner wins.** When someone signs in with an email link (or resets the password) for an
  account whose address was never verified, whoever made that account may not be them: its password, linked
  providers, two-step sign-in and sessions are removed first.

Links to Winche Auth's own page carry `#mode=…&code=…`: after `#`, so the code never reaches a server's logs (the page
reads it and posts it). Links to the app's own page (`ActionUrl`) and sign-in links (`LinkUrl`) carry `?mode=…&code=…`.
Codes are single-use, stored only as hashes, replaced when a newer one of the same kind is
sent; at most five messages an hour per address (`Bob@` and `bob@` are one address). Password-reset and sign-in-link
emails go out after the request is answered, so its timing doesn't tell whether the address has an account
(`e.SendInBackground = false`, or `email.sendInBackground: false` in the console's settings, sends them first). Winche Auth's own page at `/auth/v1/action` only acts when its button is
pressed, so mail scanners opening links don't use them up. The messages are editable in the Winche console
(Authentication → Email templates), with `%APP_NAME%`, `%EMAIL%`, `%NEW_EMAIL%`, `%DISPLAY_NAME%` and `%LINK%`. Locally,
`e.LogLinks()` sends nothing and writes the links to the log.

## Tokens and rules

An access token carries `sub` and `uid` (the user's 28-character uid), `provider` (`password`, `anonymous`, `custom`),
`auth_time`, `email`, `email_verified`, `name`, `picture`, `anonymous` for guests, and the user's **custom claims** at the
top level. In rules:

```
match users/{uid} {
  allow read, write: if request.auth.uid == uid;
}
match reports/{id} {
  allow read: if request.auth.token.role == 'clinician';
}
```

Access tokens last 15 minutes (`AccessTokenLifetime`): disabling a user ends their sessions at once, and a token they
already hold stops working when it expires. Sessions last 60 days from their last use (`RefreshTokenLifetime`).

## Trusted issuers

Accept another provider's tokens directly, without Winche issuing its own; its users aren't Winche Auth users:

```csharp
builder.Services.AddAuthentication().AddWincheTokens(t =>
{
    t.TrustWincheAuth();                                // optional: only if you use AddWincheAuth too
    t.TrustIssuer("keycloak", i =>
    {
        i.Authority = "https://auth.example.com/realms/example";
        i.Audience = "clinic-api";
        i.UidClaim = "sub";                             // the default
        i.MapClaims("role", "org");                     // passed on besides uid, sub, email, name; all when not set
    });
});
```

An outside token never carries what only Winche sets: `uid`, `issuer`, `provider`, `anonymous`, `mfa` and `sid` are
dropped from it (and can't be mapping targets), so rules can trust them. Its users aren't Winche Auth's: a rule that
compares uids across both should check `request.auth.token.issuer` too.

Fields can be renamed and flattened: `i.Map("realm_access.roles", "roles")`, or joined:
`i.Map("given_name + family_name", "name")`.

**From the console.** With `t.UseSettings()` and `AddWincheConfig` (Winche.Core), the trusted providers and their
mapping become the settings area `auth.identityProviders`: the code's values are the starting point, and the Winche
console can add providers, change mappings, test a pasted token, and restore earlier versions, applied without a
restart. Providers added there get their keys from their discovery document (`{issuer}/.well-known/openid-configuration`).

```csharp
builder.Services.AddWincheConfig(o => o.ConnectionString = connectionString);
builder.Services.AddAuthentication().AddWincheTokens(t => t.UseSettings());   // or with TrustIssuer(...) defaults
```

`WincheTokenInspector` is what the console's token test uses: `InspectAsync(token, draft?)` returns the checks and the
`request.auth` the rules would see; `CheckProviderAsync(issuer)` checks a provider's address.

The token's issuer picks the check. Rules see `request.auth.uid` either way, and `request.auth.token.issuer` is
`winche` or the trusted issuer's name.

## Users in database documents

With Winche.Database in the same app, a user reference in a document (`userReferenceValue`, e.g. an `author` field) can be
expanded: `expand: ["author"]` returns the user's public profile under `resolved` (`user:<uid>`): `uid`, `displayName`, `photoUrl`, and the custom claims you list in
`o.PublicProfileClaims` (none by default). Signed-in callers see that much of anyone, a user sees their own account in
full, signed-out callers see nothing, and functions (the app's own code) see everything. Live subscriptions follow
profile changes.

## From your code

`IWincheAuth` (scoped): `CreateUserAsync`, `GetUserAsync`, `FindByEmailAsync`, `FindByProviderAsync(provider, subject)`
(the user linked to that provider account, by its `sub`), `ListUsersAsync(search)`,
`UpdateProfileAsync`, `SetDisabledAsync`, `SetCustomClaimsAsync` (up to 1,000 bytes of JSON; names Winche sets are
refused), `DeleteUserAsync`, `ListSessionsAsync`, `RevokeSessionAsync`, `RevokeSessionsAsync` (sign out everywhere), `UnlockAsync`, `ResetMfaAsync`, the email flows (`SendPasswordResetAsync`, `SetEmailVerifiedAsync`, …), and
`SignInAsUserAsync(uid)` for signing users in through systems of your own.

- `ListUsersPageAsync(pageToken, pageSize)`: every user, newest first, a page at a time; the page token keeps its place
  while users are added or deleted (offsets don't).
- `SetPasswordAsync(uid, password)`: sets or replaces anyone's password (an account made without one, too); every
  session ends.
- `SetEmailAsync(uid, email)`: an admin's change of the email, at once (no link): marked verified, every session ends;
  `EMAIL_EXISTS` if another account has it.
- `CreateCustomTokenAsync(uid)`: a token your server hands a client, which posts it to `signIn/custom` and is signed in
  as that uid (made on first use). Valid an hour at most; its audience is `{issuer}/auth/v1/signIn/custom`, so it's
  never accepted as an access token, nor an access token as one. No second step is asked: your server vouched.
- `CreateEmailLinkAsync(kind, email)`: a `verifyEmail`, `resetPassword` or `signIn` link for your server to send through
  its own mail or channel; nothing is emailed.

Errors are `AuthException`s: `Code` is Winche Auth's own (`INVALID_CREDENTIALS`, …), and `Error` the `WincheError`
every Winche package answers with (shared kind, `reason` = the code).

Hooks: `o.Events.BeforeCreate`, `AfterCreate` (e.g. create `users/{uid}`) and `BeforeSignIn`; throw
`AuthDeniedException` to refuse with a message.
Packages add checks of their own with `IWincheAuthGate` (DI, any number), run after those hooks: Winche.Functions runs
`users.beforeCreate` and `users.beforeSignIn` functions that way. A new account, its first sign-in method, `AfterCreate`'s own changes
through `IWincheAuth` and its `created` event commit together: if any part fails, there's no account.

**User events.** `IWincheAuthObserver`s (register any number) hear `created`, `signedIn`, `disabled`, `enabled`,
`claimsChanged`, `deleted` and `updated` (profile, email or its verification, a password set by the app, an unlinked
provider). Each event is written in the transaction that makes the change (table
`auth_user_events`, Winche.Core's feed `auth`), and each observer is a durable consumer of it: in commit order, at least
once, on one server at a time, after restarts too. An observer that throws gets the event again (holding back only
itself) until it has failed for `o.UserEvents.DeadLetterAfter` (one hour); then it's a dead letter, which the console's
Hooks page shows with the other feeds' to retry or discard (`AuthUserEvents` in code). An observer is known by its
`Name` (its type's name by default) and starts from when it was first seen. Events are kept seven days once every
observer has them (`o.UserEvents.Retention`).

## Logs

Sign-ins, sign-ups, lockouts and account changes are logged in the category `Winche.Auth.Events` as structured entries
— `Operation` (`auth.signIn`, `auth.signUp`, `auth.lockout`, `auth.disable`, …), `Principal` (the uid, or the email
tried) and `Outcome` (`ok`, or the error code: `invalidCredentials`, `lockedOut`, …) — with a sentence: *"Sign-in as
ann@example.com failed: The email or password is wrong."* Failures are Warnings and token refreshes Debug. The Winche
console's Logs Explorer shows them as resource `auth`.

**Metrics:** meter `Winche.Auth`, counter `winche.auth.events` — every one of those entries, tagged `operation` and
`outcome` (so sign-in failures, lockouts and refusals can be graphed and alerted on); user-event delivery is on
Winche.Core's `Winche.Feed` meter (feed `auth`). **Health:** `builder.Services.AddHealthChecks().AddWincheAuth()` is
unhealthy without the database or a signing key, and degraded when user events fall behind or are given up on.

## Protection

- Passwords are hashed by ASP.NET Core Identity (PBKDF2-SHA512). Length is the only rule (`MinLength`, default 10).
- An account locks after `MaxFailedSignIns` (5) failures in a row, for `LockoutDuration` (15 minutes).
- Each address gets 20 sign-in attempts, 10 new users and 120 refreshes a minute, counted in Postgres
  (`auth_attempts`), so every instance shares them.
- Behind a proxy, use ASP.NET Core's forwarded headers so the limits see the caller's address.
- Changing the email, deleting the account, adding a second step and unlinking need a sign-in from the last five
  minutes (`auth_time`); otherwise `REQUIRES_RECENT_SIGN_IN` (400): sign in again, then retry. A guest's own upgrade
  (`link/password`, `link/idp`) doesn't.
- An access token is read from `?access_token=` only on WebSocket upgrades (browsers can't set headers there); anywhere
  else it would end up in logs. Tokens carry `sid`, their session.

## 2.1.0

- Photos (above): `POST me/photo`, `DELETE me/photo`, `GET photos/{id}`; `SetPhotoAsync`, `RemovePhotoAsync`,
  `GetPhotoAsync`; `photoSource` on users. A provider's picture is now refreshed at sign-in while it's the user's photo,
  and goes when the provider is unlinked.
- An access token whose session has ended (signed out everywhere, ended by an admin, or the account claimed by its
  email's owner) no longer works on Winche Auth's own endpoints (`me`, `me/…`), though it hasn't expired; other services
  checking tokens are unchanged. Claiming an account also ends a two-step set-up only begun.
- `PATCH me` is a patch: a field left out stays as it is (before, a missing `photoUrl` cleared the photo); a field that
  isn't text or null is refused; names in any case, as before. Sending back the upload's own address (even one from
  before the server moved) keeps the upload. From code, `PatchProfileAsync(uid, ProfilePatch.Name("Ann"))` changes only what it
  sets, read and written together.
  A migration adds `auth_user_photos` and a column (by itself, at start).

## 2.0.1

- Fixed: with an SMTP server, sign-in-link and password-reset emails sent after answering were lost ("Cannot access a
  disposed object" in the log). The SMTP password is now read before answering.
- `email.sendInBackground` in the settings (the console: Authentication → Settings → Emails to users), on by default.

## Upgrading to 2.0

- **Breaking:** secrets (a Keycloak sync's client secret, the SMTP password) are kept by [Winche.Secrets](https://github.com/FlameOfUdun/winche-secrets) instead of Winche.Core
  (Core 2.0); `AddWincheAuth` adds the store. Saved secrets read as before, and either can now be a reference to AWS
  Secrets Manager or Parameter Store.
- Only Winche's own claim names are reserved: other claims a provider or your code sets are kept.
