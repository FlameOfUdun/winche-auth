using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Winche.Auth.Tokens;

namespace Winche.Auth.AspNetCore;

public static class WincheAuthEndpoints
{
    public sealed record SignUpRequest(string? Email, string? Password, string? DisplayName);
    public sealed record SignInRequest(string? Email, string? Password);
    public sealed record RefreshRequest(string? RefreshToken);
    public sealed record ProfileRequest(string? DisplayName, string? PhotoUrl);
    public sealed record PasswordRequest(string? CurrentPassword, string? NewPassword);
    public sealed record EmailRequest(string? Email);
    public sealed record CodeRequest(string? Code);
    public sealed record ResetRequest(string? Code, string? NewPassword);
    public sealed record NewEmailRequest(string? NewEmail);
    public sealed record IdpRequest(string? Provider, string? IdToken, string? Nonce);
    public sealed record CustomTokenRequest(string? Token);
    public sealed record UnlinkRequest(string? Provider);
    public sealed record MfaSignInRequest(string? MfaToken, string? Code);
    public sealed record MfaCodeRequest(string? Code);

    /// <summary>
    /// Maps Winche Auth's REST API under <paramref name="prefix"/> (default <c>/auth/v1</c>): signUp, signIn,
    /// signIn/anonymous, token, signOut, link/password and me; and <c>/.well-known/jwks.json</c> and
    /// <c>/.well-known/openid-configuration</c> so other services can check Winche tokens.
    /// </summary>
    public static IEndpointRouteBuilder MapWincheAuth(this IEndpointRouteBuilder app, string prefix = "/auth/v1")
    {
        if (app.ServiceProvider.GetService<IServiceProviderIsService>()?.IsService(typeof(IWincheAuth)) != true)
            throw new InvalidOperationException("MapWincheAuth: call services.AddWincheAuth(…) first.");
        var tokens = app.ServiceProvider.GetService<WincheTokenOptions>();
        if (tokens is not { Own: true } && tokens is not { Managed: true })
            throw new InvalidOperationException("MapWincheAuth: add AddAuthentication().AddWincheTokens(t => t.TrustWincheAuth()).");

        var attempts = app.ServiceProvider.GetRequiredService<AttemptLimiter>();
        var clock = app.ServiceProvider.GetService<TimeProvider>() ?? TimeProvider.System;
        // Attempts per client address per minute, shared by every server (the address is the app's to get right behind
        // a proxy: UseForwardedHeaders).
        Task Limit(HttpContext http, string kind, int perMinute) =>
            attempts.CheckAsync(kind, http.Connection.RemoteIpAddress?.ToString(), perMinute, http.RequestAborted);
        // Uploaded photos' addresses follow the prefix the host maps (and its PathBase, e.g. /projects/<id>).
        if (app.ServiceProvider.GetService<WincheAuthOptions>() is { } authOptions) authOptions.PhotosPath = $"{prefix.TrimEnd('/')}/photos";
        var group = app.MapGroup(prefix).AddEndpointFilter(async (ctx, next) =>
        {
            try { return await next(ctx); }
            catch (AuthException ex) { return Error(ex); }
        });

        group.MapPost("/signUp", async (SignUpRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "create", 10);
            return Tokens(await auth.SignUpAsync(body.Email ?? "", body.Password ?? "", body.DisplayName, Info(http), ct));
        });
        group.MapPost("/signIn", async (SignInRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "signIn", 20);
            return Tokens(await auth.SignInAsync(body.Email ?? "", body.Password ?? "", Info(http), ct));
        });
        group.MapPost("/signIn/anonymous", async (HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "create", 10);
            return Tokens(await auth.SignInAnonymouslyAsync(Info(http), ct));
        });
        // A Keycloak webhook (any plugin): read that provider's events now. The body isn't used; the secret is the proof.
        group.MapPost("/providers/{name}/changed", async (string name, HttpContext http, WincheAuthOptions options, Providers.ProviderSyncs syncs,
            CancellationToken ct) =>
        {
            await Limit(http, "webhook", 120);
            var secret = options.IdentityProviders.FirstOrDefault(p => p.Name == name)?.KeycloakSync?.WebhookSecret;
            var sent = http.Request.Headers.Authorization.ToString() is { } h && h.StartsWith("Bearer ", StringComparison.Ordinal) ? h[7..].Trim() : "";
            if (secret is null || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.UTF8.GetBytes(sent), System.Text.Encoding.UTF8.GetBytes(secret)))
                return Results.NotFound();   // no such webhook, as far as callers can tell
            await syncs.WakeAsync(name, ct);
            return Results.Accepted();
        });
        // OpenID Connect Back-Channel Logout: the provider says someone signed out there (a form with logout_token); the
        // session it names ends, or every session of theirs that came through it. Register this address at the provider.
        group.MapPost("/providers/{name}/backchannel-logout", async (string name, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "webhook", 120);
            http.Response.Headers.CacheControl = "no-store";
            var token = http.Request.HasFormContentType ? (string?)(await http.Request.ReadFormAsync(ct))["logout_token"] : null;
            if (string.IsNullOrEmpty(token)) return Results.BadRequest(new { error = "invalid_request", error_description = "No logout_token." });
            try { await auth.EndProviderSessionsAsync(name, token, ct); }
            catch (AuthException ex) { return Results.BadRequest(new { error = "invalid_request", error_description = ex.Message }); }
            return Results.Ok();
        }).DisableAntiforgery();
        // A custom token from the app's own server (IWincheAuth.CreateCustomTokenAsync).
        group.MapPost("/signIn/custom", async (CustomTokenRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "signIn", 20);
            return Tokens(await auth.SignInWithCustomTokenAsync(body.Token ?? "", Info(http), ct));
        });
        // Google, Apple, OpenID Connect: the app signs in with the provider and exchanges its ID token.
        group.MapPost("/signIn/idp", async (IdpRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "signIn", 20);
            return Tokens(await auth.SignInWithProviderAsync(body.Provider ?? "", body.IdToken ?? "", body.Nonce, Info(http), ct));
        });
        group.MapPost("/link/idp", async (IdpRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await RecentMe(http, clock, guestsToo: true) is not { } uid) return Unauthorized();
            await Limit(http, "signIn", 20);
            return Tokens(await auth.LinkProviderAsync(uid, body.Provider ?? "", body.IdToken ?? "", body.Nonce, Info(http), ct));
        });
        group.MapPost("/unlink", async (UnlinkRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
            await RecentMe(http, clock) is { } uid ? Results.Json(User(await auth.UnlinkProviderAsync(uid, body.Provider ?? "", ct))) : Unauthorized());
        // What a sign-in screen can offer.
        group.MapGet("/providers", (WincheAuthOptions o) => Results.Json(new
        {
            emailPassword = o.EmailPasswordSignIn is not null,
            emailLink = o.EmailLinkSignIn is not null,
            anonymous = o.AnonymousSignIn,
            providers = o.IdentityProviders.Select(p => new { name = p.Name, kind = p.Kind, displayName = p.DisplayName ?? p.Name }),
        }));

        // Two-step sign-in (o.Mfa).
        group.MapPost("/signIn/mfa", async (MfaSignInRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "signIn", 20);
            return Tokens(await auth.SignInWithMfaAsync(body.MfaToken ?? "", body.Code ?? "", Info(http), ct));
        });
        group.MapGet("/me/mfa", async (HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await Me(http) is not { } uid) return Unauthorized();
            var status = await auth.GetMfaStatusAsync(uid, ct);
            return Results.Json(new { enabled = status.Enabled, recoveryCodesLeft = status.RecoveryCodesLeft });
        });
        group.MapPost("/me/mfa/totp/start", async (HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            // A stolen token mustn't be able to put a second step on the owner's account.
            if (await RecentMe(http, clock) is not { } uid) return Unauthorized();
            var e = await auth.StartTotpEnrollmentAsync(uid, ct);
            return Results.Json(new { secret = e.Secret, otpauthUri = e.OtpAuthUri });
        });
        group.MapPost("/me/mfa/totp/confirm", async (MfaCodeRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await Me(http) is not { } uid) return Unauthorized();
            await Limit(http, "code", 30);
            // Every other session ends: this one goes on.
            var codes = auth is Users.WincheAuthService service
                ? await service.ConfirmTotpEnrollmentAsync(uid, body.Code ?? "", SessionOf(http), ct)
                : await auth.ConfirmTotpEnrollmentAsync(uid, body.Code ?? "", ct);
            return Results.Json(new { recoveryCodes = codes });
        });
        group.MapPost("/me/mfa/recoveryCodes", async (MfaCodeRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await Me(http) is not { } uid) return Unauthorized();
            await Limit(http, "code", 30);
            return Results.Json(new { recoveryCodes = await auth.RegenerateRecoveryCodesAsync(uid, body.Code ?? "", ct) });
        });
        group.MapPost("/me/mfa/disable", async (MfaCodeRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await Me(http) is not { } uid) return Unauthorized();
            await Limit(http, "code", 30);
            await auth.DisableMfaAsync(uid, body.Code ?? "", ct);
            return Results.NoContent();
        });

        group.MapPost("/token", async (RefreshRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "token", 120);
            return Tokens(await auth.RefreshAsync(body.RefreshToken ?? "", Info(http), ct));
        });
        // Email: verify, reset, sign-in links, change of address (o.Email).
        group.MapPost("/sendPasswordReset", async (EmailRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "email", 10);
            await auth.SendPasswordResetAsync(body.Email ?? "", Info(http), ct);
            return Results.NoContent();
        });
        group.MapPost("/resetPassword", async (ResetRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "code", 30);
            return Results.Json(User(await auth.ResetPasswordAsync(body.Code ?? "", body.NewPassword ?? "", ct)));
        });
        group.MapPost("/sendSignInLink", async (EmailRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "email", 10);
            await auth.SendSignInLinkAsync(body.Email ?? "", Info(http), ct);
            return Results.NoContent();
        });
        group.MapPost("/signIn/link", async (CodeRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "code", 30);
            return Tokens(await auth.SignInWithLinkAsync(body.Code ?? "", Info(http), ct));
        });
        group.MapPost("/action/check", async (CodeRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "code", 30);
            var info = await auth.CheckActionCodeAsync(body.Code ?? "", ct);
            return Results.Json(new { mode = info.Mode, email = info.Email });
        });
        group.MapPost("/action/apply", async (CodeRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            await Limit(http, "code", 30);
            var info = await auth.ApplyActionCodeAsync(body.Code ?? "", ct);
            return Results.Json(new { mode = info.Mode, email = info.Email });
        });
        group.MapPost("/sendVerification", async (HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await Me(http) is not { } uid) return Unauthorized();
            await Limit(http, "email", 10);
            await auth.SendEmailVerificationAsync(uid, ct);
            return Results.NoContent();
        });
        group.MapPost("/me/email", async (NewEmailRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await RecentMe(http, clock) is not { } uid) return Unauthorized();
            await Limit(http, "email", 10);
            await auth.ChangeEmailAsync(uid, body.NewEmail ?? "", ct);
            return Results.Accepted();
        });
        // The page emailed links open (unless o.Email(e => e.ActionUrl = …) points them at the app's own).
        group.MapGet("/action", (HttpContext http, IWincheAuth auth, WincheAuthOptions o) => ActionPage.GetAsync(http, auth, o));
        group.MapPost("/action", async (HttpContext http, IWincheAuth auth, WincheAuthOptions o) =>
        {
            await Limit(http, "code", 30);
            return await ActionPage.PostAsync(http, auth, o);
        }).DisableAntiforgery();

        group.MapPost("/signOut", async (RefreshRequest body, IWincheAuth auth, CancellationToken ct) =>
        {
            await auth.SignOutAsync(body.RefreshToken ?? "", ct);
            return Results.NoContent();
        });

        // The signed-in user (a Winche Auth token).
        group.MapPost("/link/password", async (SignInRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await RecentMe(http, clock, guestsToo: true) is not { } uid) return Unauthorized();
            await Limit(http, "create", 10);
            return Tokens(await auth.LinkPasswordAsync(uid, body.Email ?? "", body.Password ?? "", Info(http), ct));
        });
        group.MapGet("/me", async (HttpContext http, IWincheAuth auth, CancellationToken ct) =>
            await Me(http) is { } uid && await auth.GetUserAsync(uid, ct) is { } user ? Results.Json(User(user)) : Unauthorized());
        group.MapPatch("/me", async (HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await Me(http) is not { } uid) return Unauthorized();
            await Limit(http, "profile", 30);
            // A patch: what's left out stays as it is (only an explicit null clears it).
            if (await ReadPatchAsync(http.Request, ct) is not { } body || PatchOf(body) is not { } patch)
                return Send(new WincheError(WincheErrorCode.InvalidArgument, "Send a JSON object: displayName and/or photoUrl, each text or null."));
            return Results.Json(User(await auth.PatchProfileAsync(uid, patch, ct)));
        });
        group.MapPost("/me/password", async (PasswordRequest body, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await Me(http) is not { } uid) return Unauthorized();
            await Limit(http, "signIn", 20);
            return Tokens(await auth.ChangePasswordAsync(uid, body.CurrentPassword ?? "", body.NewPassword ?? "", Info(http), ct));
        });
        // The signed-in user's photo: the image itself as the body (JPEG, PNG or WebP, at most 100 KB), or removed.
        group.MapPost("/me/photo", async (HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await Me(http) is not { } uid) return Unauthorized();
            await Limit(http, "profile", 30);
            if (await ReadPhotoAsync(http.Request, ct) is not { } image)
                return Send(new WincheError(WincheErrorCode.InvalidArgument, $"Send the photo as the request's body, at most {WincheAuthLimits.MaxPhotoBytes / 1024} KB."));
            return Results.Json(User(await auth.SetPhotoAsync(uid, image, ct)));
        });
        group.MapDelete("/me/photo", async (HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await Me(http) is not { } uid) return Unauthorized();
            await Limit(http, "profile", 30);
            return Results.Json(User(await auth.RemovePhotoAsync(uid, ct)));
        });
        // Uploaded photos, by their unguessable id: open to anyone with the address (an <img> can't send a token). A new photo
        // has a new id, so caches never show an old one; a day's caching keeps a removed one from lingering for long.
        group.MapGet("/photos/{id}", async (string id, HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await auth.GetPhotoAsync(id, ct) is not { } photo) return Results.NotFound();
            http.Response.Headers.CacheControl = "public, max-age=86400";
            http.Response.Headers.XContentTypeOptions = "nosniff";
            http.Response.Headers.ContentSecurityPolicy = "default-src 'none'";
            return Results.Bytes(photo.Bytes, photo.ContentType, lastModified: photo.UpdatedAt);
        }).AllowAnonymous();

        group.MapDelete("/me", async (HttpContext http, IWincheAuth auth, CancellationToken ct) =>
        {
            if (await RecentMe(http, clock) is not { } uid) return Unauthorized();
            await auth.DeleteUserAsync(uid, ct);
            return Results.NoContent();
        });

        app.MapGet("/.well-known/jwks.json", async (SigningKeyStore keys, CancellationToken ct) => Results.Json(await keys.JwksAsync(ct)));
        app.MapGet("/.well-known/openid-configuration", (WincheAuthOptions o) => Results.Json(new Dictionary<string, object>
        {
            ["issuer"] = o.Issuer,
            ["jwks_uri"] = $"{o.Issuer.TrimEnd('/')}/.well-known/jwks.json",
            ["id_token_signing_alg_values_supported"] = new[] { "ES256" },
            ["subject_types_supported"] = new[] { "public" },
            ["response_types_supported"] = new[] { "token" },
        }));
        return app;
    }

    /// <summary>The uid of the request's Winche Auth token (not a trusted issuer's), or null.</summary>
    private static async Task<string?> Me(HttpContext http)
    {
        var result = await http.AuthenticateAsync(WincheAuthDefaults.OwnScheme);
        if (!result.Succeeded) return null;
        return http.Items[WincheAuthDefaults.ClaimsItem] is IReadOnlyDictionary<string, object?> c ? c.GetValueOrDefault("uid") as string : null;
    }

    /// <summary>How recent a sign-in the sensitive actions need (changing the email, deleting the account, …).</summary>
    internal static readonly TimeSpan RecentSignIn = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The uid of the request's Winche Auth token, when that session signed in within <see cref="RecentSignIn"/>; null
    /// without a token; REQUIRES_RECENT_SIGN_IN for an older sign-in. A guest's own upgrade (<paramref name="guestsToo"/>)
    /// is never held back: a guest has nothing to steal yet.
    /// </summary>
    private static async Task<string?> RecentMe(HttpContext http, TimeProvider clock, bool guestsToo = false)
    {
        if (await Me(http) is not { } uid) return null;
        var claims = (IReadOnlyDictionary<string, object?>)http.Items[WincheAuthDefaults.ClaimsItem]!;
        if (guestsToo && claims.GetValueOrDefault("anonymous") is true) return uid;
        var authTime = Seconds(claims.GetValueOrDefault("auth_time"));
        if (authTime is null || clock.GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(authTime.Value) > RecentSignIn)
            throw new AuthException(AuthErrorCodes.RequiresRecentSignIn, "For this, sign in again first: your last sign-in was too long ago.");
        return uid;
    }

    private static long? Seconds(object? v) => v switch
    {
        long l => l,
        int i => i,
        double d => (long)d,
        System.Text.Json.JsonElement { ValueKind: System.Text.Json.JsonValueKind.Number } e => e.GetInt64(),
        _ => null,
    };

    /// <summary>The session of the request's Winche Auth token (its <c>sid</c>), if it has one.</summary>
    private static Guid? SessionOf(HttpContext http) =>
        http.Items[WincheAuthDefaults.ClaimsItem] is IReadOnlyDictionary<string, object?> c && c.GetValueOrDefault("sid") is string s && Guid.TryParse(s, out var id)
            ? id : null;

    private static AuthRequestInfo Info(HttpContext http) =>
        new(http.Connection.RemoteIpAddress?.ToString(), http.Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua : null);

    private static IResult Tokens(AuthTokens t) => Results.Json(new
    {
        accessToken = t.AccessToken,
        expiresIn = t.ExpiresIn,
        expiresAt = t.ExpiresAt,
        refreshToken = t.RefreshToken,
        user = User(t.User),
    });

    private static object User(WincheUserInfo u) => new
    {
        uid = u.Uid, email = u.Email, emailVerified = u.EmailVerified, displayName = u.DisplayName, photoUrl = u.PhotoUrl, photoSource = u.PhotoSource,
        isAnonymous = u.IsAnonymous, mfaEnabled = u.MfaEnabled, providers = u.Providers, customClaims = u.CustomClaims, createdAt = u.CreatedAt, lastSignInAt = u.LastSignInAt,
    };

    /// <summary>A PATCH body as a JSON object, or null when it isn't one.</summary>
    public static async Task<System.Text.Json.Nodes.JsonObject?> ReadPatchAsync(HttpRequest request, CancellationToken ct)
    {
        try { return await System.Text.Json.Nodes.JsonNode.ParseAsync(request.Body, cancellationToken: ct) as System.Text.Json.Nodes.JsonObject; }
        catch (System.Text.Json.JsonException) { return null; }
    }

    /// <summary>
    /// A profile patch from a PATCH body: <c>displayName</c> and <c>photoUrl</c> when present (text, or null to clear),
    /// what's left out unchanged. Null when a field is there with another type (a number, an object): refused, never
    /// taken for "clear".
    /// </summary>
    public static ProfilePatch? PatchOf(System.Text.Json.Nodes.JsonObject body)
    {
        // Field names in any case (displayName, DisplayName), as the body binding before 2.1 took them.
        static bool Read(System.Text.Json.Nodes.JsonObject body, string name, out bool set, out string? value)
        {
            var found = body.FirstOrDefault(p => string.Equals(p.Key, name, StringComparison.OrdinalIgnoreCase));
            set = found.Key is not null;
            var node = found.Value;
            value = null;
            if (!set || node is null) return true;
            return node is System.Text.Json.Nodes.JsonValue v && v.TryGetValue(out value);
        }
        return Read(body, "displayName", out var setName, out var name) && Read(body, "photoUrl", out var setPhoto, out var photo)
            ? new ProfilePatch(setName, name, setPhoto, photo) : null;
    }

    /// <summary>A request's body as a photo, or null when it's empty or over the limit.</summary>
    public static async Task<byte[]?> ReadPhotoAsync(HttpRequest request, CancellationToken ct)
    {
        if (request.ContentLength is > WincheAuthLimits.MaxPhotoBytes) return null;
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await request.Body.ReadAsync(chunk, ct)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > WincheAuthLimits.MaxPhotoBytes) return null;
        }
        return buffer.Length == 0 ? null : buffer.ToArray();
    }

    private static IResult Unauthorized() => Send(new WincheError(WincheErrorCode.Unauthenticated, "Sign in first: send a Winche Auth access token."));

    /// <summary>
    /// The shared error: <c>code</c> the kind (<see cref="AuthErrorCodes.Kind"/>), <c>reason</c> auth's own code, and
    /// <c>details</c> its extra values (the <c>mfaToken</c> and <c>factors</c> of <c>MFA_REQUIRED</c>).
    /// </summary>
    internal static IResult Error(AuthException ex) => Send(ex.Error);

    private static IResult Send(WincheError error) => error.ToResult();
}
