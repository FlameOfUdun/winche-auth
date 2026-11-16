using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Winche.Auth.Data;
using Winche.Auth.Logging;
using Winche.Auth.Providers;
using Winche.Auth.Tokens;

namespace Winche.Auth.Users;

internal sealed partial class WincheAuthService
{
    /// <summary>
    /// Where the sync notes that it disabled a user (an Identity user token): only those it re-enables when the provider
    /// does, never one an admin disabled.
    /// </summary>
    private const string SyncMarker = "winche-sync", DisabledBy = "disabledBy";

    /// <summary>
    /// Brings the Winche user linked to <paramref name="subject"/> at <paramref name="provider"/> in step with
    /// <paramref name="state"/> (null: deleted there). Returns what changed, or null when nothing did or no Winche
    /// user is linked (they've never signed in with it).
    /// </summary>
    internal async Task<string?> SyncFromProviderAsync(IdentityProviderOptions provider, string subject, KeycloakUserState? state,
        IReadOnlyList<string> claimNames, CancellationToken ct)
    {
        var user = await users.FindByLoginAsync(provider.Name, subject);
        if (user is null) return null;
        var source = ProviderName(provider.Name);
        if (state is null && provider.KeycloakSync?.WhenDeleted == KeycloakSyncOptions.Delete)
        {
            // Deleted there, and that's where accounts are kept: deleted here too (sessions with it).
            var uid = user.Id;
            await InTransaction(async () =>
            {
                var info = await InfoAsync(user);
                var deleted = await users.DeleteAsync(user);
                if (!deleted.Succeeded) throw Failed(deleted);
                await Record(WincheAuthUserEvent.Deleted, info, ct);
            }, ct);
            AuthEvents.Log(_events, LogLevel.Warning, $"auth.sync.{provider.Name}", uid, "ok",
                $"{uid} ({user.Email ?? "no email"}) was deleted in {source}: deleted here too.", user.Email);
            return "deleted";
        }
        var changes = new List<string>();
        await InTransaction(async () =>
        {
            var wasDisabled = user.Disabled;
            var profileChanged = false;
            if (state is null)
            {
                // Deleted there: kept here, disabled and unlinked (an admin decides what becomes of it).
                if (!user.Disabled)
                {
                    user.Disabled = true;
                    await users.SetAuthenticationTokenAsync(user, SyncMarker, DisabledBy, provider.Name);
                    changes.Add("disabled");
                }
                var removed = await users.RemoveLoginAsync(user, provider.Name, subject);
                if (!removed.Succeeded) throw Failed(removed);
                changes.Add($"unlinked from {source}");
                profileChanged = true;
            }
            else
            {
                if (!state.Enabled && !user.Disabled)
                {
                    user.Disabled = true;
                    await users.SetAuthenticationTokenAsync(user, SyncMarker, DisabledBy, provider.Name);
                    changes.Add("disabled");
                }
                else if (state.Enabled && user.Disabled && await users.GetAuthenticationTokenAsync(user, SyncMarker, DisabledBy) == provider.Name)
                {
                    user.Disabled = false;
                    await users.RemoveAuthenticationTokenAsync(user, SyncMarker, DisabledBy);
                    changes.Add("enabled");
                }

                if (Clean(state.Name, 100) is { } name && name != user.DisplayName)
                {
                    user.DisplayName = name;
                    changes.Add($"name {name}");
                }
                if (state.Email is { Length: > 0 } email && !string.Equals(email, user.Email, StringComparison.OrdinalIgnoreCase))
                {
                    if (await users.FindByEmailAsync(email) is { } other && other.Id != user.Id)
                        AuthEvents.Log(_events, LogLevel.Warning, $"auth.sync.{provider.Name}", user.Id, "emailExists",
                            $"{user.Id}'s email changed to {email} in {source}, but another account here has it: kept {user.Email ?? "none"}.", email);
                    else
                    {
                        changes.Add($"email {user.Email ?? "none"} → {email}");
                        user.Email = email;
                        user.NormalizedEmail = users.NormalizeEmail(email);
                        user.EmailConfirmed = state.EmailVerified;
                    }
                }
                else if (state.EmailVerified && user.Email is not null && !user.EmailConfirmed)
                {
                    user.EmailConfirmed = true;   // verified there; a verification here is never undone by it
                    changes.Add("email verified");
                }

                if (claimNames.Count > 0)
                {
                    var claims = new Dictionary<string, object?>(CustomClaims.Parse(user.CustomClaims), StringComparer.Ordinal);
                    foreach (var claim in claimNames)
                    {
                        if (state.Claims.GetValueOrDefault(claim) is { } value) claims[claim] = value;
                        else claims.Remove(claim);
                    }
                    var json = CustomClaims.Serialize(claims);
                    if (json != user.CustomClaims && !SameJson(json, user.CustomClaims))
                    {
                        user.CustomClaims = json;
                        changes.Add("claims");
                    }
                }
                profileChanged = changes.Any(c => c is not "disabled" and not "enabled");
            }
            if (changes.Count == 0) return;
            await Save(user);
            if (user.Disabled && !wasDisabled) await sessions.RevokeAllAsync(user.Id, $"disabled in {source}", ct);
            var info = await InfoAsync(user);
            if (user.Disabled != wasDisabled) await Record(user.Disabled ? WincheAuthUserEvent.Disabled : WincheAuthUserEvent.Enabled, info, ct);
            if (profileChanged) await Record(WincheAuthUserEvent.Updated, info, ct);
        }, ct);
        if (changes.Count == 0) return null;
        var summary = string.Join(", ", changes);
        AuthEvents.Log(_events, state is null || changes.Contains("disabled") ? LogLevel.Warning : LogLevel.Information, $"auth.sync.{provider.Name}", user.Id, "ok",
            $"{user.Id} ({user.Email ?? "no email"}) was {(state is null ? $"deleted in {source}" : $"changed in {source}")}: {summary}.", user.Email);
        return summary;
    }

    private static bool SameJson(string? a, string? b)
    {
        if (a is null || b is null) return a == b;
        return System.Text.Json.Nodes.JsonNode.DeepEquals(System.Text.Json.Nodes.JsonNode.Parse(a), System.Text.Json.Nodes.JsonNode.Parse(b));
    }

    /// <summary>The (uid, subject) pairs of users linked to <paramref name="provider"/>, after <paramref name="afterUid"/>, for reconciling.</summary>
    internal async Task<IReadOnlyList<(string Uid, string Subject)>> LinkedAsync(string provider, string? afterUid, int count, CancellationToken ct) =>
        [.. (await db.UserLogins.AsNoTracking()
            .Where(l => l.LoginProvider == provider && (afterUid == null || string.Compare(l.UserId, afterUid) > 0))
            .OrderBy(l => l.UserId).Take(count).Select(l => new { l.UserId, l.ProviderKey }).ToListAsync(ct))
            .Select(l => (l.UserId, l.ProviderKey))];
}
